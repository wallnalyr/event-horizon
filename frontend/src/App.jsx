import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { toast } from 'sonner'

// Utilities
import { fetchWithTimeout } from './lib/fetch'
import * as crypto from './lib/crypto'

// Components
import { ToastProvider } from './components/ui/Toast'
import { FileCardSkeleton } from './components/ui/Skeleton'
import { SecurityBanner } from './components/ui/SecurityBanner'
import { LockModal, UnlockModal } from './components/ui/LockModal'
import { UploadZone } from './components/features/UploadZone'
import { Clipboard } from './components/features/Clipboard'
import { ClipboardImage } from './components/features/ClipboardImage'
import { FileCard } from './components/features/FileCard'
import { LockButton } from './components/features/LockButton'

// Hooks
import { useReducedMotion } from './hooks/useReducedMotion'

function App() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [clipboardText, setClipboardText] = useState('')
  const [clipboardSynced, setClipboardSynced] = useState(true)
  const [clipboardImageData, setClipboardImageData] = useState(null)

  // Lock state
  const [isLocked, setIsLocked] = useState(false)
  const [hasSession, setHasSession] = useState(false)
  const [sessionToken, setSessionToken] = useState(null)
  const [showLockModal, setShowLockModal] = useState(false)
  const [showUnlockModal, setShowUnlockModal] = useState(false)
  const [hasExistingData, setHasExistingData] = useState(false)

  // E2EE: Local decryption key and decrypted data (never sent to server)
  // Key is stored in memory only - cleared on page refresh or lock removal
  const [encryptionKey, setEncryptionKey] = useState(null)
  const encryptionKeyRef = useRef(null) // Ref for use in callbacks

  const clipboardSyncedRef = useRef(true)
  const clipboardCooldownRef = useRef(null)
  const clipboardDebounceRef = useRef(null)
  const prefersReducedMotion = useReducedMotion()

  // Conflict detection: track what we last saved to detect overwrites from other devices
  const lastSavedClipboardRef = useRef(null)
  const lastSavedFilesRef = useRef(null) // Track file IDs we uploaded

  // Get session token from storage
  useEffect(() => {
    const token = sessionStorage.getItem('session-token')
    if (token) {
      setSessionToken(token)
    }
  }, [])

  // Keep encryption key ref in sync with state
  useEffect(() => {
    encryptionKeyRef.current = encryptionKey
  }, [encryptionKey])

  // Helper to get headers with session token
  const getHeaders = (contentType = null) => {
    const headers = {}
    if (sessionToken) {
      headers['X-Session-Token'] = sessionToken
    }
    if (contentType) {
      headers['Content-Type'] = contentType
    }
    return headers
  }

  // Fetch lock status - returns the locked state for change detection
  const fetchLockStatus = async () => {
    try {
      const response = await fetchWithTimeout('/api/lock/status', {
        headers: getHeaders()
      })
      if (!response.ok) {
        console.error(`Lock status fetch failed: ${response.status} ${response.statusText}`)
        return undefined
      }

      const data = await response.json()
      setIsLocked(data.locked)
      setHasSession(data.hasSession)
      setHasExistingData(data.hasData)

      // If locked and we have a session, we can access data
      // If locked and no session, show unlock modal
      if (data.locked && !data.hasSession && sessionToken) {
        // Token is invalid, clear it
        setSessionToken(null)
        sessionStorage.removeItem('session-token')
      }

      return data.locked
    } catch (err) {
      console.error('Failed to fetch lock status:', err)
      return undefined
    }
  }

  // Track previous lock state to detect changes from other devices
  const prevLockedRef = useRef(null)

  // Data fetching - poll every 2 seconds for real-time sync across devices
  useEffect(() => {
    const fetchAllData = async () => {
      const lockStatus = await fetchLockStatus()

      // Detect lock state change from another device
      if (prevLockedRef.current !== null && lockStatus !== undefined) {
        if (prevLockedRef.current !== lockStatus) {
          // Lock state changed from another device
          if (!lockStatus && prevLockedRef.current === true) {
            // Session was unlocked by another device - notify user and refresh data
            toast.success('Session unsealed from another device')
            await Promise.all([fetchFiles(), fetchClipboard(), fetchClipboardImage()])
          } else if (lockStatus && prevLockedRef.current === false) {
            // Session was locked by another device - notify user
            toast.info('Session sealed from another device')
          }
        }
      }
      prevLockedRef.current = lockStatus

      // Skip data fetches when showing locked overlay (no session token) - these return 401
      // When we have an encryption key, we still fetch to enable cross-device sync
      // The fetch functions will decrypt the data locally
      const showingLockedOverlay = lockStatus === true && !sessionToken

      if (!showingLockedOverlay) {
        await Promise.all([fetchFiles(), fetchClipboard(), fetchClipboardImage()])
      }
      setLoading(false)
    }
    fetchAllData()

    const interval = setInterval(fetchAllData, 2000) // Poll every 2 seconds to reduce load

    return () => {
      clearInterval(interval)
      // Clean up timers
      if (clipboardDebounceRef.current) {
        clearTimeout(clipboardDebounceRef.current)
      }
      if (clipboardCooldownRef.current) {
        clearTimeout(clipboardCooldownRef.current)
      }
    }
  }, [sessionToken])

  const fetchFiles = async () => {
    try {
      const response = await fetchWithTimeout('/api/files', {
        headers: getHeaders()
      })

      // 401 means locked without valid token - don't update state here,
      // fetchLockStatus handles the lock state to avoid redundant updates
      if (response.status === 401) {
        return
      }

      if (!response.ok) {
        console.error(`Files fetch failed: ${response.status} ${response.statusText}`)
        return
      }

      const data = await response.json()

      if (Array.isArray(data)) {
        let processedFiles = data

        // If we have encryption key and files are encrypted, decrypt them
        if (encryptionKeyRef.current && data.length > 0 && data[0].encrypted_b64) {
          const decryptedFiles = []
          for (const file of data) {
            try {
              const encryptedData = crypto.fromBase64(file.encrypted_b64)
              const fileBytes = await crypto.decrypt(encryptionKeyRef.current, encryptedData)
              decryptedFiles.push({
                id: file.id,
                name: file.name,
                mimetype: file.mimetype,
                size: file.size,
                localDecryptedData: fileBytes
              })
            } catch (err) {
              console.error(`Failed to decrypt file ${file.name}:`, err)
            }
          }
          processedFiles = decryptedFiles
        }

        // Conflict detection: check if any recently uploaded files are missing
        if (lastSavedFilesRef.current && lastSavedFilesRef.current.length > 0) {
          const serverFileIds = new Set(processedFiles.map(f => f.id))
          const missingFiles = lastSavedFilesRef.current.filter(id => !serverFileIds.has(id))
          if (missingFiles.length > 0) {
            toast.info('Some files were removed from another device')
            // Clear the missing IDs from tracking
            lastSavedFilesRef.current = lastSavedFilesRef.current.filter(id => !missingFiles.includes(id))
            if (lastSavedFilesRef.current.length === 0) {
              lastSavedFilesRef.current = null
            }
          }
        }

        setFiles(processedFiles)
      }
    } catch (err) {
      console.error('Failed to fetch files:', err)
    }
  }

  const fetchClipboard = async () => {
    try {
      const response = await fetchWithTimeout('/api/clipboard', {
        headers: getHeaders()
      })

      // 401 means locked without valid token - don't update state here,
      // fetchLockStatus handles the lock state to avoid redundant updates
      if (response.status === 401) {
        return
      }

      if (!response.ok) {
        console.error(`Clipboard fetch failed: ${response.status} ${response.statusText}`)
        return
      }

      const data = await response.json()

      // Update clipboard if synced - check both text field and has_content flag
      // When clipboard is shredded, backend returns { has_content: false } without text field
      if (clipboardSyncedRef.current && data) {
        let serverText = null

        if (data.encrypted_b64 && encryptionKeyRef.current) {
          // Decrypt encrypted clipboard
          try {
            const encryptedData = crypto.fromBase64(data.encrypted_b64)
            serverText = await crypto.decryptText(encryptionKeyRef.current, encryptedData)
          } catch (err) {
            console.error('Failed to decrypt clipboard:', err)
            return
          }
        } else if (typeof data.text !== 'undefined') {
          serverText = data.text || ''
        } else if (data.has_content === false) {
          // Clipboard was shredded on another device
          serverText = ''
        }

        if (serverText !== null) {
          // Conflict detection: if we recently saved something different than what server has,
          // another device overwrote our changes
          if (lastSavedClipboardRef.current !== null &&
              serverText !== lastSavedClipboardRef.current &&
              serverText !== clipboardText) {
            toast.info('Clipboard updated from another device')
            lastSavedClipboardRef.current = null // Clear to prevent repeated notifications
          }

          setClipboardText(serverText)
        }
      }
    } catch (err) {
      console.error('Failed to fetch clipboard:', err)
    }
  }

  const fetchClipboardImage = async () => {
    try {
      const response = await fetchWithTimeout('/api/clipboard-image', {
        headers: getHeaders()
      })

      // 401 means locked without valid token - don't update state here,
      // fetchLockStatus handles the lock state to avoid redundant updates
      if (response.status === 401) {
        return
      }

      if (!response.ok) {
        console.error(`Clipboard image fetch failed: ${response.status} ${response.statusText}`)
        return
      }

      const data = await response.json()

      // If we have encryption key and image is encrypted, decrypt it
      if (data.encrypted_b64 && encryptionKeyRef.current) {
        try {
          const encryptedData = crypto.fromBase64(data.encrypted_b64)
          const imageBytes = await crypto.decrypt(encryptionKeyRef.current, encryptedData)
          const base64Image = crypto.toBase64(imageBytes)
          setClipboardImageData({
            hasImage: true,
            mimeType: data.mimeType || 'image/png',
            localDecryptedData: base64Image
          })
        } catch (err) {
          console.error('Failed to decrypt clipboard image:', err)
        }
      } else {
        setClipboardImageData(data)
      }
    } catch (err) {
      console.error('Failed to fetch clipboard image:', err)
    }
  }

  const saveClipboard = (text) => {
    // Update local state immediately for responsive UI
    setClipboardText(text)
    setClipboardSynced(false)
    clipboardSyncedRef.current = false

    // Clear any existing debounce timer
    if (clipboardDebounceRef.current) {
      clearTimeout(clipboardDebounceRef.current)
    }

    // Clear any existing cooldown
    if (clipboardCooldownRef.current) {
      clearTimeout(clipboardCooldownRef.current)
    }

    // Debounce: wait 500ms after last keystroke before saving
    clipboardDebounceRef.current = setTimeout(async () => {
      try {
        let bodyData

        // E2EE: If locked (have encryption key), encrypt before sending
        if (encryptionKeyRef.current) {
          const encrypted = await crypto.encryptText(encryptionKeyRef.current, text)
          const encryptedB64 = crypto.toBase64(encrypted)
          bodyData = { encrypted_b64: encryptedB64 }
        } else {
          bodyData = { text }
        }

        const response = await fetchWithTimeout('/api/clipboard', {
          method: 'POST',
          headers: getHeaders('application/json'),
          body: JSON.stringify(bodyData)
        })

        if (!response.ok) {
          console.error(`Clipboard save failed: ${response.status} ${response.statusText}`)
          toast.error('Failed to save clipboard')
          setClipboardSynced(true) // Reset indicator so it doesn't stay stuck at "Saving..."
          // Set cooldown to prevent immediate overwrite
          clipboardCooldownRef.current = setTimeout(() => {
            clipboardSyncedRef.current = true
          }, 2000)
          return
        }

        // Track what we saved for conflict detection
        lastSavedClipboardRef.current = text

        setClipboardSynced(true)
        // Add cooldown before allowing fetched data to overwrite
        clipboardCooldownRef.current = setTimeout(() => {
          clipboardSyncedRef.current = true
          // Clear saved reference after cooldown - we've accepted the server state
          lastSavedClipboardRef.current = null
        }, 2000)
      } catch (err) {
        console.error('Failed to save clipboard:', err)
        toast.error('Failed to save clipboard')
        setClipboardSynced(true) // Reset indicator so it doesn't stay stuck at "Saving..."
        // Still set cooldown to prevent immediate overwrite of local changes
        clipboardCooldownRef.current = setTimeout(() => {
          clipboardSyncedRef.current = true
        }, 2000)
      }
    }, 500)
  }

  const shredClipboard = async () => {
    try {
      const response = await fetchWithTimeout('/api/clipboard', {
        method: 'DELETE',
        headers: getHeaders()
      })
      if (!response.ok) throw new Error('Failed to shred clipboard')
      setClipboardText('')
      setClipboardSynced(true)
      clipboardSyncedRef.current = true
      lastSavedClipboardRef.current = null // Clear conflict tracking
    } catch (err) {
      toast.error(err.message)
    }
  }

  const saveClipboardImage = async (base64Data, mimetype) => {
    try {
      let bodyData

      // E2EE: If locked (have encryption key), encrypt before sending
      if (encryptionKeyRef.current) {
        // Convert base64 to bytes, encrypt, then send as encrypted_b64
        const imageBytes = crypto.fromBase64(base64Data)
        const encrypted = await crypto.encrypt(encryptionKeyRef.current, imageBytes)
        bodyData = {
          encrypted_b64: crypto.toBase64(encrypted),
          mimetype
        }
      } else {
        bodyData = { image: base64Data, mimetype }
      }

      const response = await fetchWithTimeout('/api/clipboard-image', {
        method: 'POST',
        headers: getHeaders('application/json'),
        body: JSON.stringify(bodyData)
      })
      if (!response.ok) throw new Error('Failed to save image')

      // If we have local encryption, update local state directly instead of fetching
      if (encryptionKeyRef.current) {
        setClipboardImageData({
          hasImage: true,
          mimeType: mimetype,
          localDecryptedData: base64Data
        })
      } else {
        await fetchClipboardImage()
      }
    } catch (err) {
      console.error('Failed to save clipboard image:', err)
      throw err
    }
  }

  const shredClipboardImage = async () => {
    try {
      const response = await fetchWithTimeout('/api/clipboard-image', {
        method: 'DELETE',
        headers: getHeaders()
      })
      if (!response.ok) throw new Error('Failed to shred image')
      setClipboardImageData(null)
    } catch (err) {
      toast.error(err.message)
    }
  }

  const handleUpload = async (fileList) => {
    if (!fileList || fileList.length === 0) return

    setUploading(true)
    setUploadProgress(0)

    try {
      const totalFiles = fileList.length
      const newFiles = []

      for (let i = 0; i < totalFiles; i++) {
        const file = fileList[i]

        // E2EE: If locked (have encryption key), encrypt file before uploading
        if (encryptionKeyRef.current) {
          // Read file as bytes
          const fileBytes = new Uint8Array(await file.arrayBuffer())

          // Encrypt the file
          const encryptedData = await crypto.encrypt(encryptionKeyRef.current, fileBytes)

          // Generate a unique ID for the file
          const fileId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

          // Send encrypted file data to server
          const response = await fetchWithTimeout('/api/upload/encrypted', {
            method: 'POST',
            headers: getHeaders('application/json'),
            body: JSON.stringify({
              id: fileId,
              name: file.name,
              mimetype: file.type || 'application/octet-stream',
              size: file.size,
              encrypted_b64: crypto.toBase64(encryptedData)
            })
          }, 120000)

          const data = await response.json()
          if (!response.ok) throw new Error(data.error || 'Upload failed')

          // Store decrypted file locally for display
          newFiles.push({
            id: data.id || fileId,
            name: file.name,
            mimetype: file.type || 'application/octet-stream',
            size: file.size,
            localDecryptedData: fileBytes
          })
        } else {
          // Normal plaintext upload
          const formData = new FormData()
          formData.append('file', file)

          const response = await fetchWithTimeout('/api/upload', {
            method: 'POST',
            headers: sessionToken ? { 'X-Session-Token': sessionToken } : {},
            body: formData
          }, 120000) // 2 min timeout for uploads

          const data = await response.json()
          if (!response.ok) throw new Error(data.error || 'Upload failed')

          // Track uploaded file for conflict detection
          newFiles.push({ id: data.id })
        }

        setUploadProgress(((i + 1) / totalFiles) * 100)
      }

      toast.success(`${totalFiles} file${totalFiles > 1 ? 's' : ''} captured!`)

      // Track uploaded file IDs for conflict detection (brief window to detect immediate removal)
      const uploadedIds = newFiles.map(f => f.id).filter(Boolean)
      if (uploadedIds.length > 0) {
        lastSavedFilesRef.current = [...(lastSavedFilesRef.current || []), ...uploadedIds]
        // Clear tracking after 5 seconds - enough time to detect immediate conflicts
        setTimeout(() => {
          if (lastSavedFilesRef.current) {
            lastSavedFilesRef.current = lastSavedFilesRef.current.filter(id => !uploadedIds.includes(id))
            if (lastSavedFilesRef.current.length === 0) {
              lastSavedFilesRef.current = null
            }
          }
        }, 5000)
      }

      // If we have local encryption, add files to local state (excluding plaintext-only entries)
      const encryptedFiles = newFiles.filter(f => f.localDecryptedData)
      if (encryptionKeyRef.current && encryptedFiles.length > 0) {
        setFiles(prev => [...prev, ...encryptedFiles])
      } else {
        await fetchFiles()
      }
    } catch (err) {
      toast.error(err.message)
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  const handleDownload = async (file) => {
    // Always use fetch + blob approach to avoid iOS PWA black screen issue
    // (window.location.href can trap users in share sheet with no back button)
    try {
      let blob

      // E2EE: If file has locally decrypted data (session was unlocked locally), use that
      if (file.localDecryptedData) {
        // localDecryptedData is a Uint8Array of decrypted bytes
        blob = new Blob([file.localDecryptedData], { type: file.mimetype || 'application/octet-stream' })
      } else {
        // Normal mode: fetch from server
        const response = await fetchWithTimeout(`/api/files/${file.id}/download`, {
          headers: getHeaders()
        }, 120000) // 2 min timeout for downloads
        if (!response.ok) throw new Error('Download failed')
        blob = await response.blob()
      }

      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.name
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      // Delay revoking URL to ensure iOS has time to process
      setTimeout(() => window.URL.revokeObjectURL(url), 1000)
    } catch (err) {
      toast.error(err.message)
    }
  }

  const handleShred = async (file) => {
    try {
      const response = await fetchWithTimeout(`/api/files/${file.id}`, {
        method: 'DELETE',
        headers: getHeaders()
      })

      if (!response.ok) throw new Error('Failed to shred file')

      setFiles(files.filter(f => f.id !== file.id))
      toast.success('Sent to singularity!')
    } catch (err) {
      toast.error(err.message)
    }
  }

  // Lock functions - E2EE: encryption happens client-side
  const handleLock = async (password, clearExisting) => {
    let key = null
    try {
      // 1. Generate salt and derive key client-side
      const salt = crypto.generateSalt()
      key = await crypto.deriveKey(password, salt)
      const keyHash = await crypto.hashKey(key)

      // 2. Encrypt existing data if not clearing
      let encryptedClipboard = null
      let encryptedImage = null
      let encryptedFiles = []

      if (!clearExisting) {
        // Encrypt clipboard text
        if (clipboardText) {
          encryptedClipboard = await crypto.encryptText(key, clipboardText)
        }

        // Encrypt clipboard image
        if (clipboardImageData?.hasImage) {
          try {
            const imageResponse = await fetchWithTimeout('/api/clipboard-image/data', {
              headers: getHeaders()
            })
            if (imageResponse.ok) {
              const imageBlob = await imageResponse.blob()
              const imageBytes = new Uint8Array(await imageBlob.arrayBuffer())
              encryptedImage = await crypto.encrypt(key, imageBytes)
            }
          } catch (err) {
            console.warn('Failed to encrypt clipboard image:', err)
          }
        }

        // Encrypt files
        for (const file of files) {
          try {
            const fileResponse = await fetchWithTimeout(`/api/files/${file.id}/download`, {
              headers: getHeaders()
            })
            if (fileResponse.ok) {
              const fileBlob = await fileResponse.blob()
              const fileBytes = new Uint8Array(await fileBlob.arrayBuffer())
              const encryptedData = await crypto.encrypt(key, fileBytes)
              encryptedFiles.push({
                id: file.id,
                name: file.name,
                mimetype: file.mimetype,
                size: file.size,
                encrypted_b64: crypto.toBase64(encryptedData)
              })
            }
          } catch (err) {
            console.warn(`Failed to encrypt file ${file.name}:`, err)
          }
        }
      }

      // 3. Send to server (server cannot decrypt - only has keyHash for verification)
      const response = await fetchWithTimeout('/api/lock', {
        method: 'POST',
        headers: getHeaders('application/json'),
        body: JSON.stringify({
          keyHash_b64: crypto.toBase64(keyHash),
          salt_b64: crypto.toBase64(salt),
          clearExisting,
          encryptedClipboard_b64: encryptedClipboard ? crypto.toBase64(encryptedClipboard) : null,
          encryptedImage_b64: encryptedImage ? crypto.toBase64(encryptedImage) : null,
          imageMimeType: clipboardImageData?.mimeType || null,
          encryptedFiles: encryptedFiles.length > 0 ? encryptedFiles : null
        })
      })

      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to lock session')

      // 4. Store session token and update state
      setSessionToken(data.token)
      sessionStorage.setItem('session-token', data.token)
      setIsLocked(true)
      prevLockedRef.current = true // Prevent "from another device" toast
      setHasSession(true)

      if (clearExisting) {
        setFiles([])
        setClipboardText('')
        setClipboardImageData(null)
      }

      // 5. Store encryption key so user stays in the main UI after sealing
      // This allows them to continue using the app without re-entering password
      setEncryptionKey(key)
      key = null // Prevent finally from wiping our stored key

      toast.success('Session sealed!')
    } finally {
      // 6. Only wipe key if we didn't store it (error case)
      if (key) {
        crypto.wipe(key)
      }
    }
  }

  // Unlock - E2EE: decryption happens client-side ONLY
  // IMPORTANT: Data NEVER goes back to server as plaintext
  // Server stays locked, data stays encrypted on server
  // We decrypt locally and store the key for future operations
  const handleUnlock = async (password) => {
    let key = null
    try {
      // 1. Get salt from server
      const saltResponse = await fetchWithTimeout('/api/lock/salt', {
        headers: getHeaders()
      })
      if (!saltResponse.ok) {
        throw new Error('Failed to get encryption salt')
      }
      const { salt_b64 } = await saltResponse.json()
      const salt = crypto.fromBase64(salt_b64)

      // 2. Derive key and hash it client-side
      key = await crypto.deriveKey(password, salt)
      const keyHash = await crypto.hashKey(key)

      // 3. Verify with server and get encrypted data
      // Note: Server stays locked, returns encrypted blobs only
      const response = await fetchWithTimeout('/api/unlock', {
        method: 'POST',
        headers: getHeaders('application/json'),
        body: JSON.stringify({ keyHash_b64: crypto.toBase64(keyHash) })
      })

      if (!response.ok) {
        // Try to parse error message, but handle non-JSON responses
        let errorMessage = 'Invalid password'
        try {
          const errorData = await response.json()
          errorMessage = errorData.error || errorMessage
        } catch {
          // Response wasn't JSON, use default message
        }
        throw new Error(errorMessage)
      }

      const data = await response.json()

      // 4. Store session token
      const newToken = data.token
      setSessionToken(newToken)
      sessionStorage.setItem('session-token', newToken)

      // 5. Store encryption key in memory for future decrypt/encrypt operations
      // This key NEVER leaves the client
      setEncryptionKey(key)
      key = null // Prevent cleanup from wiping our stored key

      // 6. Decrypt clipboard text locally (DO NOT send back to server!)
      if (data.encryptedClipboard_b64) {
        try {
          const encryptedClipboard = crypto.fromBase64(data.encryptedClipboard_b64)
          const text = await crypto.decryptText(encryptionKeyRef.current || await crypto.deriveKey(password, salt), encryptedClipboard)
          setClipboardText(text)
        } catch (err) {
          console.error('Failed to decrypt clipboard:', err)
        }
      }

      // 7. Decrypt clipboard image locally (DO NOT send back to server!)
      if (data.encryptedImage_b64) {
        try {
          const encryptedImage = crypto.fromBase64(data.encryptedImage_b64)
          const imageBytes = await crypto.decrypt(encryptionKeyRef.current || await crypto.deriveKey(password, salt), encryptedImage)
          // Store decrypted image data locally for display
          const base64Image = crypto.toBase64(imageBytes)
          setClipboardImageData({
            hasImage: true,
            mimeType: data.imageMimeType || 'image/png',
            localDecryptedData: base64Image // Local only, never sent to server
          })
        } catch (err) {
          console.error('Failed to decrypt clipboard image:', err)
        }
      }

      // 8. Decrypt files locally (DO NOT send back to server!)
      if (data.encryptedFiles && data.encryptedFiles.length > 0) {
        const decryptedFiles = []
        for (const encFile of data.encryptedFiles) {
          try {
            const encryptedData = crypto.fromBase64(encFile.encrypted_b64)
            const fileBytes = await crypto.decrypt(encryptionKeyRef.current || await crypto.deriveKey(password, salt), encryptedData)
            decryptedFiles.push({
              id: encFile.id,
              name: encFile.name,
              mimetype: encFile.mimetype,
              size: encFile.size,
              localDecryptedData: fileBytes // Local only, never sent to server
            })
          } catch (err) {
            console.error(`Failed to decrypt file ${encFile.name}:`, err)
          }
        }
        setFiles(decryptedFiles)
      }

      // 9. Update state - session is still locked on server, but we have the key locally
      setHasSession(true)
      // Note: isLocked stays true because server is still locked
      // But hasSession=true means we have authenticated and have the decryption key

      toast.success('Session unlocked locally. Data decrypted.')
    } finally {
      // 10. Only wipe key if we didn't store it (error case)
      if (key) {
        crypto.wipe(key)
      }
    }
  }

  const handleForceUnlock = async () => {
    const response = await fetchWithTimeout('/api/lock/force-unlock', {
      method: 'POST',
      headers: getHeaders('application/json'),
      body: JSON.stringify({ confirm: 'SHRED' })
    })

    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Failed to force unlock')

    // Clear session and encryption key
    setSessionToken(null)
    sessionStorage.removeItem('session-token')

    // Wipe encryption key from memory
    if (encryptionKey) {
      crypto.wipe(encryptionKey)
    }
    setEncryptionKey(null)

    setIsLocked(false)
    prevLockedRef.current = false // Prevent "from another device" toast
    setHasSession(false)
    setFiles([])
    setClipboardText('')
    setClipboardImageData(null)

    toast.success('All data consumed. Session breached.')
  }

  const handleLockButtonClick = () => {
    if (isLocked && !hasSession) {
      setShowUnlockModal(true)
    } else if (isLocked && hasSession) {
      // Already unlocked, could add option to re-lock or show info
      setShowUnlockModal(true)
    } else {
      setShowLockModal(true)
    }
  }

  const formatSize = (bytes) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  const getFileIcon = (mimetype, name) => {
    if (mimetype?.startsWith('image/')) return 'image'
    if (mimetype?.startsWith('video/')) return 'movie'
    if (mimetype?.startsWith('audio/')) return 'audio_file'
    if (mimetype?.includes('pdf')) return 'picture_as_pdf'
    if (mimetype?.includes('zip') || mimetype?.includes('rar') || mimetype?.includes('7z') || name?.endsWith('.zip') || name?.endsWith('.rar')) return 'folder_zip'
    if (mimetype?.includes('word') || name?.endsWith('.doc') || name?.endsWith('.docx')) return 'description'
    if (mimetype?.includes('sheet') || mimetype?.includes('excel') || name?.endsWith('.xls') || name?.endsWith('.xlsx')) return 'table_chart'
    if (mimetype?.includes('presentation') || name?.endsWith('.ppt') || name?.endsWith('.pptx')) return 'slideshow'
    if (mimetype?.includes('text') || name?.endsWith('.txt')) return 'article'
    if (mimetype?.includes('json') || name?.endsWith('.json')) return 'data_object'
    if (name?.endsWith('.js') || name?.endsWith('.ts') || name?.endsWith('.jsx') || name?.endsWith('.tsx') || name?.endsWith('.py') || name?.endsWith('.java') || name?.endsWith('.cpp') || name?.endsWith('.c')) return 'code'
    return 'draft'
  }

  const getIconColor = (mimetype, name) => {
    if (mimetype?.startsWith('image/')) return 'text-kurz-purple'
    if (mimetype?.startsWith('video/')) return 'text-kurz-pink'
    if (mimetype?.startsWith('audio/')) return 'text-kurz-orange'
    if (mimetype?.includes('pdf')) return 'text-red-500'
    if (mimetype?.includes('zip') || mimetype?.includes('rar') || mimetype?.includes('7z') || name?.endsWith('.zip') || name?.endsWith('.rar')) return 'text-amber-500'
    if (mimetype?.includes('word') || name?.endsWith('.doc') || name?.endsWith('.docx')) return 'text-blue-600'
    if (mimetype?.includes('sheet') || mimetype?.includes('excel') || name?.endsWith('.xls') || name?.endsWith('.xlsx')) return 'text-green-600'
    return 'text-kurz-blue'
  }

  const formatTime = (isoString) => {
    const date = new Date(isoString)
    const now = new Date()
    const diff = now - date

    if (diff < 60000) return 'Just now'
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
    return date.toLocaleDateString()
  }

  // Show locked overlay if locked and no encryption key (user hasn't entered password)
  // Once user enters password, encryptionKey is set and we show decrypted data locally
  const showLockedOverlay = isLocked && !encryptionKey

  return (
    <>
      <ToastProvider />

      {/* Skip link for accessibility */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4
                   bg-kurz-cyan text-kurz-dark px-4 py-2 rounded z-50 font-display font-bold"
      >
        Skip to main content
      </a>

      <div className="min-h-screen geometric-bg pb-safe">
        {/* Header */}
        <header className="bg-kurz-dark border-b-2 border-kurz-cyan pt-safe">
          <div className="max-w-3xl mx-auto px-4 px-safe py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 flex items-center justify-center">
                <img src="/blackhole.svg" alt="" className="w-full h-full" aria-hidden="true" />
              </div>
              <h1 className="font-display font-black text-2xl text-white uppercase tracking-tight">
                Event Horizon
              </h1>
            </div>

            <LockButton isLocked={isLocked} hasUnlockedKey={!!encryptionKey} onClick={handleLockButtonClick} />
          </div>
        </header>

        {/* Security Banner */}
        <SecurityBanner isLocked={isLocked} />

        <main id="main-content" className="max-w-3xl mx-auto px-4 px-safe py-6 space-y-6">
          {showLockedOverlay ? (
            // Locked overlay - no animation to prevent flash on state updates
            <div className="kurz-card-shadow kurz-border bg-white rounded overflow-hidden">
              <div className="p-8 text-center">
                <span className="material-symbols-outlined text-6xl text-kurz-blue block mb-4">lock</span>
                <h2 className="font-display font-bold text-2xl text-kurz-dark uppercase mb-2">
                  Session Sealed
                </h2>
                <p className="text-gray-600 mb-6">
                  Enter the session password to access the accretion disk.
                </p>
                <button
                  onClick={() => setShowUnlockModal(true)}
                  className="bg-kurz-blue hover:bg-kurz-purple text-white font-display font-bold uppercase
                             py-3 px-6 rounded kurz-border transition-colors
                             focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
                >
                  Unseal Session
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Upload Zone */}
              <UploadZone
                onUpload={handleUpload}
                uploading={uploading}
                uploadProgress={uploadProgress}
              />

              {/* Accretion Section */}
              <section aria-labelledby="accretion-heading">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-kurz-orange text-2xl" aria-hidden="true">
                    cyclone
                  </span>
                  <h2 id="accretion-heading" className="font-display font-black text-xl text-kurz-dark uppercase tracking-tight">
                    Accretion
                  </h2>
                </div>

                <div className="space-y-6">
                  {/* Wormhole (Text Clipboard) */}
                  <Clipboard
                    text={clipboardText}
                    synced={clipboardSynced}
                    onSave={saveClipboard}
                    onShred={shredClipboard}
                  />

                  {/* Photon Capture (Image Clipboard) */}
                  <ClipboardImage
                    imageData={clipboardImageData}
                    onPaste={saveClipboardImage}
                    onShred={shredClipboardImage}
                    sessionToken={sessionToken}
                    isLocked={isLocked}
                  />

                  {/* Accretion Disk (Files List) */}
                  <div className="kurz-card-shadow kurz-border bg-white rounded overflow-hidden">
                    <div className="bg-kurz-dark p-3 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-kurz-cyan" aria-hidden="true">
                          inventory_2
                        </span>
                        <span className="font-display font-bold text-white uppercase text-sm">
                          Accretion Disk
                        </span>
                        {isLocked && (
                          <span className="material-symbols-outlined text-kurz-green text-sm" title="Encrypted">
                            lock
                          </span>
                        )}
                      </div>
                      <span
                        className="bg-kurz-cyan text-kurz-dark px-2 py-0.5 rounded font-display font-bold text-xs"
                        aria-label={`${files.length} files`}
                      >
                        {files.length}
                      </span>
                    </div>

                    {loading ? (
                      <div className="divide-y divide-gray-100" role="status" aria-label="Loading files">
                        {[1, 2, 3].map(i => <FileCardSkeleton key={i} />)}
                      </div>
                    ) : files.length === 0 ? (
                      <div className="p-8 text-center">
                        <span className="material-symbols-outlined text-4xl text-gray-300 block mb-2" aria-hidden="true">
                          folder_off
                        </span>
                        <p className="text-gray-500 font-display">No data in orbit yet</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-gray-100" role="list" aria-label="Uploaded files">
                        {files.map(file => (
                          <FileCard
                            key={file.id}
                            file={file}
                            onDownload={handleDownload}
                            onShred={handleShred}
                            formatSize={formatSize}
                            formatTime={formatTime}
                            getFileIcon={getFileIcon}
                            getIconColor={getIconColor}
                          />
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {/* Footer Info */}
              <footer className="text-center text-gray-400 text-xs font-display" role="contentinfo">
                <p>Data orbits in the accretion disk. Lost upon stellar collapse.</p>
                <p className="mt-1">Singularity consumes data beyond recovery.</p>
                {isLocked && (
                  <p className="mt-1 text-kurz-green">Session protected by gravitational encryption (AES-256-GCM).</p>
                )}
              </footer>
            </>
          )}
        </main>
      </div>

      {/* Lock Modal */}
      <LockModal
        isOpen={showLockModal}
        onClose={() => setShowLockModal(false)}
        onLock={handleLock}
        hasExistingData={hasExistingData}
      />

      {/* Unlock Modal */}
      <UnlockModal
        isOpen={showUnlockModal}
        onClose={() => setShowUnlockModal(false)}
        onUnlock={handleUnlock}
        onForceUnlock={handleForceUnlock}
        isUnlockedLocally={isLocked && !!encryptionKey}
        onRemoveSeal={handleForceUnlock}
      />
    </>
  )
}

export default App
