import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { toast } from 'sonner'

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

// Animations
// Animations moved to individual components

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

  const clipboardSyncedRef = useRef(true)
  const clipboardCooldownRef = useRef(null)
  const prefersReducedMotion = useReducedMotion()

  // Get session token from storage
  useEffect(() => {
    const token = sessionStorage.getItem('session-token')
    if (token) {
      setSessionToken(token)
    }
  }, [])

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

  // Fetch lock status
  const fetchLockStatus = async () => {
    try {
      const response = await fetch('/api/lock/status', {
        headers: getHeaders()
      })
      if (!response.ok) return

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
    } catch (err) {
      console.error('Failed to fetch lock status:', err)
    }
  }

  // Data fetching - poll every 2 seconds for faster sync across devices
  useEffect(() => {
    const fetchData = async () => {
      await fetchLockStatus()
      await Promise.all([fetchFiles(), fetchClipboard(), fetchClipboardImage()])
      setLoading(false)
    }
    fetchData()

    const interval = setInterval(() => {
      fetchLockStatus()
      fetchFiles()
      fetchClipboard()
      fetchClipboardImage()
    }, 2000)

    return () => clearInterval(interval)
  }, [sessionToken])

  const fetchFiles = async () => {
    try {
      const response = await fetch('/api/files', {
        headers: getHeaders()
      })
      if (!response.ok) return

      const data = await response.json()

      // Check if response indicates locked state
      if (data.locked) {
        setIsLocked(true)
        return
      }

      if (Array.isArray(data)) {
        setFiles(data)
      }
    } catch (err) {
      console.error('Failed to fetch files:', err)
    }
  }

  const fetchClipboard = async () => {
    try {
      const response = await fetch('/api/clipboard', {
        headers: getHeaders()
      })
      if (!response.ok) return

      const data = await response.json()

      // Check if response indicates locked state
      if (data.locked) {
        setIsLocked(true)
        return
      }

      if (clipboardSyncedRef.current && data && typeof data.text !== 'undefined') {
        setClipboardText(data.text || '')
      }
    } catch (err) {
      console.error('Failed to fetch clipboard:', err)
    }
  }

  const fetchClipboardImage = async () => {
    try {
      const response = await fetch('/api/clipboard-image', {
        headers: getHeaders()
      })
      if (!response.ok) return

      const data = await response.json()

      // Check if response indicates locked state
      if (data.locked) {
        setIsLocked(true)
        return
      }

      setClipboardImageData(data)
    } catch (err) {
      console.error('Failed to fetch clipboard image:', err)
    }
  }

  const saveClipboard = async (text) => {
    setClipboardText(text)
    setClipboardSynced(false)
    clipboardSyncedRef.current = false

    // Clear any existing cooldown
    if (clipboardCooldownRef.current) {
      clearTimeout(clipboardCooldownRef.current)
    }

    try {
      await fetch('/api/clipboard', {
        method: 'POST',
        headers: getHeaders('application/json'),
        body: JSON.stringify({ text })
      })
      setClipboardSynced(true)
      // Add cooldown before allowing fetched data to overwrite
      // This prevents race conditions with polling
      clipboardCooldownRef.current = setTimeout(() => {
        clipboardSyncedRef.current = true
      }, 2000)
    } catch (err) {
      console.error('Failed to save clipboard:', err)
      toast.error('Failed to save clipboard')
      clipboardSyncedRef.current = true
    }
  }

  const shredClipboard = async () => {
    try {
      const response = await fetch('/api/clipboard', {
        method: 'DELETE',
        headers: getHeaders()
      })
      if (!response.ok) throw new Error('Failed to shred clipboard')
      setClipboardText('')
      setClipboardSynced(true)
      clipboardSyncedRef.current = true
    } catch (err) {
      toast.error(err.message)
    }
  }

  const saveClipboardImage = async (base64Data, mimetype) => {
    try {
      const response = await fetch('/api/clipboard-image', {
        method: 'POST',
        headers: getHeaders('application/json'),
        body: JSON.stringify({ image: base64Data, mimetype })
      })
      if (!response.ok) throw new Error('Failed to save image')
      await fetchClipboardImage()
    } catch (err) {
      console.error('Failed to save clipboard image:', err)
      throw err
    }
  }

  const shredClipboardImage = async () => {
    try {
      const response = await fetch('/api/clipboard-image', {
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
      for (let i = 0; i < totalFiles; i++) {
        const file = fileList[i]
        const formData = new FormData()
        formData.append('file', file)

        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: sessionToken ? { 'X-Session-Token': sessionToken } : {},
          body: formData
        })

        const data = await response.json()
        if (!response.ok) throw new Error(data.error || 'Upload failed')

        setUploadProgress(((i + 1) / totalFiles) * 100)
      }

      toast.success(`${totalFiles} file${totalFiles > 1 ? 's' : ''} captured!`)
      await fetchFiles()
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
      const response = await fetch(`/api/files/${file.id}/download`, {
        headers: getHeaders()
      })
      if (!response.ok) throw new Error('Download failed')

      const blob = await response.blob()
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
      const response = await fetch(`/api/files/${file.id}`, {
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

  // Lock functions
  const handleLock = async (password, clearExisting) => {
    const response = await fetch('/api/lock', {
      method: 'POST',
      headers: getHeaders('application/json'),
      body: JSON.stringify({ password, clearExisting })
    })

    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Failed to lock session')

    // Store session token
    setSessionToken(data.token)
    sessionStorage.setItem('session-token', data.token)
    setIsLocked(true)
    setHasSession(true)

    if (clearExisting) {
      setFiles([])
      setClipboardText('')
      setClipboardImageData(null)
    }

    toast.success('Session sealed!')
  }

  const handleUnlock = async (password) => {
    const response = await fetch('/api/unlock', {
      method: 'POST',
      headers: getHeaders('application/json'),
      body: JSON.stringify({ password })
    })

    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Invalid password')

    // Store session token
    setSessionToken(data.token)
    sessionStorage.setItem('session-token', data.token)
    setHasSession(true)

    // Refresh data
    await Promise.all([fetchFiles(), fetchClipboard(), fetchClipboardImage()])
    toast.success('Session unsealed!')
  }

  const handleForceUnlock = async () => {
    const response = await fetch('/api/lock/force-unlock', {
      method: 'POST',
      headers: getHeaders('application/json'),
      body: JSON.stringify({ confirm: 'SHRED' })
    })

    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Failed to force unlock')

    // Clear session
    setSessionToken(null)
    sessionStorage.removeItem('session-token')
    setIsLocked(false)
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

  // Show locked overlay if locked and no session
  const showLockedOverlay = isLocked && !hasSession

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

            <LockButton isLocked={isLocked} onClick={handleLockButtonClick} />
          </div>
        </header>

        {/* Security Banner */}
        <SecurityBanner isLocked={isLocked} />

        <main id="main-content" className="max-w-3xl mx-auto px-4 px-safe py-6 space-y-6">
          {showLockedOverlay ? (
            // Locked overlay
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="kurz-card-shadow kurz-border bg-white rounded overflow-hidden"
            >
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
            </motion.div>
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
      />
    </>
  )
}

export default App
