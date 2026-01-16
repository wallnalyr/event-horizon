import { useState, useRef, useEffect } from 'react'
import { toast } from 'sonner'
import { ConfirmModal } from '../ui/Modal'

export function ClipboardImage({
  imageData,
  onPaste,
  onShred,
  sessionToken,
  isLocked
}) {
  const [showShredModal, setShowShredModal] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [copying, setCopying] = useState(false)
  const containerRef = useRef(null)
  const fileInputRef = useRef(null)

  // Handle paste event
  useEffect(() => {
    const handlePaste = async (e) => {
      const items = e.clipboardData?.items
      if (!items) return

      for (const item of items) {
        if (item.type.startsWith('image/')) {
          e.preventDefault()
          const file = item.getAsFile()
          if (file) {
            await uploadImage(file)
          }
          break
        }
      }
    }

    document.addEventListener('paste', handlePaste)
    return () => document.removeEventListener('paste', handlePaste)
  }, [sessionToken])

  const uploadImage = async (file) => {
    try {
      // Convert to base64
      const reader = new FileReader()
      reader.onload = async () => {
        const base64 = reader.result.split(',')[1]
        await onPaste(base64, file.type)
        toast.success('Image pasted!')
      }
      reader.readAsDataURL(file)
    } catch (err) {
      toast.error('Failed to paste image')
    }
  }

  // Handle drag and drop
  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = async (e) => {
    e.preventDefault()
    setIsDragging(false)

    const files = e.dataTransfer?.files
    if (files && files.length > 0) {
      const file = files[0]
      if (file.type.startsWith('image/')) {
        await uploadImage(file)
      } else {
        toast.error('Please drop an image file')
      }
    }
  }

  // Handle file input change (for mobile/iOS)
  const handleFileSelect = async (e) => {
    const file = e.target.files?.[0]
    if (file) {
      if (file.type.startsWith('image/')) {
        await uploadImage(file)
      } else {
        toast.error('Please select an image file')
      }
    }
    // Reset input so same file can be selected again
    e.target.value = ''
  }

  // Open file picker
  const openFilePicker = () => {
    fileInputRef.current?.click()
  }

  // Copy image to clipboard
  const copyToClipboard = async () => {
    if (!imageData?.hasImage) return

    setCopying(true)
    try {
      // Fetch the image data
      const headers = sessionToken ? { 'X-Session-Token': sessionToken } : {}
      const response = await fetch('/api/clipboard-image/data', { headers })

      if (!response.ok) throw new Error('Failed to fetch image')

      const blob = await response.blob()

      // Try to copy to clipboard
      if (navigator.clipboard && navigator.clipboard.write) {
        await navigator.clipboard.write([
          new ClipboardItem({ [blob.type]: blob })
        ])
        toast.success('Image copied to clipboard!')
      } else {
        // Fallback: download the image
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `clipboard-image.${blob.type.split('/')[1] || 'png'}`
        a.click()
        URL.revokeObjectURL(url)
        toast.success('Image downloaded (clipboard not supported)')
      }
    } catch (err) {
      console.error('Copy failed:', err)
      toast.error('Failed to copy image')
    } finally {
      setCopying(false)
    }
  }

  const handleShred = () => {
    onShred()
    toast.success('Sent to singularity!')
  }

  const formatSize = (bytes) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  // Build image URL with cache busting
  const imageUrl = imageData?.hasImage
    ? `/api/clipboard-image/data?t=${imageData.updatedAt || Date.now()}`
    : null

  return (
    <div className="kurz-card-shadow kurz-border bg-white rounded overflow-hidden">
      <div className="bg-kurz-dark p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-kurz-purple">image</span>
          <span className="font-display font-bold text-white uppercase text-sm">
            Photon Capture
          </span>
        </div>
        {imageData?.hasImage && (
          <span className="text-kurz-cyan text-xs">
            {formatSize(imageData.size)}
          </span>
        )}
      </div>

      <div className="p-3 space-y-3">
        {/* Hidden file input for mobile/iOS */}
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleFileSelect}
          className="hidden"
          aria-hidden="true"
        />

        {/* Drop zone / Image display */}
        <div
          ref={containerRef}
          onClick={!imageData?.hasImage ? openFilePicker : undefined}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          role={!imageData?.hasImage ? 'button' : undefined}
          tabIndex={!imageData?.hasImage ? 0 : undefined}
          onKeyDown={!imageData?.hasImage ? (e) => e.key === 'Enter' && openFilePicker() : undefined}
          className={`
            relative border-2 border-dashed rounded min-h-[150px]
            flex items-center justify-center transition-all
            ${!imageData?.hasImage ? 'cursor-pointer' : ''}
            ${isDragging
              ? 'border-kurz-cyan bg-kurz-cyan/10'
              : 'border-gray-300 bg-gray-50 hover:border-kurz-purple hover:bg-kurz-purple/5'
            }
          `}
        >
          {imageData?.hasImage ? (
            <div className="w-full p-2">
              <img
                src={imageUrl}
                alt="Clipboard image"
                className="max-w-full max-h-[300px] mx-auto rounded shadow-sm"
                style={{ objectFit: 'contain' }}
              />
            </div>
          ) : (
            <div className="text-center p-6">
              <span className="material-symbols-outlined text-4xl text-gray-300 block mb-2">
                add_photo_alternate
              </span>
              <p className="text-gray-500 font-display text-sm">
                Tap to select or paste an image
              </p>
              <p className="text-gray-400 text-xs mt-1">
                PNG, JPEG, GIF, WebP supported
              </p>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex gap-2">
          {imageData?.hasImage && (
            <button
              onClick={openFilePicker}
              className="bg-kurz-purple hover:bg-kurz-blue
                         text-white font-display font-bold uppercase py-2.5 px-4 rounded
                         kurz-border transition-all text-sm
                         flex items-center justify-center gap-2 min-h-[44px]
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
              aria-label="Replace image"
            >
              <span className="material-symbols-outlined text-lg">swap_horiz</span>
            </button>
          )}
          <button
            onClick={copyToClipboard}
            disabled={!imageData?.hasImage || copying}
            className="flex-1 bg-kurz-blue hover:bg-kurz-purple disabled:bg-gray-300
                       text-white font-display font-bold uppercase py-2.5 px-4 rounded
                       kurz-border transition-all disabled:cursor-not-allowed text-sm
                       flex items-center justify-center gap-2 min-h-[44px]
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
          >
            <span className="material-symbols-outlined text-lg">
              {copying ? 'hourglass_empty' : 'content_copy'}
            </span>
            {copying ? 'Copying...' : 'Copy'}
          </button>
          <button
            onClick={() => setShowShredModal(true)}
            disabled={!imageData?.hasImage}
            className="flex-1 bg-kurz-pink hover:bg-kurz-orange disabled:bg-gray-300
                       text-white font-display font-bold uppercase py-2.5 px-4 rounded
                       kurz-border transition-all disabled:cursor-not-allowed text-sm
                       flex items-center justify-center gap-2 min-h-[44px]
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
          >
            <span className="material-symbols-outlined text-lg">delete_forever</span>
            Singularity
          </button>
        </div>
      </div>

      <ConfirmModal
        isOpen={showShredModal}
        onClose={() => setShowShredModal(false)}
        onConfirm={handleShred}
        title="Send to Singularity?"
        message="Are you sure you want to send this image to the singularity? Data cannot escape a black hole."
        confirmText="Consume"
        variant="danger"
      />
    </div>
  )
}
