import { useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { uploadZoneVariants } from '../../lib/animations'
import { useReducedMotion } from '../../hooks/useReducedMotion'

export function UploadZone({ onUpload, uploading, uploadProgress = 0 }) {
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef(null)
  const prefersReducedMotion = useReducedMotion()

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    onUpload(e.dataTransfer.files)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    setDragOver(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    setDragOver(false)
  }

  return (
    <motion.div
      onClick={() => !uploading && fileInputRef.current?.click()}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      className={`
        kurz-card-shadow kurz-border bg-white rounded p-8 text-center
        cursor-pointer transition-colors relative overflow-hidden
        min-h-[160px] flex flex-col items-center justify-center
        focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
        ${dragOver ? 'bg-kurz-cyan/10 border-kurz-cyan' : 'hover:bg-kurz-bg'}
        ${uploading ? 'pointer-events-none' : ''}
      `}
      variants={prefersReducedMotion ? {} : uploadZoneVariants}
      animate={dragOver ? 'dragging' : 'idle'}
      role="button"
      tabIndex={0}
      aria-label="Capture files. Click to browse or drop files into the void."
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          fileInputRef.current?.click()
        }
      }}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={(e) => onUpload(e.target.files)}
        className="hidden"
        aria-hidden="true"
      />

      <AnimatePresence mode="wait">
        {uploading ? (
          <motion.div
            key="uploading"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="flex flex-col items-center"
          >
            <motion.span
              className="material-symbols-outlined text-5xl text-kurz-blue block mb-3"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
            >
              progress_activity
            </motion.span>
            <p className="font-display font-bold text-kurz-dark uppercase mb-3">
              Capturing...
            </p>
            <div className="w-48 h-2 bg-gray-200 rounded-full overflow-hidden border-2 border-kurz-dark">
              <motion.div
                className="h-full bg-kurz-cyan"
                initial={{ width: 0 }}
                animate={{ width: `${uploadProgress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
            <p className="text-sm text-gray-500 mt-2">{Math.round(uploadProgress)}%</p>
          </motion.div>
        ) : (
          <motion.div
            key="idle"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="flex flex-col items-center"
          >
            <motion.span
              className="material-symbols-outlined text-5xl text-kurz-cyan block mb-3"
              animate={dragOver ? { scale: 1.2, y: -5 } : { scale: 1, y: 0 }}
            >
              cloud_upload
            </motion.span>
            <p className="font-display font-bold text-kurz-dark uppercase">
              {dragOver ? 'Release to accrete' : 'Drop files to accrete'}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
