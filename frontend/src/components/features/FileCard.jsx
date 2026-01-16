import { useState } from 'react'
import { motion } from 'framer-motion'
import { shredVariants } from '../../lib/animations'
import { ConfirmModal } from '../ui/Modal'

export function FileCard({
  file,
  onDownload,
  onShred,
  formatSize,
  formatTime,
  getFileIcon,
  getIconColor
}) {
  const [showShredModal, setShowShredModal] = useState(false)
  const [isShredding, setIsShredding] = useState(false)

  const handleShred = async () => {
    setIsShredding(true)
    await new Promise(resolve => setTimeout(resolve, 400))
    onShred(file)
  }

  return (
    <>
      <motion.div
        variants={isShredding ? shredVariants : undefined}
        animate={isShredding ? 'shredding' : undefined}
        className="p-4 flex items-center gap-3 bg-white hover:bg-kurz-bg/50 transition-colors"
      >
        <span
          className={`material-symbols-outlined text-3xl ${getIconColor(file.mimetype, file.name)}`}
          style={{ flexShrink: 0 }}
        >
          {getFileIcon(file.mimetype, file.name)}
        </span>

        <div style={{ flex: '1 1 auto', minWidth: 0, overflow: 'hidden' }}>
          <p
            className="font-display font-bold text-kurz-dark"
            style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
            title={file.name}
          >
            {file.name}
          </p>
          <p className="text-gray-500 text-xs" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>{formatSize(file.size)}</span>
            <span aria-hidden="true">&bull;</span>
            <span>{formatTime(file.uploadedAt)}</span>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
          <motion.button
            onClick={() => onDownload(file)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="bg-kurz-blue hover:bg-kurz-purple text-white p-2.5 rounded kurz-border
                       transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
            aria-label={`Download ${file.name}`}
          >
            <span className="material-symbols-outlined text-lg">download</span>
          </motion.button>
          <motion.button
            onClick={() => setShowShredModal(true)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="bg-kurz-pink hover:bg-kurz-orange text-white p-2.5 rounded kurz-border
                       transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
            aria-label={`Send ${file.name} to singularity`}
          >
            <span className="material-symbols-outlined text-lg">delete_forever</span>
          </motion.button>
        </div>
      </motion.div>

      <ConfirmModal
        isOpen={showShredModal}
        onClose={() => setShowShredModal(false)}
        onConfirm={handleShred}
        title="Send to Singularity?"
        message={`Are you sure you want to send "${file.name}" to the singularity? Data cannot escape a black hole.`}
        confirmText="Consume"
        variant="danger"
      />
    </>
  )
}
