import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export function SecurityBanner({ isLocked }) {
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    // Check if banner was dismissed this session
    const wasDismissed = sessionStorage.getItem('security-banner-dismissed')
    if (wasDismissed) {
      setDismissed(true)
    }
  }, [])

  const handleDismiss = () => {
    setDismissed(true)
    sessionStorage.setItem('security-banner-dismissed', 'true')
  }

  // Don't show if locked or dismissed
  if (isLocked || dismissed) return null

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        className="bg-kurz-yellow text-kurz-dark border-b-2 border-kurz-dark"
      >
        <div className="max-w-3xl mx-auto px-4 px-safe py-2 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-1">
            <span className="material-symbols-outlined text-lg" aria-hidden="true">
              warning
            </span>
            <p className="text-xs font-display font-semibold">
              Seal session before adding sensitive data. Anyone with network access can see unsealed content.
            </p>
          </div>
          <button
            onClick={handleDismiss}
            className="p-1 hover:bg-kurz-dark/10 rounded transition-colors min-w-[32px] min-h-[32px] flex items-center justify-center"
            aria-label="Dismiss warning"
          >
            <span className="material-symbols-outlined text-lg">close</span>
          </button>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
