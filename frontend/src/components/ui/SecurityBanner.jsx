import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export function SecurityBanner({ isLocked, onSeal }) {
  const [dismissed, setDismissed] = useState(false)
  // E2EE (Web Crypto) is only available in a secure context (HTTPS or localhost).
  const secureContext = typeof window !== 'undefined' && window.isSecureContext

  useEffect(() => {
    const wasDismissed = sessionStorage.getItem('security-banner-dismissed')
    if (wasDismissed) {
      setDismissed(true)
    }
  }, [])

  const handleDismiss = () => {
    setDismissed(true)
    sessionStorage.setItem('security-banner-dismissed', 'true')
  }

  // Sealed sessions are already E2EE — nothing to nudge.
  if (isLocked || dismissed) return null

  const message = secureContext
    ? 'Unsealed: anyone on your network can read this. Seal the session for end-to-end encryption.'
    : 'End-to-end encryption needs HTTPS. Over http://, data is unsealed and readable on your network — open via https:// or localhost to seal.'

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
              {secureContext ? 'lock_open' : 'warning'}
            </span>
            <p className="text-xs font-display font-semibold">{message}</p>
          </div>
          <div className="flex items-center gap-1">
            {secureContext && onSeal && (
              <button
                onClick={onSeal}
                className="px-3 py-1 bg-kurz-dark text-white text-xs font-display font-bold uppercase rounded transition-colors hover:bg-kurz-dark/80 min-h-[32px]
                           focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-dark focus-visible:ring-offset-1"
              >
                Seal now
              </button>
            )}
            <button
              onClick={handleDismiss}
              className="p-1 hover:bg-kurz-dark/10 rounded transition-colors min-w-[32px] min-h-[32px] flex items-center justify-center"
              aria-label="Dismiss warning"
            >
              <span className="material-symbols-outlined text-lg">close</span>
            </button>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
