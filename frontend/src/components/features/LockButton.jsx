import { motion } from 'framer-motion'

export function LockButton({ isLocked, onClick }) {
  return (
    <motion.button
      onClick={onClick}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      className={`
        flex items-center gap-1.5 px-3 py-1.5 rounded min-h-[44px]
        transition-colors font-display font-bold uppercase text-sm
        focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan
        ${isLocked
          ? 'bg-kurz-green text-kurz-dark'
          : 'bg-white/10 text-white/80 hover:text-white hover:bg-white/20'
        }
      `}
      aria-label={isLocked ? 'Session sealed - click to unseal' : 'Seal session'}
    >
      <span className="material-symbols-outlined text-lg">
        {isLocked ? 'lock' : 'lock_open'}
      </span>
      <span className="hidden sm:inline">
        {isLocked ? 'Sealed' : 'Seal'}
      </span>
    </motion.button>
  )
}
