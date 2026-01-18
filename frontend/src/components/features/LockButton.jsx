import { motion } from 'framer-motion'

export function LockButton({ isLocked, hasUnlockedKey, onClick }) {
  // Determine button state:
  // - Not locked: show "Seal" option
  // - Locked + has key: user is unlocked locally, show "Manage" option (cyan)
  // - Locked + no key: user is locked out, show "Sealed" indicator (green)
  const getButtonState = () => {
    if (!isLocked) {
      return {
        icon: 'lock_open',
        text: 'Seal',
        className: 'bg-white/10 text-white/80 hover:text-white hover:bg-white/20',
        ariaLabel: 'Seal session'
      }
    }
    if (hasUnlockedKey) {
      return {
        icon: 'admin_panel_settings',
        text: 'Manage',
        className: 'bg-kurz-cyan text-kurz-dark hover:bg-kurz-cyan/80',
        ariaLabel: 'Manage sealed session'
      }
    }
    return {
      icon: 'lock',
      text: 'Sealed',
      className: 'bg-kurz-green text-kurz-dark',
      ariaLabel: 'Session sealed - click to unseal'
    }
  }

  const state = getButtonState()

  return (
    <motion.button
      onClick={onClick}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      className={`
        flex items-center gap-1.5 px-3 py-1.5 rounded min-h-[44px]
        transition-colors font-display font-bold uppercase text-sm
        focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan
        ${state.className}
      `}
      aria-label={state.ariaLabel}
    >
      <span className="material-symbols-outlined text-lg">
        {state.icon}
      </span>
      <span className="hidden sm:inline">
        {state.text}
      </span>
    </motion.button>
  )
}
