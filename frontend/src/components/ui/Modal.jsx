import { useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { createPortal } from 'react-dom'
import { modalOverlayVariants, modalContentVariants } from '../../lib/animations'
import { useReducedMotion } from '../../hooks/useReducedMotion'

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  actions,
  variant = 'default'
}) {
  const prefersReducedMotion = useReducedMotion()
  const focusTrapRef = useRef(null)
  const previousActiveElement = useRef(null)

  useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement
      setTimeout(() => {
        const focusableElements = focusTrapRef.current?.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        )
        if (focusableElements?.length) {
          focusableElements[0].focus()
        }
      }, 100)
    } else if (previousActiveElement.current) {
      previousActiveElement.current.focus()
    }
  }, [isOpen])

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [isOpen])

  const variantStyles = {
    default: 'border-t-kurz-cyan',
    danger: 'border-t-kurz-pink'
  }

  const iconStyles = {
    default: { icon: 'help', color: 'text-kurz-cyan' },
    danger: { icon: 'warning', color: 'text-kurz-pink' }
  }

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          initial="hidden"
          animate="visible"
          exit="exit"
          variants={prefersReducedMotion ? {} : modalOverlayVariants}
        >
          <motion.div
            className="absolute inset-0 bg-kurz-dark/80 backdrop-blur-sm"
            onClick={onClose}
            aria-hidden="true"
          />

          <motion.div
            ref={focusTrapRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="modal-title"
            className={`
              relative bg-white rounded kurz-border kurz-card-shadow
              max-w-md w-full border-t-4 ${variantStyles[variant]}
            `}
            variants={prefersReducedMotion ? {} : modalContentVariants}
          >
            <div className="p-6 pb-4">
              <div className="flex items-center gap-3">
                <span className={`material-symbols-outlined text-3xl ${iconStyles[variant].color}`}>
                  {iconStyles[variant].icon}
                </span>
                <h2 id="modal-title" className="font-display font-bold text-xl text-kurz-dark uppercase">
                  {title}
                </h2>
              </div>
            </div>

            <div className="px-6 pb-4">
              {children}
            </div>

            <div className="p-6 pt-4 flex gap-3 justify-end border-t border-gray-100">
              {actions}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body
  )
}

export function ConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'danger'
}) {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      variant={variant}
      actions={
        <>
          <button
            onClick={onClose}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                       rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
          >
            {cancelText}
          </button>
          <button
            onClick={() => { onConfirm(); onClose() }}
            className={`
              min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-white
              rounded kurz-border transition-colors
              focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
              ${variant === 'danger' ? 'bg-kurz-pink hover:bg-kurz-orange' : 'bg-kurz-blue hover:bg-kurz-purple'}
            `}
          >
            {confirmText}
          </button>
        </>
      }
    >
      <p className="text-gray-600">{message}</p>
    </Modal>
  )
}
