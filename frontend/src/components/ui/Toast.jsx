import { Toaster } from 'sonner'

export function ToastProvider() {
  return (
    <Toaster
      position="bottom-center"
      offset={16}
      toastOptions={{
        style: {
          background: '#080f2b',
          color: 'white',
          border: '2px solid #080f2b',
          boxShadow: '4px 4px 0 0 #080f2b',
          fontFamily: 'Outfit, sans-serif',
          fontWeight: 600,
          textTransform: 'uppercase',
          fontSize: '14px',
          borderRadius: '4px',
          padding: '12px 16px'
        },
        className: 'toast-custom',
        duration: 3000
      }}
    />
  )
}
