import { useState } from 'react'
import { toast } from 'sonner'
import { ConfirmModal } from '../ui/Modal'
import { LineNumberedTextarea } from '../ui/LineNumberedTextarea'

export function Clipboard({
  text,
  synced,
  onSave,
  onShred
}) {
  const [expanded, setExpanded] = useState(false)
  const [showShredModal, setShowShredModal] = useState(false)

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success('Copied to clipboard!')
    } catch (err) {
      toast.error('Failed to copy')
    }
  }

  const handleShred = () => {
    onShred()
    toast.success('Sent to singularity!')
  }

  return (
    <div className="kurz-card-shadow kurz-border bg-white rounded overflow-hidden">
      <div className="bg-kurz-dark p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-kurz-green">content_paste</span>
          <span className="font-display font-bold text-white uppercase text-sm">
            Wormhole
          </span>
        </div>
        <div className="flex items-center gap-2">
          {!synced && (
            <span className="text-kurz-cyan text-xs animate-pulse">Saving...</span>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-white/70 hover:text-white p-1.5 rounded transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan"
            aria-label={expanded ? 'Collapse clipboard' : 'Expand clipboard'}
          >
            <span className="material-symbols-outlined text-lg">
              {expanded ? 'expand_less' : 'expand_more'}
            </span>
          </button>
        </div>
      </div>

      <div className="p-3 space-y-3">
        <LineNumberedTextarea
          value={text}
          onChange={onSave}
          minRows={expanded ? 18 : 10}
          placeholder="Paste or type text here..."
        />

        <div className="flex gap-2">
          <button
            onClick={copyToClipboard}
            disabled={!text?.trim()}
            className="flex-1 bg-kurz-blue hover:bg-kurz-purple disabled:bg-gray-300
                       text-white font-display font-bold uppercase py-2.5 px-4 rounded
                       kurz-border transition-all disabled:cursor-not-allowed text-sm
                       flex items-center justify-center gap-2 min-h-[44px]
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
          >
            <span className="material-symbols-outlined text-lg">content_copy</span>
            Copy
          </button>
          <button
            onClick={() => setShowShredModal(true)}
            disabled={!text?.trim()}
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
        message="Are you sure you want to send this to the singularity? Data cannot escape a black hole."
        confirmText="Consume"
        variant="danger"
      />
    </div>
  )
}
