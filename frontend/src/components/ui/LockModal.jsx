import { useState } from 'react'
import { Modal } from './Modal'

export function LockModal({ isOpen, onClose, onLock, hasExistingData }) {
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [clearExisting, setClearExisting] = useState(true)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLock = async () => {
    setError('')

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    try {
      await onLock(password, clearExisting)
      setPassword('')
      setConfirmPassword('')
      setClearExisting(true)
      onClose()
    } catch (err) {
      setError(err.message || 'Failed to lock session')
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    setPassword('')
    setConfirmPassword('')
    setError('')
    setClearExisting(true)
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Seal Session"
      variant="default"
      actions={
        <>
          <button
            onClick={handleClose}
            disabled={loading}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                       rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                       disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleLock}
            disabled={loading || !password || !confirmPassword}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-white
                       rounded kurz-border bg-kurz-blue hover:bg-kurz-purple transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                       disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {loading && (
              <span className="material-symbols-outlined animate-spin text-lg">progress_activity</span>
            )}
            {loading ? 'Deriving Key...' : 'Seal Session'}
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {hasExistingData && (
          <div className="bg-kurz-yellow/20 border-2 border-kurz-yellow rounded p-3">
            <div className="flex items-start gap-2">
              <span className="material-symbols-outlined text-kurz-orange text-lg mt-0.5">warning</span>
              <p className="text-sm text-kurz-dark">
                <strong>Warning:</strong> If data already exists, it will be encrypted but anyone who already viewed it has that information.
                For best security, lock <strong>before</strong> adding sensitive content.
              </p>
            </div>
          </div>
        )}

        <div>
          <label className="block text-sm font-display font-semibold text-kurz-dark mb-1">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Minimum 8 characters"
            className="w-full px-3 py-2.5 border-2 border-kurz-dark/30 rounded
                       focus:border-kurz-blue focus:ring-2 focus:ring-kurz-blue/20 outline-none
                       font-body text-kurz-dark"
            autoFocus
          />
        </div>

        <div>
          <label className="block text-sm font-display font-semibold text-kurz-dark mb-1">
            Confirm Password
          </label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter password"
            className="w-full px-3 py-2.5 border-2 border-kurz-dark/30 rounded
                       focus:border-kurz-blue focus:ring-2 focus:ring-kurz-blue/20 outline-none
                       font-body text-kurz-dark"
          />
        </div>

        {hasExistingData && (
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={clearExisting}
              onChange={(e) => setClearExisting(e.target.checked)}
              className="w-4 h-4 rounded border-2 border-kurz-dark/30 text-kurz-blue
                         focus:ring-2 focus:ring-kurz-blue/20"
            />
            <span className="text-sm text-kurz-dark">
              Clear existing data before locking <span className="text-kurz-green">(recommended)</span>
            </span>
          </label>
        )}

        {error && (
          <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
            <p className="text-sm text-kurz-pink font-semibold">{error}</p>
          </div>
        )}
      </div>
    </Modal>
  )
}

export function UnlockModal({ isOpen, onClose, onUnlock, onForceUnlock, isUnlockedLocally, onRemoveSeal }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showForceUnlock, setShowForceUnlock] = useState(false)
  const [confirmShred, setConfirmShred] = useState('')
  const [showRemoveSeal, setShowRemoveSeal] = useState(false)

  const handleUnlock = async () => {
    setError('')

    if (!password) {
      setError('Password is required')
      return
    }

    setLoading(true)
    try {
      await onUnlock(password)
      setPassword('')
      onClose()
    } catch (err) {
      setError(err.message || 'Invalid password')
    } finally {
      setLoading(false)
    }
  }

  const handleForceUnlock = async () => {
    if (confirmShred !== 'CONSUME') {
      setError('Type CONSUME to confirm')
      return
    }

    setLoading(true)
    try {
      await onForceUnlock()
      setPassword('')
      setConfirmShred('')
      setShowForceUnlock(false)
      onClose()
    } catch (err) {
      setError(err.message || 'Failed to force unlock')
    } finally {
      setLoading(false)
    }
  }

  const handleRemoveSeal = async () => {
    if (confirmShred !== 'CONSUME') {
      setError('Type CONSUME to confirm')
      return
    }

    setLoading(true)
    try {
      await onRemoveSeal()
      setConfirmShred('')
      setShowRemoveSeal(false)
      onClose()
    } catch (err) {
      setError(err.message || 'Failed to remove seal')
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    setPassword('')
    setError('')
    setShowForceUnlock(false)
    setShowRemoveSeal(false)
    setConfirmShred('')
    onClose()
  }

  // Show "Remove Seal" confirmation view
  if (showRemoveSeal) {
    return (
      <Modal
        isOpen={isOpen}
        onClose={handleClose}
        title="Remove Seal"
        variant="danger"
        actions={
          <>
            <button
              onClick={() => {
                setShowRemoveSeal(false)
                setConfirmShred('')
                setError('')
              }}
              disabled={loading}
              className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                         rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                         disabled:opacity-50"
            >
              Back
            </button>
            <button
              onClick={handleRemoveSeal}
              disabled={loading || confirmShred !== 'CONSUME'}
              className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-white
                         rounded kurz-border bg-kurz-pink hover:bg-kurz-orange transition-colors
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                         disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading && (
                <span className="material-symbols-outlined animate-spin text-lg">progress_activity</span>
              )}
              Consume & Unseal
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
            <div className="flex items-start gap-2">
              <span className="material-symbols-outlined text-kurz-pink text-lg mt-0.5">warning</span>
              <p className="text-sm text-kurz-dark">
                <strong>Warning:</strong> Removing the seal will send all encrypted data to the singularity.
                The session will return to unencrypted mode.
              </p>
            </div>
          </div>

          <div>
            <label className="block text-sm font-display font-semibold text-kurz-dark mb-1">
              Type "CONSUME" to confirm
            </label>
            <input
              type="text"
              value={confirmShred}
              onChange={(e) => setConfirmShred(e.target.value.toUpperCase())}
              placeholder="CONSUME"
              className="w-full px-3 py-2.5 border-2 border-kurz-dark/30 rounded
                         focus:border-kurz-pink focus:ring-2 focus:ring-kurz-pink/20 outline-none
                         font-mono text-kurz-dark uppercase"
              autoFocus
            />
          </div>

          {error && (
            <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
              <p className="text-sm text-kurz-pink font-semibold">{error}</p>
            </div>
          )}
        </div>
      </Modal>
    )
  }

  // Show "Manage Seal" view when user is already unlocked locally
  if (isUnlockedLocally) {
    return (
      <Modal
        isOpen={isOpen}
        onClose={handleClose}
        title="Manage Seal"
        variant="default"
        actions={
          <button
            onClick={handleClose}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                       rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2"
          >
            Close
          </button>
        }
      >
        <div className="space-y-4">
          <div className="bg-kurz-green/10 border-2 border-kurz-green rounded p-3">
            <div className="flex items-start gap-2">
              <span className="material-symbols-outlined text-kurz-green text-lg mt-0.5">lock</span>
              <div>
                <p className="text-sm font-semibold text-kurz-dark">Session is sealed and protected</p>
                <p className="text-sm text-kurz-dark mt-1">
                  Your data is encrypted with AES-256-GCM. Other devices need the password to access.
                </p>
              </div>
            </div>
          </div>

          <div className="border-t border-gray-200 pt-4">
            <button
              onClick={() => setShowRemoveSeal(true)}
              className="w-full text-left flex items-center gap-3 p-3 rounded border-2 border-kurz-dark/20
                         hover:bg-kurz-bg transition-colors"
            >
              <span className="material-symbols-outlined text-kurz-pink">lock_open</span>
              <div>
                <p className="font-display font-bold text-kurz-dark">Remove Seal</p>
                <p className="text-sm text-gray-600">
                  Shred all encrypted data and return to unencrypted mode
                </p>
              </div>
            </button>
          </div>
        </div>
      </Modal>
    )
  }

  if (showForceUnlock) {
    return (
      <Modal
        isOpen={isOpen}
        onClose={handleClose}
        title="Emergency Breach"
        variant="danger"
        actions={
          <>
            <button
              onClick={() => setShowForceUnlock(false)}
              disabled={loading}
              className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                         rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                         disabled:opacity-50"
            >
              Back
            </button>
            <button
              onClick={handleForceUnlock}
              disabled={loading || confirmShred !== 'CONSUME'}
              className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-white
                         rounded kurz-border bg-kurz-pink hover:bg-kurz-orange transition-colors
                         focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                         disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading && (
                <span className="material-symbols-outlined animate-spin text-lg">progress_activity</span>
              )}
              Consume & Breach
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
            <div className="flex items-start gap-2">
              <span className="material-symbols-outlined text-kurz-pink text-lg mt-0.5">warning</span>
              <p className="text-sm text-kurz-dark">
                <strong>Warning:</strong> This will send all encrypted data to the singularity.
                Nothing escapes a black hole.
              </p>
            </div>
          </div>

          <div>
            <label className="block text-sm font-display font-semibold text-kurz-dark mb-1">
              Type "CONSUME" to confirm
            </label>
            <input
              type="text"
              value={confirmShred}
              onChange={(e) => setConfirmShred(e.target.value.toUpperCase())}
              placeholder="CONSUME"
              className="w-full px-3 py-2.5 border-2 border-kurz-dark/30 rounded
                         focus:border-kurz-pink focus:ring-2 focus:ring-kurz-pink/20 outline-none
                         font-mono text-kurz-dark uppercase"
              autoFocus
            />
          </div>

          {error && (
            <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
              <p className="text-sm text-kurz-pink font-semibold">{error}</p>
            </div>
          )}
        </div>
      </Modal>
    )
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Unseal Session"
      variant="default"
      actions={
        <>
          <button
            onClick={handleClose}
            disabled={loading}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-kurz-dark
                       rounded border-2 border-kurz-dark hover:bg-kurz-bg transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                       disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleUnlock}
            disabled={loading || !password}
            className="min-h-[44px] px-4 py-2.5 font-display font-bold uppercase text-white
                       rounded kurz-border bg-kurz-blue hover:bg-kurz-purple transition-colors
                       focus:outline-none focus-visible:ring-2 focus-visible:ring-kurz-cyan focus-visible:ring-offset-2
                       disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {loading && (
              <span className="material-symbols-outlined animate-spin text-lg">progress_activity</span>
            )}
            {loading ? 'Decrypting...' : 'Unlock'}
          </button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-display font-semibold text-kurz-dark mb-1">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter session password"
            className="w-full px-3 py-2.5 border-2 border-kurz-dark/30 rounded
                       focus:border-kurz-blue focus:ring-2 focus:ring-kurz-blue/20 outline-none
                       font-body text-kurz-dark"
            autoFocus
            onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
          />
        </div>

        {error && (
          <div className="bg-kurz-pink/10 border-2 border-kurz-pink rounded p-3">
            <p className="text-sm text-kurz-pink font-semibold">{error}</p>
          </div>
        )}

        <div className="border-t border-gray-200 pt-4">
          <button
            onClick={() => setShowForceUnlock(true)}
            className="text-sm text-kurz-pink hover:underline font-display"
          >
            Forgot password? Emergency breach (consumes all data)
          </button>
        </div>
      </div>
    </Modal>
  )
}
