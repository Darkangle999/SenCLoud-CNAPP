import { AnimatePresence, motion } from 'motion/react'
import { X } from 'lucide-react'
import { useEffect } from 'react'
import type { ReactNode } from 'react'

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
}: {
  open: boolean
  onClose: () => void
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  return (
    <AnimatePresence>
      {open ? (
        <>
          <motion.div
            className="drawer-scrim"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            onClick={onClose}
          />
          <motion.aside
            className="drawer-panel"
            role="dialog"
            aria-modal="true"
            initial={{ x: 56, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 56, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 420, damping: 38 }}
          >
            <div className="drawer-head">
              <div style={{ minWidth: 0 }}>
                <h2 style={{ fontSize: 15 }}>{title}</h2>
                {subtitle ? (
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3, wordBreak: 'break-all' }}>
                    {subtitle}
                  </div>
                ) : null}
              </div>
              <button className="icon-btn" onClick={onClose} aria-label="Close panel" autoFocus>
                <X />
              </button>
            </div>
            <div className="drawer-body">{children}</div>
          </motion.aside>
        </>
      ) : null}
    </AnimatePresence>
  )
}
