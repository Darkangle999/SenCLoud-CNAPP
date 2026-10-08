import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  /** Reset when the tree below changes (e.g. route switch). */
  resetKey?: string
  children: ReactNode
}

interface State {
  error: Error | null
  resetKey?: string
}

const TOPBAR_HEIGHT = 'var(--topbar-h, 56px)'
const RAIL_WIDTH = 'var(--rail-w, 64px)'

/** Last-resort boundary: a render crash must never leave a blank white page.
 *  Shows the error plus a recovery action that clears locally cached state
 *  (theme/scope localStorage keys and the Vite HMR cache) and reloads. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, resetKey: this.props.resetKey }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null, resetKey: this.props.resetKey })
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Unhandled UI error:', error, info.componentStack)
  }

  private recover = () => {
    try {
      localStorage.clear()
      sessionStorage.clear()
      if ('caches' in window) void caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
    } catch {
      /* storage unavailable; reload is still worth it */
    }
    window.location.reload()
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div
        role="alert"
        style={{
          position: 'fixed',
          inset: 0,
          display: 'grid',
          placeItems: 'center',
          background: 'var(--bg, #f4f6fb)',
          color: 'var(--text, #1a2233)',
          fontFamily: 'var(--font-sans, system-ui, sans-serif)',
        }}
      >
        <div
          style={{
            maxWidth: 460,
            padding: '28px 32px',
            borderRadius: 14,
            background: 'var(--surface, #fff)',
            boxShadow: '0 12px 40px rgb(15 23 42 / 0.12)',
            marginLeft: RAIL_WIDTH,
            marginTop: TOPBAR_HEIGHT,
          }}
        >
          <h2 style={{ margin: 0, fontSize: 17 }}>Something broke while rendering</h2>
          <p style={{ margin: '10px 0 4px', fontSize: 13, lineHeight: 1.5, opacity: 0.8 }}>
            This is usually stale cached state after a redeploy. Recovery clears local cache and reloads.
          </p>
          <pre
            style={{
              margin: '12px 0',
              padding: '10px 12px',
              maxHeight: 120,
              overflow: 'auto',
              fontSize: 11.5,
              borderRadius: 8,
              background: 'var(--surface-2, #f1f3f9)',
              whiteSpace: 'pre-wrap',
            }}
          >
            {error.message || String(error)}
          </pre>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              type="button"
              onClick={this.recover}
              style={{
                padding: '9px 16px',
                borderRadius: 8,
                border: 0,
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: 13,
                background: 'var(--brand, #2563eb)',
                color: '#fff',
              }}
            >
              Clear cache &amp; reload
            </button>
            <button
              type="button"
              onClick={() => this.setState({ error: null })}
              style={{
                padding: '9px 16px',
                borderRadius: 8,
                cursor: 'pointer',
                fontSize: 13,
                background: 'transparent',
                border: '1px solid var(--border, #d7dce6)',
                color: 'inherit',
              }}
            >
              Try again
            </button>
          </div>
        </div>
      </div>
    )
  }
}
