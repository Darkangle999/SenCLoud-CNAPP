import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

export type RealtimeStatus = 'connecting' | 'live' | 'degraded'
export const REALTIME_EVENT = 'odineyes:realtime'

type RealtimeContextValue = { status: RealtimeStatus; lastEventAt: string | null }
const RealtimeContext = createContext<RealtimeContextValue>({ status: 'connecting', lastEventAt: null })

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<RealtimeStatus>('connecting')
  const [lastEventAt, setLastEventAt] = useState<string | null>(null)

  useEffect(() => {
    let socket: WebSocket | null = null
    let timer: number | null = null
    let stopped = false
    let attempt = 0

    function connect() {
      if (stopped) return
      setStatus(attempt ? 'degraded' : 'connecting')
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/api/realtime/ws`)
      socket.onopen = () => { attempt = 0; setStatus('live') }
      socket.onmessage = (message) => {
        try {
          const detail = JSON.parse(message.data)
          if (detail.type === 'connected') return
          setLastEventAt(new Date().toISOString())
          window.dispatchEvent(new CustomEvent(REALTIME_EVENT, { detail }))
        } catch { /* Ignore malformed server frames. */ }
      }
      socket.onclose = () => {
        if (stopped) return
        setStatus('degraded')
        const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempt++, 5)) + Math.random() * 500
        timer = window.setTimeout(connect, delay)
      }
      socket.onerror = () => socket?.close()
    }

    connect()
    return () => {
      stopped = true
      if (timer !== null) window.clearTimeout(timer)
      socket?.close()
    }
  }, [])

  const value = useMemo(() => ({ status, lastEventAt }), [status, lastEventAt])
  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>
}

export function useRealtime() { return useContext(RealtimeContext) }
