import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError } from '../lib/api'

interface ApiState<T> {
  data: T | null
  error: ApiError | null
  loading: boolean
}

/** Fetch-on-mount (and on dep change) with honest tri-state. `refetch` re-runs
 *  the same call; stale responses from superseded calls are discarded. Pass
 *  `{ enabled: false }` to defer the call (e.g. a tab the user hasn't opened). */
export function useApi<T>(
  fn: () => Promise<T>,
  deps: unknown[] = [],
  opts: { enabled?: boolean } = {},
) {
  const enabled = opts.enabled ?? true
  const [state, setState] = useState<ApiState<T>>({ data: null, error: null, loading: enabled })
  const seq = useRef(0)

  const run = useCallback(() => {
    const id = ++seq.current
    setState((s) => ({ ...s, loading: true, error: null }))
    fn().then(
      (data) => {
        if (seq.current === id) setState({ data, error: null, loading: false })
      },
      (error: unknown) => {
        if (seq.current !== id) return
        const err =
          error instanceof ApiError ? error : new ApiError('GET', '(unknown)', null, String(error))
        setState({ data: null, error: err, loading: false })
      },
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    if (enabled) run()
  }, [run, enabled])

  return { ...state, refetch: run }
}
