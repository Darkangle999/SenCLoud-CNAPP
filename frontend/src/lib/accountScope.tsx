// Global "which account am I looking at" scope. The backend already filters
// every read endpoint by account_id (the CloudAccount row id); this is the
// missing client half — one selected id, threaded into each page's api call so
// the whole console shows one account's resources at a time (null = all).

import { createContext, useContext, useEffect, useState } from 'react'

const KEY = 'cs.accountScope'
const PROVIDER_KEY = 'cs.providerScope'
const REGION_KEY = 'cs.regionScope'

export type CloudProvider = 'aws' | 'azure' | 'gcp'

interface Scope {
  accountId: number | null // null only while connected account data loads
  setAccountId: (id: number | null) => void
  provider: CloudProvider
  setProvider: (p: CloudProvider) => void
  region: string
  setRegion: (region: string) => void
}

const Ctx = createContext<Scope>({
  accountId: null,
  setAccountId: () => {},
  provider: 'aws',
  setProvider: () => {},
  region: 'ap-south-1',
  setRegion: () => {},
})

export function AccountScopeProvider({ children }: { children: React.ReactNode }) {
  const [accountId, setAccountId] = useState<number | null>(() => {
    const raw = localStorage.getItem(KEY)
    return raw ? Number(raw) : null
  })
  const [provider, setProvider] = useState<CloudProvider>(() => {
    const raw = localStorage.getItem(PROVIDER_KEY)
    return raw === 'aws' || raw === 'azure' || raw === 'gcp' ? raw : 'aws'
  })
  const [region, setRegion] = useState(() => localStorage.getItem(REGION_KEY) || 'ap-south-1')

  useEffect(() => {
    if (accountId === null) localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, String(accountId))
  }, [accountId])

  useEffect(() => {
    localStorage.setItem(PROVIDER_KEY, provider)
  }, [provider])

  useEffect(() => {
    localStorage.setItem(REGION_KEY, region)
  }, [region])

  return <Ctx.Provider value={{ accountId, setAccountId, provider, setProvider, region, setRegion }}>{children}</Ctx.Provider>
}

/** Selected account id (or null for all). Pass into api calls AND into the
 *  useApi deps array so a scope change refetches. */
export function useAccountScope() {
  return useContext(Ctx)
}
