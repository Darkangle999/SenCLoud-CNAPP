import { createContext, useCallback, useContext, useState } from 'react'
import type { ReactNode } from 'react'

export type Persona = 'executive' | 'analyst' | 'engineer' | 'grc'

export const PERSONAS: Record<Persona, { label: string; role: string; focus: string }> = {
  executive: {
    label: 'CISO',
    role: 'Security leadership',
    focus: 'Business exposure, critical risk and security progress',
  },
  analyst: {
    label: 'Security analyst',
    role: 'Risk operations',
    focus: 'Triage, evidence and active attack paths',
  },
  engineer: {
    label: 'Cloud engineer',
    role: 'Remediation',
    focus: 'Ownership, configuration fixes and validation',
  },
  grc: {
    label: 'GRC & audit',
    role: 'Governance',
    focus: 'Control coverage, exceptions and audit readiness',
  },
}

const STORAGE_KEY = 'odineyes.persona'

function initialPersona(): Persona {
  try {
    const value = localStorage.getItem(STORAGE_KEY)
    if (value && value in PERSONAS) return value as Persona
  } catch {
    // Storage may be unavailable in private browsing.
  }
  return 'analyst'
}

const PersonaContext = createContext<{
  persona: Persona
  setPersona: (persona: Persona) => void
}>({ persona: 'analyst', setPersona: () => {} })

export function PersonaProvider({ children }: { children: ReactNode }) {
  const [persona, setPersonaState] = useState<Persona>(initialPersona)

  const setPersona = useCallback((next: Persona) => {
    setPersonaState(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // The in-memory preference still works for this session.
    }
  }, [])

  return (
    <PersonaContext.Provider value={{ persona, setPersona }}>
      {children}
    </PersonaContext.Provider>
  )
}

export function usePersona() {
  return useContext(PersonaContext)
}
