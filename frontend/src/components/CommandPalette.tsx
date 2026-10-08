import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

interface Command {
  label: string
  hint: string
  to: string
}

const COMMANDS: Command[] = [
  { label: 'Dashboard', hint: 'Security posture overview', to: '/' },
  { label: 'Cloud accounts', hint: 'Onboard and manage accounts', to: '/accounts' },
  { label: 'Inventory', hint: 'All cloud assets', to: '/inventory' },
  { label: 'Findings', hint: 'Security issues and misconfigurations', to: '/findings' },
  { label: 'Attack paths', hint: 'Toxic combination explorer', to: '/attack-paths' },
  { label: 'Identity', hint: 'IAM principals and risk', to: '/identity' },
  { label: 'Data security', hint: 'Data stores and exposure', to: '/data' },
  { label: 'Architecture', hint: 'Network and architecture view', to: '/architecture' },
  { label: 'Runtime sensors', hint: 'Runtime collection status', to: '/sensors' },
  { label: 'Vulnerabilities', hint: 'CVEs across compute', to: '/vulnerabilities' },
  { label: 'Infrastructure as code', hint: 'IaC scan results', to: '/iac' },
  { label: 'Compliance', hint: 'Framework scores and controls', to: '/compliance' },
  { label: 'Projects', hint: 'Workspace settings', to: '/settings' },
]

/** Ctrl+K command palette for fast enterprise navigation. */
export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setOpen((value) => !value)
      }
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActive(0)
      window.setTimeout(() => inputRef.current?.focus(), 10)
    }
  }, [open])

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return COMMANDS
    return COMMANDS.filter(
      (command) =>
        command.label.toLowerCase().includes(q) || command.hint.toLowerCase().includes(q),
    )
  }, [query])

  if (!open) return null

  const go = (to: string) => {
    setOpen(false)
    navigate(to)
  }

  return (
    <div className="cmdk-overlay" onClick={() => setOpen(false)}>
      <div
        className="cmdk-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(event) => event.stopPropagation()}
      >
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Search pages and actions…"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value)
            setActive(0)
          }}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault()
              setActive((i) => Math.min(i + 1, results.length - 1))
            } else if (event.key === 'ArrowUp') {
              event.preventDefault()
              setActive((i) => Math.max(i - 1, 0))
            } else if (event.key === 'Enter' && results[active]) {
              go(results[active].to)
            }
          }}
        />
        <ul className="cmdk-list">
          {results.length === 0 && <li className="cmdk-empty">No matches</li>}
          {results.map((command, index) => (
            <li key={command.to}>
              <button
                type="button"
                className={`cmdk-item${index === active ? ' active' : ''}`}
                onMouseEnter={() => setActive(index)}
                onClick={() => go(command.to)}
              >
                <span className="cmdk-label">{command.label}</span>
                <span className="cmdk-hint">{command.hint}</span>
              </button>
            </li>
          ))}
        </ul>
        <div className="cmdk-foot">↑↓ navigate · ↵ open · esc close</div>
      </div>
    </div>
  )
}
