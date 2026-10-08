import {
  Activity,
  BadgeCheck,
  Boxes,
  Cloud,
  Cpu,
  Database,
  FileCode2,
  KeyRound,
  LayoutDashboard,
  Moon,
  Network,
  Route,
  Settings,
  ShieldAlert,
  SlidersHorizontal,
  Sun,
} from 'lucide-react'
import { useEffect } from 'react'
import { motion, useReducedMotion } from 'motion/react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { PERSONAS, usePersona } from '../lib/persona'
import { useRealtime } from '../lib/realtime'
import type { Persona } from '../lib/persona'
import { useTheme } from '../theme'

function AccountScopePicker() {
  const { accountId, setAccountId } = useAccountScope()
  const accounts = useApi(() => api.accounts())
  const active = (accounts.data?.items ?? []).filter((account) => account.is_active)

  useEffect(() => {
    if (!accounts.data) return
    if (accountId !== null && !active.some((account) => account.id === accountId)) {
      setAccountId(null)
    }
  }, [accountId, accounts.data, active, setAccountId])

  return (
    <label className="top-scope-picker">
      <span className="sr-only">Cloud account scope</span>
      <Cloud size={13} aria-hidden />
      <select
        value={accountId ?? ''}
        onFocus={() => accounts.refetch()}
        onChange={(event) => setAccountId(event.target.value ? Number(event.target.value) : null)}
      >
        <option value="">All accounts</option>
        {active.map((account) => (
          <option key={account.id} value={account.id}>
            {account.name || account.account_identifier}
          </option>
        ))}
      </select>
    </label>
  )
}

function PersonaPicker() {
  const { persona, setPersona } = usePersona()
  const profile = PERSONAS[persona]

  return (
    <label className="top-persona-picker" title={profile.focus}>
      <span className="top-avatar" aria-hidden>{profile.role.slice(0, 2).toUpperCase()}</span>
      <span className="sr-only">Choose workspace role</span>
      <select value={persona} onChange={(event) => setPersona(event.target.value as Persona)}>
        {(Object.entries(PERSONAS) as Array<[Persona, (typeof PERSONAS)[Persona]]>).map(([key, item]) => (
          <option key={key} value={key}>{item.label}</option>
        ))}
      </select>
    </label>
  )
}

const PRIMARY_NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/inventory', label: 'Inventory' },
  { to: '/findings', label: 'Issues' },
  { to: '/attack-paths', label: 'Explorer' },
  { to: '/compliance', label: 'Compliance' },
  { to: '/settings', label: 'Projects' },
  { to: '/accounts', label: 'Onboard' },
] as const

const RAIL_NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/accounts', label: 'Cloud accounts', icon: Cloud },
  { to: '/inventory', label: 'Inventory', icon: Boxes },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/attack-paths', label: 'Attack paths', icon: Route },
  { to: '/identity', label: 'Identity', icon: KeyRound },
  { to: '/data', label: 'Data security', icon: Database },
  { to: '/architecture', label: 'Architecture', icon: Network },
  { to: '/sensors', label: 'Runtime sensors', icon: Activity },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Cpu },
  { to: '/iac', label: 'Infrastructure as code', icon: FileCode2 },
  { to: '/compliance', label: 'Compliance', icon: BadgeCheck },
] as const

const CONTEXT_NAV = [
  {
    match: /^\/$/,
    links: [
      { to: '/', label: 'Security posture', end: true },
      { to: '/findings', label: 'Material risk' },
      { to: '/attack-paths', label: 'Attack paths' },
      { to: '/data', label: 'Data exposure' },
    ],
  },
  {
    match: /^\/(inventory|identity|data|architecture)/,
    links: [
      { to: '/inventory', label: 'Assets' },
      { to: '/identity', label: 'Identities' },
      { to: '/data', label: 'Data stores' },
      { to: '/architecture', label: 'Security graph' },
    ],
  },
  {
    match: /^\/(findings|attack-paths)/,
    links: [
      { to: '/findings', label: 'Material-risk issues' },
      { to: '/attack-paths', label: 'Linked attack paths' },
      { to: '/identity', label: 'Identity reachability' },
    ],
  },
  {
    match: /^\/(sensors|threats|vulnerabilities|cve-database)/,
    links: [
      { to: '/sensors', label: 'Sensors' },
      { to: '/threats', label: 'Runtime threats' },
      { to: '/vulnerabilities', label: 'Vulnerabilities' },
      { to: '/cve-database', label: 'CVE database' },
    ],
  },
  {
    match: /^\/(iac|compliance|settings)/,
    links: [
      { to: '/compliance', label: 'Framework controls' },
      { to: '/iac', label: 'IaC assurance' },
      { to: '/settings', label: 'Policy settings' },
    ],
  },
  {
    match: /^\/accounts/,
    links: [
      { to: '/accounts', label: '1 · Connect AWS' },
      { to: '/inventory', label: '2 · Review inventory' },
      { to: '/findings', label: '3 · Triage findings' },
      { to: '/attack-paths', label: '4 · Explore paths' },
    ],
  },
] as const

function ContextTabs() {
  const { pathname } = useLocation()
  const context = CONTEXT_NAV.find((item) => item.match.test(pathname))
  if (!context) return null

  return (
    <nav className="context-tabs" aria-label="Current workspace views">
      {context.links.map((item) => (
        <NavLink
          key={`${item.to}-${item.label}`}
          to={item.to}
          end={'end' in item ? item.end : false}
          className={({ isActive }) => `context-tab${isActive ? ' active' : ''}`}
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  )
}

export function Shell() {
  const { theme, toggle } = useTheme()
  const reduceMotion = useReducedMotion()
  const realtime = useRealtime()

  return (
    <div className="shell">
      <motion.header
        className="app-topbar"
        initial={reduceMotion ? false : { opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.16, ease: 'easeOut' }}
      >
        <NavLink to="/" className="top-brand" aria-label="Odineyes dashboard">
          <span className="top-brand-mark" aria-hidden>
            <svg viewBox="0 0 32 32" fill="none">
              <path d="M8 17 14 11 18 15 25 8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="25" cy="8" r="2.5" fill="currentColor" />
            </svg>
          </span>
          <span>
            <strong>Odineyes</strong>
            <small>Cloud security posture</small>
          </span>
        </NavLink>

        <nav className="top-primary-nav" aria-label="Primary navigation">
          {PRIMARY_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={'end' in item ? item.end : false}
              className={({ isActive }) => `top-primary-link${isActive ? ' active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="top-actions">
          <AccountScopePicker />
          <NavLink className="top-icon-button" to="/settings" aria-label="Settings" title="Settings">
            <Settings size={15} />
          </NavLink>
          <button
            className="top-icon-button"
            type="button"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
          >
            {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
          </button>
          <PersonaPicker />
        </div>
      </motion.header>

      <motion.aside
        className="icon-rail"
        initial={reduceMotion ? false : { opacity: 0, x: -8 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.18, ease: 'easeOut' }}
      >
        <nav className="rail-nav" aria-label="All product areas">
          {RAIL_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={'end' in item ? item.end : false}
              className={({ isActive }) => `rail-link${isActive ? ' active' : ''}`}
              aria-label={item.label}
              title={item.label}
            >
              <item.icon aria-hidden />
              <span className="rail-tooltip" role="tooltip">{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="rail-footer">
          <NavLink to="/settings" className="rail-link" aria-label="Policy settings" title="Policy settings">
            <SlidersHorizontal aria-hidden />
            <span className="rail-tooltip" role="tooltip">Policy settings</span>
          </NavLink>
          <div className={`rail-status realtime-${realtime.status}`} title={`Realtime stream: ${realtime.status}`} aria-label={`Realtime stream ${realtime.status}`}>
            <span />
          </div>
        </div>
      </motion.aside>

      <div className="shell-content">
        <ContextTabs />
        <nav className="mobile-nav" aria-label="Mobile primary navigation">
          {PRIMARY_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={'end' in item ? item.end : false}
              className={({ isActive }) => `mobile-nav-item${isActive ? ' active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <main className="main">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
