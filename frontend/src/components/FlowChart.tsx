import { motion } from 'motion/react'
import {
  Crown,
  Database,
  Globe,
  HardDrive,
  KeyRound,
  Server,
  Shield,
  Users,
} from 'lucide-react'
import { Fragment } from 'react'

import type { PathHop, Severity } from '../types'

const KIND_ICON: Record<PathHop['kind'], typeof Globe> = {
  internet: Globe,
  external: Users,
  compute: Server,
  role: KeyRound,
  bucket: HardDrive,
  database: Database,
  security_group: Shield,
}

const KIND_LABEL: Record<PathHop['kind'], string> = {
  internet: 'Internet',
  external: 'External principal',
  compute: 'Compute',
  role: 'IAM role',
  bucket: 'S3 bucket',
  database: 'Database',
  security_group: 'Security group',
}

// The relationship a connector represents, inferred from the kinds it joins.
function edgeVerb(from: PathHop['kind'], to: PathHop['kind']): string {
  if (from === 'internet') return 'exposed to'
  if (from === 'external') return 'can assume'
  if (from === 'compute' && to === 'role') return 'assumes'
  if (from === 'role' && (to === 'bucket' || to === 'database')) return 'can access'
  if (to === 'role') return 'can assume'
  return 'reaches'
}

const THREAT_KINDS = new Set<PathHop['kind']>(['internet', 'external'])

function Connector({ verb, sev, i }: { verb: string; sev: Severity; i: number }) {
  return (
    <div className="flow-edge" aria-hidden>
      <span className="flow-verb">{verb}</span>
      <div className="flow-line-wrap">
        <motion.div
          className={`flow-line sev-${sev}`}
          initial={{ scaleX: 0 }}
          animate={{ scaleX: 1 }}
          transition={{ delay: 0.12 + i * 0.14, duration: 0.32, ease: 'easeOut' }}
        />
        <motion.span
          className={`flow-arrow sev-${sev}`}
          initial={{ opacity: 0, x: -4 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.12 + i * 0.14 + 0.28, duration: 0.18 }}
        >
          ▸
        </motion.span>
      </div>
    </div>
  )
}

export function FlowChart({ path, severity }: { path: PathHop[]; severity: Severity }) {
  return (
    <div className="flow" role="list" aria-label="attack path">
      {path.map((h, i) => {
        const Icon = KIND_ICON[h.kind] ?? Server
        const isEntry = i === 0
        const isTarget = i === path.length - 1 && path.length > 1
        const threat = THREAT_KINDS.has(h.kind)
        return (
          <Fragment key={`${h.id}-${i}`}>
            {i > 0 ? (
              <Connector verb={edgeVerb(path[i - 1].kind, h.kind)} sev={severity} i={i} />
            ) : null}
            <motion.div
              role="listitem"
              className={`flow-node${threat ? ' threat' : ''}${isTarget ? ' target' : ''}`}
              initial={{ opacity: 0, y: 10, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ delay: i * 0.14, type: 'spring', stiffness: 460, damping: 30 }}
              title={h.id}
            >
              <div className={`flow-icon${isEntry ? ` ring sev-${severity}` : ''}`}>
                <Icon size={15} />
                {isTarget ? <Crown className="flow-crown" size={11} /> : null}
              </div>
              <div className="flow-meta">
                <span className="flow-kind">{KIND_LABEL[h.kind] ?? h.kind}</span>
                <span className="flow-name" title={h.name}>
                  {h.name}
                </span>
              </div>
              {isEntry ? <span className="flow-tag">entry</span> : null}
              {isTarget ? <span className="flow-tag target">target</span> : null}
            </motion.div>
          </Fragment>
        )
      })}
    </div>
  )
}
