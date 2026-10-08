export function relTime(iso: string | null): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const s = Math.floor((Date.now() - t) / 1000)
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`
  return new Date(iso).toLocaleDateString()
}

/** Countdown to an ISO instant, or null once it has passed. A link that has
 *  quietly expired should read as expired, not as live. */
export function timeUntil(iso: string): string | null {
  const ms = new Date(iso).getTime() - Date.now()
  if (!Number.isFinite(ms) || ms <= 0) return null
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

export function shortHash(hash: string | null | undefined): string {
  return hash ? hash.slice(0, 12) : '—'
}

export function num(n: number): string {
  return n.toLocaleString('en-US')
}

/** "aws.ec2.security_group" → "security group" */
export function shortType(assetType: string): string {
  const tail = assetType.split('.').slice(2).join('.') || assetType
  return tail.replace(/_/g, ' ')
}

/** Last path-ish segment of an ARN / resource id, for compact display. */
export function shortId(resourceId: string): string {
  const seg = resourceId.split(/[/:]/).filter(Boolean)
  return seg[seg.length - 1] ?? resourceId
}
