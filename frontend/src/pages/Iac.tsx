import { FileCode2, Play } from 'lucide-react'
import { useState } from 'react'

import { Card, PageHead, SevBadge, StateView } from '../components/ui'
import { api, ApiError } from '../lib/api'
import type { IacScanResult } from '../types'

const SAMPLE = `{
  "resource": {
    "aws_s3_bucket": { "logs": { "acl": "public-read" } },
    "aws_security_group": {
      "ssh": { "ingress": [{ "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"] }] }
    }
  }
}`

export function Iac() {
  const [content, setContent] = useState('')
  const [result, setResult] = useState<IacScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function scan() {
    setLoading(true)
    setError(null)
    try {
      const r = await api.iacScan(content)
      setResult(r)
    } catch (e) {
      setError(e instanceof ApiError ? (e.detail ?? e.message) : String(e))
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page">
      <PageHead
        crumb="iac"
        title="IaC security"
        sub="Pre-deploy misconfiguration scan of Terraform plan JSON or CloudFormation (JSON/YAML)."
        actions={
          <button className="btn primary" onClick={scan} disabled={loading || !content.trim()}>
            <Play size={14} style={loading ? { animation: 'spin 0.7s linear infinite' } : undefined} />
            {loading ? 'Scanning…' : 'Scan template'}
          </button>
        }
      />

      <Card i={1}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span className="label" style={{ color: 'var(--text-2)' }}>
            <FileCode2 size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />
            template source
          </span>
          <button className="btn" style={{ fontSize: 11 }} onClick={() => setContent(SAMPLE)}>
            load sample
          </button>
        </div>
        <textarea
          className="iac-input mono"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste `terraform show -json` output or a CloudFormation template…"
          spellCheck={false}
          rows={12}
        />
      </Card>

      <div style={{ marginTop: 12 }}>
        <Card
          title={result ? `Findings · ${result.total} (${result.format ?? 'unknown'}, ${result.resources_scanned} resources)` : 'Findings'}
          i={2}
          bodyPad={false}
        >
          <StateView
            loading={loading}
            error={error ? ({ message: 'IaC scan failed', detail: error } as never) : null}
            empty={!!result && result.findings.length === 0}
            emptyHint={result ? 'No misconfigurations detected in this template. ✅' : 'Paste a template and scan to see findings.'}
          >
            {result && result.findings.length > 0 ? (
              <div>
                {result.findings.map((f, idx) => (
                  <div key={`${f.check_id}-${idx}`} className={`frow sev-${f.severity}`}>
                    <span className="pill" style={{ flexShrink: 0 }}>{f.check_id}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="t">{f.title}</div>
                      <div className="r">{f.resource_type} · {f.resource}</div>
                    </div>
                    <span style={{ width: 86, flexShrink: 0, textAlign: 'right' }}>
                      <SevBadge sev={f.severity} />
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
          </StateView>
        </Card>
      </div>
    </div>
  )
}
