// Real asset geography — world map fed exclusively by GET /api/inventory/geo
// (live group-by over persisted assets). When the inventory is empty the map
// renders with zero markers and an honest empty state; nothing is simulated.

import { useState } from 'react'

import { ComposableMap, Geographies, Geography as RSMGeography, Marker } from 'react-simple-maps'

import { Card, PageHead, StatCard, StateView } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useAccountScope } from '../lib/accountScope'
import { api } from '../lib/api'
import { num } from '../lib/format'
import type { GeoRegion } from '../types'

const GEO_URL = '/geo/countries-110m.json'

// Cloud region → geographic coordinates (lng/lat) for map projection. This is
// presentation-only geography: provider documentation publishes these region
// locations; the asset counts stay live data.
const REGION_COORDS: Record<string, [number, number]> = {
  // AWS
  'us-east-1': [-79.0, 38.0], 'us-east-2': [-82.6, 40.2], 'us-west-1': [-119.4, 36.8],
  'us-west-2': [-119.9, 46.0], 'ca-central-1': [-75.7, 45.4], 'ca-west-1': [-123.1, 49.3],
  'sa-east-1': [-46.6, -23.5], 'eu-west-1': [-6.3, 53.0], 'eu-west-2': [-0.1, 51.5],
  'eu-west-3': [2.35, 48.85], 'eu-central-1': [8.68, 50.11], 'eu-central-2': [8.54, 47.37],
  'eu-north-1': [17.9, 59.3], 'eu-south-1': [12.5, 41.9], 'eu-south-2': [-3.7, 40.4],
  'ap-south-1': [72.88, 19.08], 'ap-south-2': [77.2, 28.6], 'ap-southeast-1': [103.85, 1.29],
  'ap-southeast-2': [151.2, -33.87], 'ap-southeast-3': [106.85, -6.2], 'ap-southeast-4': [144.96, -37.81],
  'ap-southeast-5': [101.69, 3.14], 'ap-southeast-7': [100.5, 13.75], 'ap-northeast-1': [139.69, 35.69],
  'ap-northeast-2': [126.98, 37.57], 'ap-northeast-3': [135.5, 34.69], 'ap-east-1': [114.1, 22.3],
  'ap-east-2': [113.9, 22.6], 'me-south-1': [50.58, 26.07], 'me-central-1': [46.68, 24.71],
  'me-central-2': [55.27, 25.2], 'af-south-1': [18.42, -33.92], 'il-central-1': [34.78, 32.07],
  'mx-central-1': [-99.13, 19.43], 'cn-north-1': [116.4, 39.9], 'cn-northwest-1': [106.2, 38.5],
  // Azure (regions arrive as display names from inventory, e.g. "eastus")
  eastus: [-79.8, 37.4], eastus2: [-78.7, 38.4], westus: [-119.8, 37.2], westus2: [-119.5, 47.3],
  westus3: [-119.2, 46.2], centralus: [-93.8, 41.6], northcentralus: [-87.6, 41.9],
  southcentralus: [-98.5, 29.4], westcentralus: [-112.3, 43.5], canadacentral: [-79.4, 43.7],
  canadaeast: [-75.7, 45.5], brazilsouth: [-46.6, -23.5], northeurope: [-6.2, 53.2],
  westeurope: [4.9, 52.4], uksouth: [-1.9, 51.5], ukwest: [-3.1, 53.4], francecentral: [2.4, 46.6],
  germanywestcentral: [8.7, 50.1], norwayeast: [10.7, 59.9], swedencentral: [17.6, 60.1],
  switzerlandnorth: [8.5, 47.4], polandcentral: [19.9, 52.2], spaincentral: [-3.7, 40.4],
  italynorth: [9.2, 45.5], eastasia: [114.2, 22.3], southeastasia: [103.8, 1.35],
  japaneast: [139.7, 35.7], japanwest: [135.5, 34.7], koreacentral: [127.0, 37.7],
  koreasouth: [127.8, 35.2], centralindia: [78.6, 17.4], southindia: [77.6, 12.9],
  westindia: [72.9, 19.1], uaenorth: [55.3, 25.2], israelcentral: [34.8, 32.1],
  qatarcentral: [51.5, 25.3], southafricanorth: [28.0, -26.2], australiacentral: [149.1, -35.3],
  australiacentral2: [149.1, -35.4], australiaeast: [151.2, -33.9],
  australiasoutheast: [147.0, -37.8], mexicocentral: [-99.1, 19.4],
  // Google Cloud (region slugs, e.g. us-central1)
  'us-central1': [-93.3, 39.0], 'us-east1': [-79.0, 38.5], 'us-east4': [-77.5, 39.0],
  'us-east5': [-79.5, 36.9], 'us-south1': [-97.0, 29.8], 'us-west1': [-122.0, 45.6],
  'us-west2': [-118.4, 34.0], 'us-west3': [-115.1, 36.2], 'us-west4': [-119.4, 36.1],
  'northamerica-northeast1': [-75.7, 45.5], 'northamerica-northeast2': [-123.1, 49.3],
  'northamerica-south1': [-99.1, 19.4], 'southamerica-east1': [-46.6, -23.5],
  'southamerica-west1': [-70.7, -33.4], 'europe-west1': [4.0, 50.6], 'europe-west2': [-0.1, 51.5],
  'europe-west3': [8.68, 50.11], 'europe-west4': [4.9, 52.4], 'europe-west6': [8.54, 47.37],
  'europe-west8': [9.2, 45.5], 'europe-west9': [2.35, 48.85], 'europe-west10': [-3.7, 40.4],
  'europe-west12': [9.2, 45.4], 'europe-north1': [17.9, 60.5], 'europe-southwest1': [-3.7, 40.4],
  'europe-central2': [19.9, 52.2], 'asia-south1': [72.88, 19.08], 'asia-south2': [77.2, 28.6],
  'asia-southeast1': [103.85, 1.29], 'asia-southeast2': [106.85, -6.2],
  'asia-northeast1': [139.69, 35.69], 'asia-northeast2': [135.5, 34.69],
  'asia-northeast3': [126.98, 37.57], 'asia-east1': [121.5, 25.0], 'asia-east2': [114.1, 22.3],
  'australia-southeast1': [151.2, -33.87], 'australia-southeast2': [147.0, -37.8],
  'me-west1': [34.78, 32.07], 'me-central1': [46.68, 24.71], 'me-central2': [55.27, 25.2],
  'africa-south1': [18.42, -33.92],
}

const MAP_LAND = { fill: 'var(--map-land, #1b2230)', stroke: 'var(--border, #2a3342)', strokeWidth: 0.4 }

function regionLabel(region: string): string {
  return region === 'global' ? 'Global (account-wide)' : region
}

// Marker radius from asset count (sqrt keeps small counts visible, large
// counts from overwhelming the map). Counts are real; the scale is presentational.
function markerRadius(total: number, max: number): number {
  if (total <= 0 || max <= 0) return 0
  return 4 + Math.sqrt(total / max) * 16
}

function TipRow({ label, value, dotClass }: { label: string; value: number; dotClass: string }) {
  return (
    <span className="sev-badge">
      <span className={`dot ${dotClass}`} />
      {label} <span className="num">{num(value)}</span>
    </span>
  )
}

export function Geography() {
  const { accountId, provider } = useAccountScope()
  const [hovered, setHovered] = useState<GeoRegion | null>(null)
  const geo = useApi(() => api.geo({ provider, accountId }), [provider, accountId])

  const regions: GeoRegion[] = geo.data?.regions ?? []
  const located = regions.filter((r) => REGION_COORDS[r.region])
  const unmapped = regions.filter((r) => !REGION_COORDS[r.region])
  const maxTotal = regions.reduce((m, r) => Math.max(m, r.total), 0)
  const totals = regions.reduce(
    (acc, r) => ({
      compute: acc.compute + r.compute,
      storage: acc.storage + r.storage,
      other: acc.other + r.other,
    }),
    { compute: 0, storage: 0, other: 0 },
  )

  const activeProvider = geo.data?.providers[0]

  return (
    <div className="page">
      <PageHead
        crumb="inventory / geography"
        title="Asset geography"
        sub="Where scanned assets live, straight from the inventory store. Hover a marker for the compute / storage breakdown; switch clouds to isolate each provider's footprint."
      />

      <div className="grid-stats" style={{ marginBottom: 'var(--sp-3)' }}>
        <StatCard i={1} label="Assets in scope" value={geo.data ? num(geo.data.total_assets) : null} sub={(activeProvider || provider).toUpperCase()} />
        <StatCard i={2} label="Compute" value={geo.data ? num(totals.compute) : null} sub="instances, containers, serverless" />
        <StatCard i={3} label="Storage" value={geo.data ? num(totals.storage) : null} sub="buckets, volumes, databases" />
        <StatCard i={4} label="Regions with assets" value={geo.data ? num(regions.length) : null} sub={`${located.length} mapped to the globe`} />
      </div>

      <Card title="Global footprint" i={5}>
        <StateView
          loading={geo.loading}
          error={geo.error}
          empty={!!geo.data && geo.data.total_assets === 0}
          emptyHint="No assets in this scope yet. Register a cloud account, run a scan, and the map fills from real inventory."
        >
          <div className="geo-map-wrap">
            <ComposableMap
              width={980}
              height={500}
              projection="geoEqualEarth"
              projectionConfig={{ scale: 160 }}
              style={{ width: '100%', height: 'auto' }}
            >
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map((g) => (
                    <RSMGeography key={g.rKey} geography={g} {...MAP_LAND} />
                  ))
                }
              </Geographies>
              {located.map((r) => {
                const coords = REGION_COORDS[r.region]
                return (
                  <Marker
                    key={r.region}
                    coordinates={coords}
                    onMouseEnter={() => setHovered(r)}
                    onMouseLeave={() => setHovered((cur) => (cur?.region === r.region ? null : cur))}
                  >
                    <circle
                      r={markerRadius(r.total, maxTotal)}
                      fill="var(--accent, #4f8cff)"
                      fillOpacity={0.28}
                      stroke="var(--accent, #4f8cff)"
                      strokeWidth={1.4}
                      style={{ cursor: 'pointer' }}
                    />
                    <circle r={2.2} fill="var(--accent, #4f8cff)" />
                  </Marker>
                )
              })}
            </ComposableMap>

            {hovered ? (
              <div className="geo-tooltip" role="status">
                <strong>{regionLabel(hovered.region)}</strong>
                <span className="geo-tip-total num">{num(hovered.total)} assets</span>
                <div className="geo-tip-rows">
                  <TipRow label="Compute" value={hovered.compute} dotClass="sev-high" />
                  <TipRow label="Storage" value={hovered.storage} dotClass="sev-low" />
                  <TipRow label="Other" value={hovered.other} dotClass="hollow" />
                </div>
              </div>
            ) : null}
          </div>

          {unmapped.length > 0 ? (
            <div className="geo-unmapped">
              <span className="sev-badge"><span className="dot hollow" />No published location</span>
              {unmapped.map((r) => (
                <span key={r.region} className="sev-badge" title={JSON.stringify(r.by_category)}>
                  {regionLabel(r.region)} <span className="num">{num(r.total)}</span>
                </span>
              ))}
            </div>
          ) : null}

          <div className="geo-legend">
            <TipRow label="Compute" value={totals.compute} dotClass="sev-high" />
            <TipRow label="Storage" value={totals.storage} dotClass="sev-low" />
            <TipRow label="Other" value={totals.other} dotClass="hollow" />
            <span className="geo-legend-note">Marker size = asset count · hover for compute / storage split</span>
          </div>
        </StateView>
      </Card>

      <div className="grid-2" style={{ marginTop: 'var(--sp-3)' }}>
        <Card title="Assets by region" i={6} bodyPad={false}>
          <StateView
            loading={geo.loading}
            error={geo.error}
            empty={!!geo.data && regions.length === 0}
            emptyHint="No regional data in this scope."
          >
            <div className="geo-region-list">
              {regions.map((r) => (
                <div key={r.region} className="geo-region-row">
                  <span className="geo-region-name">{regionLabel(r.region)}</span>
                  <span className="geo-region-bar" aria-hidden>
                    <span style={{ width: `${maxTotal ? (r.total / maxTotal) * 100 : 0}%` }} />
                  </span>
                  <span className="num geo-region-count">{num(r.total)}</span>
                </div>
              ))}
            </div>
          </StateView>
        </Card>

        <Card title="Region × category" i={7} bodyPad={false}>
          <StateView
            loading={geo.loading}
            error={geo.error}
            empty={!!geo.data && regions.length === 0}
            emptyHint="No regional data in this scope."
          >
            <div className="geo-matrix">
              {regions.map((r) => (
                <div key={r.region} className="geo-matrix-row">
                  <span className="geo-region-name">{regionLabel(r.region)}</span>
                  <span className="geo-matrix-cells">
                    {Object.entries(r.by_category)
                      .sort((a, b) => b[1] - a[1])
                      .map(([cat, count]) => (
                        <span key={cat} className="sev-badge" title={`${cat}: ${count}`}>
                          {cat} <span className="num">{num(count)}</span>
                        </span>
                      ))}
                  </span>
                </div>
              ))}
            </div>
          </StateView>
        </Card>
      </div>
    </div>
  )
}
