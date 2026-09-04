'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Clock3,
  Copy,
  ExternalLink,
  FileSearch,
  Grid2X2,
  History,
  Lock,
  Menu,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X
} from 'lucide-react'
import {
  api,
  type BackendIncidentItem,
  type BackendScanItem,
  type CommunityFeedItem,
  type ForensicScanDetail,
  type OverviewTelemetry
} from '@/lib/api'
import {
  BENCHMARK_EVALUATION,
  navItems,
  severityClass,
  severityLabel,
  type PageKey,
  type Severity
} from '@/lib/truthlens-data'
import RealScanAnalyzer from '@/components/real-scan-analyzer'

const iconMap: Record<string, any> = {
  grid: Grid2X2,
  scan: Radar,
  alert: AlertTriangle,
  history: History,
  shield: ShieldAlert,
  barChart: BarChart3,
  settings: Lock
}

function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge ${severityClass(severity)}`}>
      <span className="dot" />
      {severityLabel(severity)}
    </span>
  )
}

function SectionTitle({ eyebrow, title, action, onAction }: { eyebrow: string; title: string; action?: string; onAction?: () => void }) {
  return (
    <div className="section-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
      </div>
      {action && (
        <button className="ghost-button" onClick={onAction}>
          {action}
          <ChevronRight size={14} />
        </button>
      )}
    </div>
  )
}

function Metric({
  label,
  value,
  change,
  tone = 'blue',
  icon: Icon
}: {
  label: string
  value: string
  change?: string
  tone?: string
  icon: any
}) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${tone}`}>
        <Icon size={17} />
      </div>
      <div>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        {change && <div className="metric-change">{change}</div>}
      </div>
    </div>
  )
}

function LoadingState({ message }: { message: string }) {
  return (
    <div className="panel incident-state">
      <span className="status-dot" />
      {message}
    </div>
  )
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="panel incident-state error-state">
      <AlertTriangle size={17} />
      <span>{message}</span>
    </div>
  )
}

// -------------------------------------------------------------
// 1. OVERVIEW VIEW
// -------------------------------------------------------------
function Overview({ setPage, setSelected }: { setPage: (p: PageKey) => void; setSelected: (id: string) => void }) {
  const [telemetry, setTelemetry] = useState<OverviewTelemetry | null>(null)
  const [recentScans, setRecentScans] = useState<BackendScanItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    Promise.all([
      api.getOverviewTelemetry(),
      api.getScans(5, 0)
    ])
      .then(([telemetryData, scansData]) => {
        if (!active) return
        setTelemetry(telemetryData)
        setRecentScans(scansData.items || [])
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof Error ? err.message : 'Telemetry data unavailable.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  const severityPieData = useMemo(() => {
    if (!telemetry?.severity_distribution) return []
    const dist = telemetry.severity_distribution
    return [
      { name: 'Critical', value: dist.critical || 0, color: 'var(--critical)' },
      { name: 'High', value: dist.high || 0, color: 'var(--high)' },
      { name: 'Suspicious', value: dist.suspicious || 0, color: 'var(--suspicious)' },
      { name: 'Safe', value: dist.safe || 0, color: 'var(--safe)' }
    ].filter((item) => item.value > 0)
  }, [telemetry])

  const totalThreats = (telemetry?.threats_detected ?? 0)

  return (
    <div className="page-content">
      <div className="welcome-row">
        <div>
          <div className="eyebrow">PLATFORM COMMAND CENTER</div>
          <h1>Security Telemetry Overview</h1>
          <p>Real-time security telemetry from the connected FastAPI detection pipeline.</p>
        </div>
        <button className="primary-button" onClick={() => setPage('Scan Analyzer')}>
          <Radar size={16} /> New scan
        </button>
      </div>

      {loading && <LoadingState message="Loading live security telemetry from backend..." />}
      {error && <ErrorState message={`Failed to load live telemetry: ${error}`} />}

      {!loading && (
        <>
          <div className="metric-grid">
            <Metric
              label="Total Scans Processed"
              value={telemetry ? telemetry.total_scans.toLocaleString() : '—'}
              change="Platform-wide exact count"
              icon={FileSearch}
            />
            <Metric
              label="Threats Detected"
              value={telemetry ? telemetry.threats_detected.toLocaleString() : '—'}
              change="Risk score >= 40"
              tone="orange"
              icon={AlertTriangle}
            />
            <Metric
              label="Critical Threats"
              value={telemetry ? telemetry.critical_threats.toLocaleString() : '—'}
              change="Risk >= 80 or confirmed scam"
              tone="red"
              icon={CircleDot}
            />
            <Metric
              label="Community Indicators"
              value={telemetry ? telemetry.community_reports_indexed.toLocaleString() : '—'}
              change="Reputation intelligence feed"
              tone="green"
              icon={ShieldCheck}
            />
          </div>

          <div className="chart-grid">
            {/* Real Threat Activity Timeline */}
            <div className="panel chart-panel">
              <SectionTitle eyebrow="ACTIVITY TIMELINE" title="Daily Threat & Clean Scans" />
              <div className="legend">
                <span>
                  <i className="legend-dot critical" />
                  Threats
                </span>
                <span>
                  <i className="legend-dot safe" />
                  Clean
                </span>
              </div>
              <div className="chart">
                {telemetry && telemetry.threat_activity && telemetry.threat_activity.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={telemetry.threat_activity}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                      <XAxis dataKey="time" stroke="var(--muted)" tickLine={false} axisLine={false} />
                      <YAxis stroke="var(--muted)" tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8 }} />
                      <Area type="monotone" dataKey="clean" stackId="1" stroke="var(--safe)" fill="var(--safe)" fillOpacity={0.12} />
                      <Area type="monotone" dataKey="threats" stackId="1" stroke="var(--critical)" fill="var(--critical)" fillOpacity={0.25} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="panel incident-state">No historical activity records available yet.</div>
                )}
              </div>
            </div>

            {/* Real Severity Distribution */}
            <div className="panel threat-panel">
              <SectionTitle eyebrow="CLASSIFICATION" title="Severity Distribution" />
              <div className="donut-wrap">
                {severityPieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={severityPieData} dataKey="value" innerRadius={58} outerRadius={80} paddingAngle={3}>
                        {severityPieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="panel incident-state">No distribution data</div>
                )}
                <div className="donut-center">
                  <strong>{totalThreats}</strong>
                  <span>threats</span>
                </div>
              </div>
              <div className="threat-list">
                {severityPieData.map((t) => (
                  <div className="threat-item" key={t.name}>
                    <span>
                      <i className="legend-dot" style={{ background: t.color }} />
                      {t.name}
                    </span>
                    <b>{t.value}</b>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <SectionTitle eyebrow="LIVE QUEUE" title="Recent Production Scans" action="View all scans" onAction={() => setPage('Scan History')} />
          <div className="panel table-panel">
            <div className="table-head">
              <span>SCAN ID</span>
              <span>PAYLOAD PREVIEW</span>
              <span>MODALITY</span>
              <span>RISK</span>
              <span>SEVERITY</span>
              <span>STATUS</span>
              <span />
            </div>
            {recentScans.length > 0 ? (
              recentScans.map((s) => (
                <button
                  className="table-row"
                  key={s.id}
                  onClick={() => {
                    setSelected(s.id)
                    setPage('Scan Analyzer')
                  }}
                >
                  <div className="scan-cell">
                    <span className="scan-id">{s.id}</span>
                  </div>
                  <span className="scan-preview truncate max-w-xs">{s.target_input || 'Payload payload'}</span>
                  <span className="type-cell uppercase font-mono text-xs">{s.modality}</span>
                  <span className="risk-number">{s.risk_score}/100</span>
                  <span>
                    <Badge severity={s.severity} />
                  </span>
                  <span className="status-cell">
                    <span className="status-dot" />
                    {s.status}
                  </span>
                  <ChevronRight size={16} className="row-arrow" />
                </button>
              ))
            ) : (
              <div className="panel incident-state">No scans have been processed yet.</div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

// -------------------------------------------------------------
// 2. SCAN HISTORY VIEW
// -------------------------------------------------------------
function ScanHistory({ setSelected, setPage }: { setSelected: (id: string) => void; setPage: (p: PageKey) => void }) {
  const [scansList, setScansList] = useState<BackendScanItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPageNumber] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const pageSize = 10

  useEffect(() => {
    let active = true
    setLoading(true)
    api.getScans(pageSize, (page - 1) * pageSize)
      .then((res) => {
        if (!active) return
        setScansList(res.items || [])
        setTotal(res.total || 0)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof Error ? err.message : 'Could not load scans.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [page])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="page-content">
      <div className="welcome-row">
        <div>
          <div className="eyebrow">AUDIT TRAIL & ARCHIVE</div>
          <h1>Scan History</h1>
          <p>Real-time records of all text, image, audio, and video detections.</p>
        </div>
      </div>

      {loading && <LoadingState message="Loading scan records from database..." />}
      {error && <ErrorState message={error} />}

      {!loading && !error && (
        <div className="panel table-panel">
          <div className="table-head">
            <span>ID</span>
            <span>TIME</span>
            <span>PLATFORM</span>
            <span>INPUT / TARGET</span>
            <span>MODALITY</span>
            <span>RISK</span>
            <span>SEVERITY</span>
            <span>STATUS</span>
            <span />
          </div>
          {scansList.length > 0 ? (
            scansList.map((s) => (
              <button
                className="table-row"
                key={s.id}
                onClick={() => {
                  setSelected(s.id)
                  setPage('Scan Analyzer')
                }}
              >
                <span className="scan-id">{s.id}</span>
                <span className="text-xs text-muted font-mono">{s.timestamp ? String(s.timestamp).slice(0, 19).replace('T', ' ') : 'Recently'}</span>
                <span className="type-cell font-bold">{s.platform}</span>
                <span className="scan-preview truncate max-w-xs">{s.target_input}</span>
                <span className="uppercase text-xs font-mono">{s.modality}</span>
                <span className="risk-number">{s.risk_score}/100</span>
                <span>
                  <Badge severity={s.severity} />
                </span>
                <span className="status-cell">
                  <span className="status-dot" />
                  {s.status}
                </span>
                <ChevronRight size={16} className="row-arrow" />
              </button>
            ))
          ) : (
            <div className="panel incident-state">No scans found in database.</div>
          )}

          {/* Pagination Controls */}
          <div className="composer-footer flex items-center justify-between p-4 border-t border-border">
            <span className="text-xs text-muted">
              Showing page {page} of {totalPages} ({total} total scans)
            </span>
            <div className="flex gap-2">
              <button
                className="secondary-button"
                disabled={page <= 1}
                onClick={() => setPageNumber((p) => Math.max(1, p - 1))}
              >
                <ChevronLeft size={14} /> Prev
              </button>
              <button
                className="secondary-button"
                disabled={page >= totalPages}
                onClick={() => setPageNumber((p) => Math.min(totalPages, p + 1))}
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// -------------------------------------------------------------
// 3. INCIDENT CENTER VIEW
// -------------------------------------------------------------
function Incidents({ setPage, setSelected }: { setPage: (p: PageKey) => void; setSelected: (id: string) => void }) {
  const [incidentsList, setIncidentsList] = useState<BackendIncidentItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPageNumber] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const pageSize = 10

  useEffect(() => {
    let active = true
    setLoading(true)
    api.getIncidents(pageSize, (page - 1) * pageSize)
      .then((res) => {
        if (!active) return
        setIncidentsList(res.items || [])
        setTotal(res.total || 0)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof Error ? err.message : 'Failed to load incidents.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [page])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const criticalCount = incidentsList.filter((i) => i.severity === 'critical').length
  const investigatingCount = incidentsList.filter((i) => i.status === 'investigating').length

  return (
    <div className="page-content">
      <div className="welcome-row">
        <div>
          <div className="eyebrow">RESPONSE WORKFLOW</div>
          <h1>Incident Center</h1>
          <p>Review, track, and triage high-confidence verified security incidents.</p>
        </div>
      </div>

      <div className="metric-grid compact">
        <Metric label="Total Incidents" value={total.toLocaleString()} change={`${criticalCount} critical in current batch`} tone="red" icon={AlertTriangle} />
        <Metric label="Investigating" value={investigatingCount.toLocaleString()} change="Active response" tone="orange" icon={Clock3} />
        <Metric label="Telemetry Link" value="Direct" change="Connected to Supabase records" tone="green" icon={CheckCircle2} />
      </div>

      <SectionTitle eyebrow="INCIDENT QUEUE" title="Indexed Incident Reports" />

      {loading && <LoadingState message="Loading incident reports from database..." />}
      {error && <ErrorState message={error} />}

      {!loading && !error && (
        <div className="panel table-panel incident-table">
          <div className="table-head incident-head">
            <span>INCIDENT ID</span>
            <span>THREAT / CHANNEL</span>
            <span>SEVERITY</span>
            <span>RISK</span>
            <span>CONFIDENCE</span>
            <span>STATUS / CREATED</span>
            <span />
          </div>
          {incidentsList.length > 0 ? (
            incidentsList.map((i) => (
              <button
                className="table-row"
                key={i.id}
                onClick={() => {
                  setSelected(i.scan_id || i.id)
                  setPage('Scan Analyzer')
                }}
              >
                <div className="scan-cell">
                  <span className="scan-id">{i.id}</span>
                  <span className="scan-preview truncate max-w-xs">{i.summary}</span>
                </div>
                <span className="type-cell">
                  <b>{i.title}</b>
                  <small>{i.channel}</small>
                </span>
                <span>
                  <Badge severity={i.severity} />
                </span>
                <span className="risk-number">{i.risk_score}/100</span>
                <span className="confidence">{i.confidence}</span>
                <span className="status-cell">
                  <span>
                    <span className="status-dot" />
                    {i.status}
                  </span>
                  <small>{i.created_at ? String(i.created_at).slice(0, 10) : 'Recently'}</small>
                </span>
                <ChevronRight size={16} className="row-arrow" />
              </button>
            ))
          ) : (
            <div className="panel incident-state">No incidents have been recorded.</div>
          )}

          {/* Pagination Controls */}
          <div className="composer-footer flex items-center justify-between p-4 border-t border-border">
            <span className="text-xs text-muted">
              Page {page} of {totalPages} ({total} incidents)
            </span>
            <div className="flex gap-2">
              <button
                className="secondary-button"
                disabled={page <= 1}
                onClick={() => setPageNumber((p) => Math.max(1, p - 1))}
              >
                <ChevronLeft size={14} /> Prev
              </button>
              <button
                className="secondary-button"
                disabled={page >= totalPages}
                onClick={() => setPageNumber((p) => Math.min(totalPages, p + 1))}
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// -------------------------------------------------------------
// 4. COMMUNITY INTELLIGENCE VIEW
// -------------------------------------------------------------
function CommunityIntelligence() {
  const [feed, setFeed] = useState<CommunityFeedItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api.getCommunityFeed(50)
      .then((res) => {
        if (!active) return
        setFeed(res.items || [])
        setTotal(res.total || (res.items || []).length)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof Error ? err.message : 'Could not load community intelligence feed.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  return (
    <div className="page-content">
      <div className="welcome-row">
        <div>
          <div className="eyebrow">COLLECTIVE DEFENSE</div>
          <h1>Community Threat Intelligence</h1>
          <p>Real-time reputation data from community reported indicators across all channels.</p>
        </div>
      </div>

      {loading && <LoadingState message="Fetching community indicators from database..." />}
      {error && <ErrorState message={error} />}

      {!loading && !error && (
        <div className="panel table-panel">
          <div className="table-head">
            <span>INDICATOR</span>
            <span>TYPE</span>
            <span>REPORTS</span>
            <span>RISK TIER</span>
            <span>FIRST SEEN</span>
            <span>LAST SEEN</span>
          </div>
          {feed.length > 0 ? (
            feed.map((item, idx) => (
              <div className="table-row" key={`${item.indicator}-${idx}`}>
                <span className="font-mono text-sm text-primary truncate max-w-sm" title={item.indicator}>
                  {item.indicator}
                </span>
                <span className="uppercase text-xs font-mono text-muted">{item.indicator_type}</span>
                <span className="font-bold">{item.report_count} reports</span>
                <span>
                  <Badge severity={item.risk_tier} />
                </span>
                <span className="text-xs text-muted font-mono">{item.first_seen ? String(item.first_seen).slice(0, 10) : 'N/A'}</span>
                <span className="text-xs text-muted font-mono">{item.last_seen ? String(item.last_seen).slice(0, 10) : 'N/A'}</span>
              </div>
            ))
          ) : (
            <div className="panel incident-state">No indicators currently recorded in community reputation database.</div>
          )}
        </div>
      )}
    </div>
  )
}

// -------------------------------------------------------------
// 5. ANALYTICS VIEW (VERIFIED 120-SAMPLE BENCHMARK)
// -------------------------------------------------------------
function Analytics() {
  const b = BENCHMARK_EVALUATION

  return (
    <div className="page-content">
      <div className="welcome-row">
        <div>
          <div className="eyebrow">MODEL EVALUATION BENCHMARK</div>
          <h1>Detection Performance Analytics</h1>
          <p>{b.provenance}</p>
        </div>
        <span className="badge severity-high">
          <span className="dot" /> Benchmark Evaluation (Not Live Telemetry)
        </span>
      </div>

      <div className="metric-grid">
        <Metric label="Benchmark Accuracy" value={`${b.overall.accuracy.toFixed(2)}%`} change="114 / 120 samples" tone="green" icon={CheckCircle2} />
        <Metric label="Precision" value={`${b.overall.precision.toFixed(2)}%`} change="0 False Positives on benign" tone="blue" icon={ShieldCheck} />
        <Metric label="Recall" value={`${b.overall.recall.toFixed(2)}%`} change="54 / 60 scam threats caught" tone="orange" icon={Radar} />
        <Metric label="F1 Score" value={`${b.overall.f1Score.toFixed(2)}%`} change="Harmonic mean of P & R" tone="blue" icon={BarChart3} />
      </div>

      {/* Language Breakdown Cards */}
      <SectionTitle eyebrow="MULTILINGUAL EVALUATION" title="Performance by Language" />
      <div className="chart-grid">
        {/* English */}
        <div className="panel">
          <div className="flex justify-between items-center mb-3">
            <h3>English (40 samples)</h3>
            <Badge severity="safe" />
          </div>
          <div className="incident-detail-facts">
            <span><small>Accuracy</small><b>{b.byLanguage.english.accuracy.toFixed(2)}%</b></span>
            <span><small>Precision</small><b>{b.byLanguage.english.precision.toFixed(2)}%</b></span>
            <span><small>Recall</small><b>{b.byLanguage.english.recall.toFixed(2)}%</b></span>
            <span><small>F1 Score</small><b>{b.byLanguage.english.f1Score.toFixed(2)}%</b></span>
          </div>
        </div>

        {/* Hindi */}
        <div className="panel">
          <div className="flex justify-between items-center mb-3">
            <h3>Hindi (40 samples)</h3>
            <Badge severity="suspicious" />
          </div>
          <div className="incident-detail-facts">
            <span><small>Accuracy</small><b>{b.byLanguage.hindi.accuracy.toFixed(2)}%</b></span>
            <span><small>Precision</small><b>{b.byLanguage.hindi.precision.toFixed(2)}%</b></span>
            <span><small>Recall</small><b>{b.byLanguage.hindi.recall.toFixed(2)}%</b></span>
            <span><small>F1 Score</small><b>{b.byLanguage.hindi.f1Score.toFixed(2)}%</b></span>
          </div>
        </div>

        {/* Hinglish */}
        <div className="panel">
          <div className="flex justify-between items-center mb-3">
            <h3>Hinglish (40 samples)</h3>
            <Badge severity="safe" />
          </div>
          <div className="incident-detail-facts">
            <span><small>Accuracy</small><b>{b.byLanguage.hinglish.accuracy.toFixed(2)}%</b></span>
            <span><small>Precision</small><b>{b.byLanguage.hinglish.precision.toFixed(2)}%</b></span>
            <span><small>Recall</small><b>{b.byLanguage.hinglish.recall.toFixed(2)}%</b></span>
            <span><small>F1 Score</small><b>{b.byLanguage.hinglish.f1Score.toFixed(2)}%</b></span>
          </div>
        </div>
      </div>

      {/* Honest Error Analysis Section */}
      <SectionTitle eyebrow="LIMITATIONS & ERROR ANALYSIS" title="The 6 Missed Scam Samples (False Negatives)" />
      <div className="panel table-panel">
        <p className="p-4 text-xs text-muted border-b border-border">
          Under the production threshold of 25, exactly 6 subtle social-engineering scams scored 15–20 points and were classified as safe when AI analysis was unavailable. All 60 benign samples were correctly classified (0 False Positives).
        </p>
        <div className="table-head">
          <span>SAMPLE ID</span>
          <span>LANG</span>
          <span>EXPECTED</span>
          <span>PREDICTED</span>
          <span>SCORE</span>
          <span>PREVIEW</span>
        </div>
        {b.limitations.map((lim) => (
          <div className="table-row" key={lim.id}>
            <span className="scan-id">{lim.id}</span>
            <span className="text-xs font-mono">{lim.lang}</span>
            <span className="text-xs text-red-400 font-bold">{lim.expected}</span>
            <span className="text-xs text-amber-400 font-bold">{lim.predicted}</span>
            <span className="risk-number">{lim.score}/100</span>
            <span className="scan-preview truncate max-w-md">{lim.text}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// -------------------------------------------------------------
// 6. FORENSIC REPORT DETAIL LOADER
// -------------------------------------------------------------
function ForensicDetailLoader({ id, setPage }: { id: string; setPage: (p: PageKey) => void }) {
  const [scan, setScan] = useState<ForensicScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api.getScan(id)
      .then((data) => {
        if (!active) return
        setScan(data)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof Error ? err.message : `Scan ${id} could not be loaded.`)
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [id])

  if (loading) {
    return (
      <div className="page-content">
        <LoadingState message={`Fetching forensic telemetry for scan ${id}...`} />
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="page-content">
        <button className="back-button" onClick={() => setPage('Scan History')}>
          ← Back to Scan History
        </button>
        <ErrorState message={error || `Scan ${id} was not found or has expired.`} />
      </div>
    )
  }

  const formatValue = (value: unknown) => (typeof value === 'string' ? value : JSON.stringify(value, null, 2))

  return (
    <div className="page-content">
      <button className="back-button" onClick={() => setPage('Scan History')}>
        ← Back to Scan History
      </button>
      <div className="detail-head">
        <div>
          <div className="eyebrow">FORENSIC REPORT / {scan.scan_id}</div>
          <h1>{scan.threat_type || 'Forensic Analysis Report'}</h1>
          <p>
            {scan.platform || 'Platform'} · {scan.timestamp || 'Recorded'}
          </p>
        </div>
        <Badge severity={scan.severity} />
      </div>

      <div className="detail-grid">
        <div className="panel verdict-panel">
          <div className="verdict-score">
            <div className="score-ring large">
              <strong>{scan.risk_score}</strong>
              <span>risk</span>
            </div>
            <div>
              <div className="incident-detail-facts">
                <span>
                  <small>Risk score</small>
                  <b>{scan.risk_score}/100</b>
                </span>
                <span>
                  <small>Severity</small>
                  <b>{severityLabel(scan.severity)}</b>
                </span>
                <span>
                  <small>Confidence</small>
                  <b>{String(scan.confidence)}</b>
                </span>
                <span>
                  <small>Threat Type</small>
                  <b>{scan.threat_type}</b>
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="panel">
          <SectionTitle eyebrow="RECOMMENDED ACTION" title="Advisory & Guidance" />
          <div className="evidence-copy">
            <p>{scan.recommendation || 'No specific recommendation provided.'}</p>
          </div>
        </div>

        <div className="panel">
          <SectionTitle eyebrow="DETECTED SIGNALS" title="Evidence Signals" />
          <div className="detail-json">
            <div>
              <span>Signals</span>
              <pre>{formatValue(scan.evidence)}</pre>
            </div>
            {scan.extracted_text && (
              <div>
                <span>Extracted OCR / Speech Text</span>
                <pre>{scan.extracted_text}</pre>
              </div>
            )}
            {scan.virustotal && (
              <div>
                <span>VirusTotal Corroboration</span>
                <pre>{formatValue(scan.virustotal)}</pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// -------------------------------------------------------------
// 7. SETTINGS VIEW (PROTECTED / RESTRICTED)
// -------------------------------------------------------------
function SettingsView() {
  return (
    <div className="page-content">
      <SectionTitle eyebrow="SECURITY ACCESS CONTROL" title="System Settings" />
      <div className="panel placeholder-panel text-center py-12">
        <div className="empty-icon mx-auto mb-4 text-amber-400">
          <Lock size={32} />
        </div>
        <h3>Access Restricted</h3>
        <p className="max-w-md mx-auto text-muted text-sm mt-2">
          System configuration and environment credentials are managed exclusively by environment administrators. Public modification of detector parameters or API endpoints is disabled.
        </p>
      </div>
    </div>
  )
}

// -------------------------------------------------------------
// 8. MAIN DASHBOARD SHELL
// -------------------------------------------------------------
export default function TruthLensDashboard() {
  const [page, setPage] = useState<PageKey>('Overview')
  const [selected, setSelected] = useState<string | null>(null)
  const current = useMemo(() => page, [page])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={21} />
          </div>
          <div>
            <strong>TruthLensAI</strong>
            <span>AI SCAM INTELLIGENCE</span>
          </div>
        </div>

        <nav>
          {navItems.map((item) => {
            const Icon = iconMap[item.icon] || Grid2X2
            return (
              <button
                className={current === item.label ? 'active' : ''}
                key={item.label}
                onClick={() => {
                  setPage(item.label)
                  setSelected(null)
                }}
              >
                <Icon size={17} />
                {item.label}
              </button>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-head">
              <span className="status-dot" />
              Engine Online
            </div>
            <div className="system-bar">
              <span />
            </div>
            <small>Connected to FastAPI backend</small>
          </div>
          <div className="profile">
            <div className="avatar">AK</div>
            <div>
              <b>Security Analyst</b>
              <span>Production SOC</span>
            </div>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="mobile-menu">
            <Menu size={18} />
          </button>
          <div className="crumb">
            <span>TruthLensAI</span>
            <ChevronRight size={14} />
            <b>{current}</b>
          </div>
          <div className="top-actions">
            <div className="search">
              <Search size={15} />
              <input placeholder="Search scans, incidents..." />
            </div>
            <button className="icon-button" title="Alerts">
              <Bell size={17} />
              <i />
            </button>
            <button className="icon-button" title="Engine Status">
              <Activity size={17} />
            </button>
          </div>
        </header>

        {selected ? (
          <ForensicDetailLoader id={selected} setPage={setPage} />
        ) : page === 'Overview' ? (
          <Overview setPage={setPage} setSelected={setSelected} />
        ) : page === 'Scan Analyzer' ? (
          <RealScanAnalyzer setSelected={setSelected} />
        ) : page === 'Incident Center' ? (
          <Incidents setPage={setPage} setSelected={setSelected} />
        ) : page === 'Scan History' ? (
          <ScanHistory setSelected={setSelected} setPage={setPage} />
        ) : page === 'Community Intelligence' ? (
          <CommunityIntelligence />
        ) : page === 'Analytics' ? (
          <Analytics />
        ) : (
          <SettingsView />
        )}
      </main>
    </div>
  )
}

