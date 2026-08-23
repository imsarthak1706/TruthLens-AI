'use client'

import { useRef, useState } from 'react'
import { Send, Sparkles, Upload, X } from 'lucide-react'
import { imageScanApi, scanApi, severityClass, severityLabel, type ScanAnalysisResponse, type Severity } from '@/lib/truthlens-data'

type RealScanAnalyzerProps = { setSelected: (id: string | null) => void }

function Badge({ severity }: { severity: Severity }) {
  return <span className={`badge ${severityClass(severity)}`}><span className="dot" />{severityLabel(severity)}</span>
}

function valueText(value: unknown) {
  if (value === undefined || value === null || value === '') return 'No data returned.'
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}

function severityValue(value: unknown): Severity {
  const normalized = String(value ?? '').toLowerCase()
  return normalized === 'critical' || normalized === 'high' || normalized === 'suspicious' || normalized === 'safe' ? normalized : 'suspicious'
}

export default function RealScanAnalyzer({ setSelected }: RealScanAnalyzerProps) {
  const fileInput = useRef<HTMLInputElement>(null)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanAnalysisResponse | null>(null)

  const run = async () => {
    setLoading(true)
    setError(null)
    try {
      setResult(await scanApi.scan(input))
    } catch (requestError) {
      setResult(null)
      setError(requestError instanceof Error ? requestError.message : 'Scan analysis could not be completed.')
    } finally {
      setLoading(false)
    }
  }

  const uploadImage = async (file: File) => {
    setLoading(true)
    setError(null)
    try {
      setResult(await imageScanApi.scan(file))
    } catch (requestError) {
      setResult(null)
      setError(requestError instanceof Error ? requestError.message : 'Image scan could not be completed.')
    } finally {
      setLoading(false)
    }
  }

  const severity = severityValue(result?.severity)
  const confidence = result?.confidence === undefined ? 'No data returned.' : typeof result.confidence === 'number' ? `${result.confidence}%` : result.confidence

  return <div className="page-content"><div className="section-heading"><div><div className="eyebrow">ANALYSIS WORKSPACE</div><h2>Scan analyzer</h2></div></div><div className="analyzer-layout"><div className="panel composer"><div className="panel-top"><div><h3>Submit content for analysis</h3><p>Paste a message, URL, or upload an image for OCR analysis.</p></div><span className="live-pill"><span className="status-dot" /> Engine online</span></div><textarea value={input} onChange={event => setInput(event.target.value)} placeholder="Paste suspicious content here..." /><div className="composer-footer"><input ref={fileInput} type="file" accept="image/png,image/jpeg" hidden onChange={event => { const file = event.target.files?.[0]; if (file) void uploadImage(file); event.currentTarget.value = '' }} /><button className="upload-button" onClick={() => fileInput.current?.click()} disabled={loading}><Upload size={15} /> Upload image</button><button className="primary-button" onClick={run} disabled={loading || !input.trim()}>{loading ? 'Analyzing...' : 'Run analysis'}<Send size={15} /></button></div><div className="supported">Supported inputs <span>TEXT</span><span>URL</span><span>PNG</span><span>JPG</span></div>{error && <div className="incident-state error-state"><span>{error}</span></div>}</div><div className="panel result-panel">{result ? <><div className="result-head"><div><div className="eyebrow">LATEST RESULT / {result.scan_id || 'UNASSIGNED'}</div><h3>{valueText(result.threat_type)}</h3></div><Badge severity={severity} /></div><div className="risk-score"><div className="score-ring"><strong>{result.risk_score ?? '—'}</strong><span>/ 100</span></div><div><div className="metric-label">Risk score</div><p>{valueText(result.recommendation)}</p></div></div><div className="result-facts"><div><span>Threat type</span><b>{valueText(result.threat_type)}</b></div><div><span>Confidence</span><b>{confidence}</b></div><div><span>Timestamp</span><b>{valueText(result.timestamp)}</b></div></div><div className="detail-json"><div><span>Extracted text</span><pre>{valueText(result.extracted_text)}</pre></div><div><span>Evidence</span><pre>{valueText(result.evidence)}</pre></div><div><span>AI analysis</span><pre>{valueText(result.ai_analysis)}</pre></div><div><span>VirusTotal</span><pre>{valueText(result.virustotal)}</pre></div><div><span>Extracted entities</span><pre>{valueText(result.extracted_entities)}</pre></div></div><button className="secondary-button" onClick={() => { setResult(null); setSelected(null) }}>Clear result <X size={14} /></button></> : <div className="empty-result"><div className="empty-icon"><Sparkles size={22} /></div><h3>{error ? 'Analysis unavailable' : 'Analysis results appear here'}</h3><p>{error || 'Run a scan to see risk scoring, threat classification, evidence, and AI reasoning.'}</p></div>}</div></div></div>
}
