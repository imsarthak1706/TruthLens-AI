import { NextResponse } from 'next/server'
import type { IncidentEvidence, IncidentRecord, Severity, ThreatType } from '@/lib/truthlens-data'

type IncidentReportRow = {
  id: string
  scan_id: string
  chat_id: string | null
  evidence_json: IncidentEvidence | string | null
  created_at: string
}

const severities: Severity[] = ['critical', 'high', 'suspicious', 'safe']
const threatTypes: ThreatType[] = ['Malicious Link', 'Credential Phishing', 'Payment Scam', 'Identity / KYC Scam', 'Possible Impersonation Scam', 'Social Engineering', 'Malware', 'No Strong Threat Detected']

function parseEvidence(value: IncidentReportRow['evidence_json']): IncidentEvidence {
  if (!value) return {}
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as IncidentEvidence
    } catch {
      return {}
    }
  }
  return value
}

function asSeverity(value: unknown): Severity {
  const normalized = String(value ?? '').toLowerCase() as Severity
  return severities.includes(normalized) ? normalized : 'suspicious'
}

function asThreatType(value: unknown): ThreatType {
  return threatTypes.includes(value as ThreatType) ? value as ThreatType : 'Social Engineering'
}

function entityCount(evidence: IncidentEvidence) {
  return ['urls', 'upi_ids', 'phone_numbers', 'emails'].reduce((count, key) => {
    const values = evidence[key]
    return count + (Array.isArray(values) ? values.length : 0)
  }, 0)
}

function mapIncident(row: IncidentReportRow): IncidentRecord {
  const evidence = parseEvidence(row.evidence_json)
  const confidence = evidence.confidence ?? 'Unknown'
  const originalText = typeof evidence.original_text === 'string' ? evidence.original_text : ''
  const extractedText = typeof evidence.extracted_text === 'string' ? evidence.extracted_text : null

  return {
    id: row.id,
    scanId: row.scan_id,
    chatId: row.chat_id,
    title: asThreatType(evidence.threat_type),
    channel: typeof evidence.platform === 'string' ? evidence.platform : 'Unknown',
    severity: asSeverity(evidence.severity),
    score: typeof evidence.risk_score === 'number' ? evidence.risk_score : 0,
    confidence: typeof confidence === 'number' ? `${confidence}%` : String(confidence),
    status: typeof evidence.status === 'string' && evidence.status.trim() ? evidence.status : 'Prepared',
    created: evidence.timestamp ? String(evidence.timestamp) : row.created_at,
    entities: entityCount(evidence),
    evidence,
    originalText,
    extractedText,
    extractedEntities: evidence.extracted_entities ?? [],
    evidenceDetails: evidence.evidence ?? [],
    aiAnalysis: evidence.ai_analysis ?? null,
    virustotal: evidence.virustotal ?? null,
    recommendation: evidence.recommendation ?? null,
  }
}

export async function GET() {
  const url = process.env.SUPABASE_URL
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (!url || !serviceRoleKey) {
    return NextResponse.json({ error: 'Incident data is not configured.' }, { status: 500 })
  }

  try {
    const response = await fetch(`${url.replace(/\/$/, '')}/rest/v1/incident_reports?select=id,scan_id,chat_id,evidence_json,created_at&order=created_at.desc`, {
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
      },
      cache: 'no-store',
    })

    if (!response.ok) {
      return NextResponse.json({ error: 'Incident data could not be loaded.' }, { status: 502 })
    }

    const rows = await response.json() as IncidentReportRow[]
    return NextResponse.json(rows.map(mapIncident))
  } catch {
    return NextResponse.json({ error: 'Incident data could not be loaded.' }, { status: 502 })
  }
}
