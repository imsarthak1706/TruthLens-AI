import { NextResponse } from 'next/server'
import type { IncidentRecord, Severity, ThreatType } from '@/lib/truthlens-data'

export async function GET() {
  const backendUrl =
    process.env.NEXT_PUBLIC_API_BASE_URL ||
    process.env.TRUTHLENSAI_BACKEND_URL ||
    'https://truthlens-ai-1-7unv.onrender.com'

  try {
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/incidents?limit=50`, {
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!response.ok) {
      return NextResponse.json({ error: 'Incident data could not be loaded.' }, { status: 502 })
    }

    const data = await response.json()
    const items = Array.isArray(data.items) ? data.items : []

    const mapped: IncidentRecord[] = items.map((inc: any) => ({
      id: String(inc.id),
      scanId: String(inc.scan_id || inc.id),
      chatId: null, // Never expose chat_id or Telegram user identities
      title: (inc.title || 'Suspicious Activity') as ThreatType,
      channel: String(inc.channel || 'Telegram'),
      severity: (inc.severity || 'suspicious') as Severity,
      score: typeof inc.risk_score === 'number' ? inc.risk_score : 0,
      confidence: String(inc.confidence || 'Medium'),
      status: String(inc.status || 'investigating'),
      created: String(inc.created_at || 'Recently'),
      entities: 0,
      evidence: {},
      originalText: String(inc.summary || ''),
      extractedText: null,
      extractedEntities: [],
      evidenceDetails: [],
      aiAnalysis: null,
      virustotal: null,
      recommendation: null,
    }))

    return NextResponse.json(mapped)
  } catch {
    return NextResponse.json({ error: 'Incident data could not be loaded.' }, { status: 502 })
  }
}

