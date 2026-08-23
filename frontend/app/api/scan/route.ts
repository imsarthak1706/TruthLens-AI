import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  const backendUrl = process.env.TRUTHLENSAI_BACKEND_URL || 'http://127.0.0.1:8000'

  try {
    const body = await request.json()
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
    })
    const responseBody = await response.text()

    return new NextResponse(responseBody, {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('content-type') || 'application/json' },
    })
  } catch {
    return NextResponse.json({ error: 'Scan backend could not be reached.' }, { status: 502 })
  }
}
