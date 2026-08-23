import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  const backendUrl = process.env.TRUTHLENSAI_BACKEND_URL || 'http://127.0.0.1:8000'

  try {
    const incoming = await request.formData()
    const image = incoming.get('file')

    if (!(image instanceof File)) {
      return NextResponse.json({ error: 'An image file is required.' }, { status: 400 })
    }

    const formData = new FormData()
    formData.append('file', image, image.name)
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/scan/image`, {
      method: 'POST',
      body: formData,
      cache: 'no-store',
    })
    const responseBody = await response.text()

    return new NextResponse(responseBody, {
      status: response.status,
      headers: { 'Content-Type': response.headers.get('content-type') || 'application/json' },
    })
  } catch {
    return NextResponse.json({ error: 'Image scan backend could not be reached.' }, { status: 502 })
  }
}
