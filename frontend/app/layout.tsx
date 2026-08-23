import type { Metadata, Viewport } from 'next'
import './globals.css'

export const metadata: Metadata = { title: 'TruthLensAI — AI Scam Intelligence', description: 'AI-powered scam intelligence and incident response command center.', generator: 'TruthLensAI' }
export const viewport: Viewport = { colorScheme: 'dark', themeColor: '#080d14' }

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en" className="bg-background"><body className="antialiased">{children}</body></html> }
