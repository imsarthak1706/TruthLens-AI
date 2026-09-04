export type Severity = 'critical' | 'high' | 'suspicious' | 'safe'
export type ThreatType = 'Malicious Link' | 'Credential Phishing' | 'Payment Scam' | 'Identity / KYC Scam' | 'Possible Impersonation Scam' | 'Social Engineering' | 'Malware' | 'No Strong Threat Detected'
export type Scan = { id: string; source: string; preview: string; type: ThreatType; severity: Severity; score: number; confidence: number; created: string; status: string }
export type Incident = { id: string; scanId: string; title: ThreatType; channel: string; severity: Severity; score: number; confidence: string; status: string; created: string; entities: number }
export type IncidentEvidence = { original_text?: string; extracted_text?: string; extracted_entities?: unknown; evidence?: unknown; ai_analysis?: unknown; virustotal?: unknown; recommendation?: unknown; risk_score?: number; severity?: string; confidence?: string | number; threat_type?: string; timestamp?: string; platform?: string; status?: string; urls?: unknown[]; upi_ids?: unknown[]; phone_numbers?: unknown[]; emails?: unknown[]; [key: string]: unknown }
export type IncidentRecord = Incident & { chatId: string | null; evidence: IncidentEvidence; originalText: string; extractedText: string | null; extractedEntities: unknown; evidenceDetails: unknown; aiAnalysis: unknown; virustotal: unknown; recommendation: unknown }
export type ScanAnalysisResponse = { scan_id?: string; risk_score?: number; severity?: string; confidence?: string | number; threat_type?: string; evidence?: unknown; ai_analysis?: unknown; virustotal?: unknown; recommendation?: unknown; extracted_entities?: unknown; extracted_text?: string; timestamp?: string }

// Real runtime empty collections (mock records removed)
export const scans: Scan[] = []
export const incidents: Incident[] = []
export const riskTrend: { day: string; critical: number; high: number; safe: number }[] = []
export const threatTypes: { name: string; value: number }[] = []

export const severityLabel = (s: Severity) => ({ critical: 'Critical', high: 'High', suspicious: 'Suspicious', safe: 'Safe' }[s] || 'Unknown')
export const severityClass = (s: Severity) => ({ critical: 'severity-critical', high: 'severity-high', suspicious: 'severity-suspicious', safe: 'severity-safe' }[s] || 'severity-safe')

export const scanApi = {
  scan: async (input: string) => {
    const { api } = await import('@/lib/api');
    return api.scanText(input);
  }
}

export const imageScanApi = {
  scan: async (image: File) => {
    const { api } = await import('@/lib/api');
    return api.scanImage(image);
  }
}

export type PageKey = 'Overview' | 'Scan Analyzer' | 'Incident Center' | 'Scan History' | 'Community Intelligence' | 'Analytics' | 'Settings'
export const navItems: { label: PageKey; icon: string }[] = [
  { label: 'Overview', icon: 'grid' },
  { label: 'Scan Analyzer', icon: 'scan' },
  { label: 'Incident Center', icon: 'alert' },
  { label: 'Scan History', icon: 'history' },
  { label: 'Community Intelligence', icon: 'shield' },
  { label: 'Analytics', icon: 'barChart' },
  { label: 'Settings', icon: 'settings' }
]

// Official reproducible 120-sample benchmark evaluation
export const BENCHMARK_EVALUATION = {
  title: '120-Sample Text Benchmark Evaluation',
  provenance: 'Evaluated against benchmark/text_benchmark.csv using the production FastAPI /api/scan detection pipeline (threshold = 25).',
  sampleCount: 120,
  overall: {
    accuracy: 95.0,
    precision: 100.0,
    recall: 90.0,
    f1Score: 94.74,
    tp: 54,
    tn: 60,
    fp: 0,
    fn: 6,
    totalScam: 60,
    totalBenign: 60,
  },
  byLanguage: {
    english: { samples: 40, accuracy: 100.0, precision: 100.0, recall: 100.0, f1Score: 100.0, tp: 20, tn: 20, fp: 0, fn: 0 },
    hindi: { samples: 40, accuracy: 87.5, precision: 100.0, recall: 75.0, f1Score: 85.71, tp: 15, tn: 20, fp: 0, fn: 5 },
    hinglish: { samples: 40, accuracy: 97.5, precision: 100.0, recall: 95.0, f1Score: 97.44, tp: 19, tn: 20, fp: 0, fn: 1 },
  },
  limitations: [
    { id: 'HI-S-002', lang: 'Hindi', expected: 'SCAM', predicted: 'SAFE', score: 15, text: 'प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा...' },
    { id: 'HI-S-004', lang: 'Hindi', expected: 'SCAM', predicted: 'SAFE', score: 15, text: 'आपका SBI खाता ब्लॉक हो गया है। तुरंत KYC अपडेट करें...' },
    { id: 'HI-S-009', lang: 'Hindi', expected: 'SCAM', predicted: 'SAFE', score: 20, text: 'बिजली बिल बकाया है। तुरंत भुगतान करें अन्यथा आपूर्ति बंद...' },
    { id: 'HI-S-015', lang: 'Hindi', expected: 'SCAM', predicted: 'SAFE', score: 15, text: 'आपके फोन में वायरस है। सुरक्षा के लिए यह सपोर्ट ऐप इंस्टॉल करें...' },
    { id: 'HI-S-018', lang: 'Hindi', expected: 'SCAM', predicted: 'SAFE', score: 20, text: 'सरकारी योजना के तहत ₹50000 की सहायता राशि प्राप्त करने के लिए...' },
    { id: 'HING-S-015', lang: 'Hinglish', expected: 'SCAM', predicted: 'SAFE', score: 15, text: 'Aapke device me security alert hai. Remote support tool download karein...' },
  ]
}

