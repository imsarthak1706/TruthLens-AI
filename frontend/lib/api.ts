/**
 * TruthLensAI Central Frontend API Client
 *
 * Connects directly to the production FastAPI backend.
 * Base URL is resolved dynamically from NEXT_PUBLIC_API_BASE_URL.
 * No Supabase credentials or Telegram PII are stored or exposed client-side.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  "https://truthlens-ai-1-7unv.onrender.com";

export interface OverviewTelemetry {
  total_scans: number;
  threats_detected: number;
  critical_threats: number;
  community_reports_indexed: number;
  severity_distribution: {
    critical: number;
    high: number;
    suspicious: number;
    safe: number;
    total: number;
  };
  threat_activity: {
    time: string;
    threats: number;
    clean: number;
  }[];
}

export interface BackendScanItem {
  id: string;
  timestamp: string;
  platform: string;
  target_input: string;
  modality: string;
  risk_score: number;
  severity: "critical" | "high" | "suspicious" | "safe";
  verdict: string;
  threat_type: string;
  status: string;
}

export interface BackendScansResponse {
  items: BackendScanItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface BackendIncidentItem {
  id: string;
  scan_id: string;
  title: string;
  channel: string;
  severity: "critical" | "high" | "suspicious" | "safe";
  risk_score: number;
  confidence: string;
  status: string;
  created_at: string;
  summary: string;
}

export interface BackendIncidentsResponse {
  items: BackendIncidentItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface CommunityFeedItem {
  indicator: string;
  indicator_type: string;
  report_count: number;
  risk_tier: "critical" | "high" | "suspicious" | "safe";
  first_seen: string | null;
  last_seen: string | null;
}

export interface CommunityFeedResponse {
  items: CommunityFeedItem[];
  total: number;
}

export interface ForensicScanDetail {
  scan_id: string;
  input?: string;
  risk_score: number;
  severity: "critical" | "high" | "suspicious" | "safe";
  confidence: string | number;
  threat_type: string;
  evidence?: { signal: string; points: number }[] | string[];
  recommendation?: string;
  ai_analysis?: Record<string, any>;
  virustotal?: Record<string, any>;
  input_type?: string;
  platform?: string;
  timestamp?: string;
  transcript?: string;
  transcription?: Record<string, any>;
  extracted_text?: string;
  image_forensics?: Record<string, any>;
  audio_forensics?: Record<string, any>;
  video_metadata?: Record<string, any>;
  frames?: any;
}

class TruthLensApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE_URL.replace(/\/$/, "");
  }

  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options?.headers || {}),
      },
      cache: "no-store",
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(`API error ${response.status} on ${endpoint}: ${errorText || response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  async getOverviewTelemetry(): Promise<OverviewTelemetry> {
    return this.request<OverviewTelemetry>("/api/telemetry/overview");
  }

  async getScans(limit = 10, offset = 0): Promise<BackendScansResponse> {
    return this.request<BackendScansResponse>(`/api/scans?limit=${limit}&offset=${offset}`);
  }

  async getIncidents(limit = 10, offset = 0): Promise<BackendIncidentsResponse> {
    return this.request<BackendIncidentsResponse>(`/api/incidents?limit=${limit}&offset=${offset}`);
  }

  async getCommunityFeed(limit = 50): Promise<CommunityFeedResponse> {
    return this.request<CommunityFeedResponse>(`/api/community/feed?limit=${limit}`);
  }

  async getScan(scanId: string): Promise<ForensicScanDetail> {
    return this.request<ForensicScanDetail>(`/api/scan/${encodeURIComponent(scanId)}`);
  }

  async scanText(input: string, platform = "web"): Promise<ForensicScanDetail> {
    return this.request<ForensicScanDetail>("/api/scan", {
      method: "POST",
      body: JSON.stringify({ input, platform }),
    });
  }

  async scanImage(file: File, platform = "web"): Promise<ForensicScanDetail> {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("platform", platform);

    const url = `${this.baseUrl}/api/scan/image`;
    const response = await fetch(url, {
      method: "POST",
      body: formData,
      cache: "no-store",
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(`Image scan failed (${response.status}): ${errorText || response.statusText}`);
    }

    return response.json() as Promise<ForensicScanDetail>;
  }
}

export const api = new TruthLensApiClient();
