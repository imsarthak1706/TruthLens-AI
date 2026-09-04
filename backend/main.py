from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from uuid import uuid4
from collections import OrderedDict
import tempfile
import os
import subprocess
from pathlib import Path
import time
import threading
import asyncio
import json
import httpx
import urllib.parse

# -----------------------------------------
# BOUNDED IN-MEMORY SCAN CACHE
# -----------------------------------------
SCAN_CACHE_MAX_SIZE = 1000
_scan_cache = OrderedDict()
_scan_cache_lock = threading.Lock()

def _save_scan_result(result: dict):
    if not isinstance(result, dict):
        return
    scan_id = result.get("scan_id")
    if scan_id:
        with _scan_cache_lock:
            _scan_cache[str(scan_id)] = result
            while len(_scan_cache) > SCAN_CACHE_MAX_SIZE:
                _scan_cache.popitem(last=False)

def _get_scan_result(scan_id: str) -> dict | None:
    if not scan_id:
        return None
    with _scan_cache_lock:
        return _scan_cache.get(str(scan_id))


# -----------------------------------------
# SUPABASE SECURE CONFIGURATION & HELPERS
# -----------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()


def _get_supabase_headers() -> dict:
    if not SUPABASE_SERVICE_ROLE_KEY:
        return {}
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }


async def _supabase_exact_count(endpoint: str, query_filter: str = "") -> int:
    """Return an exact PostgREST row count without returning row data."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return 0

    url = f"{SUPABASE_URL}/rest/v1/{endpoint}?limit=0"
    if query_filter:
        url = f"{url}&{query_filter}"

    headers = {
        **_get_supabase_headers(),
        "Prefer": "count=exact",
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.head(url, headers=headers)
            content_range = response.headers.get("content-range", "")
            if "/" not in content_range:
                return 0
            total = content_range.rsplit("/", 1)[-1].strip()
            return int(total) if total.isdigit() else 0
    except Exception as error:
        print(f"[Supabase] Count error on {endpoint}: {error}")
        return 0


def _sanitize_scan_message(msg: str | None) -> str:
    """Strip Telegram envelopes/identity and return a clean public preview."""
    if not msg:
        return "Forensic Scan"

    msg = str(msg).strip()

    if msg.startswith("{") and msg.endswith("}"):
        try:
            parsed = json.loads(msg)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("text"), str):
                    return parsed["text"].strip()[:120]
                message = parsed.get("message")
                if isinstance(message, dict) and isinstance(message.get("text"), str):
                    return message["text"].strip()[:120]
        except Exception:
            pass

    if "TRUTHLENSAI" in msg.upper() or "FORENSIC" in msg.upper():
        lines = [
            line.strip()
            for line in msg.splitlines()
            if line.strip() and not line.strip().startswith(("---", "==="))
        ]
        for line in lines:
            if "http://" in line or "https://" in line or line.lower().startswith("text:"):
                return line[:120]
        return lines[0][:120] if lines else "Forensic Analysis"

    return msg[:120]


def _derive_severity(
    risk_score: int | float | None,
    verdict: str | None,
) -> str:
    score = float(risk_score) if isinstance(risk_score, (int, float)) else 0.0
    verdict_upper = (verdict or "").upper()

    if score >= 80 or verdict_upper == "SCAM":
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40 or verdict_upper == "SUSPICIOUS":
        return "suspicious"
    return "safe"


async def _persist_scan_to_supabase(result: dict, platform: str = "Web", has_image: int = 0):
    """
    Asynchronously record a completed scan to the Supabase scans table.
    Non-blocking, safe against failures, and never leaks credentials.
    """
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY or not isinstance(result, dict):
        return

    try:
        # 1. Derive stored verdict consistently:
        # risk >= 80 -> SCAM, risk >= 40 -> SUSPICIOUS, otherwise SAFE
        risk_score = int(result.get("risk_score") or 0)
        if risk_score >= 80:
            verdict = "SCAM"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # 2. Safe preview / primary input:
        # text input when available, extracted text when available, transcript when available,
        # otherwise "Multimedia Forensic Scan"
        target_input = (
            result.get("input")
            or result.get("extracted_text")
            or result.get("transcript")
            or "Multimedia Forensic Scan"
        )
        safe_message = _sanitize_scan_message(str(target_input))[:500]

        # 3. URL and domain extraction from entities
        entities = result.get("extracted_entities") or {}
        if not isinstance(entities, dict):
            entities = {}
        urls_list = entities.get("urls") or []
        if not isinstance(urls_list, list):
            urls_list = []
        url_count = len(urls_list)

        # 4. Reasons/evidence as JSON string
        evidence = result.get("evidence") or []
        if isinstance(evidence, (list, dict)):
            reasons_json = json.dumps(evidence)
        else:
            reasons_json = str(evidence)

        # 5. Build payload matching Supabase scans table
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": str(platform or "Web"),
            "message": safe_message,
            "risk_score": risk_score,
            "verdict": verdict,
            "scam_type": str(result.get("threat_type") or "Forensic Analysis"),
            "reasons": reasons_json,
            "has_image": int(has_image),
            "url_count": url_count,
            "urls": json.dumps(urls_list) if urls_list else None,
            "domains": None,
            "chat_id": None,
        }

        url = f"{SUPABASE_URL}/rest/v1/scans"
        headers = {
            **_get_supabase_headers(),
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code not in (200, 201):
                print(f"[Supabase] Warning: Failed to persist scan (HTTP {resp.status_code}): {resp.text}")
    except Exception as error:
        print(f"[Supabase] Warning: Scan persistence error: {error}")


async def _get_scan_from_supabase(scan_id: str) -> dict | None:
    """Async persistence fallback using incident_reports.evidence_json."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY or not scan_id:
        return None

    url = f"{SUPABASE_URL}/rest/v1/incident_reports?scan_id=eq.{scan_id}&select=evidence_json&limit=1"
    headers = _get_supabase_headers()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                rows = resp.json()
                if rows and isinstance(rows, list) and len(rows) > 0:
                    ev_raw = rows[0].get("evidence_json")
                    if isinstance(ev_raw, str):
                        try:
                            return json.loads(ev_raw)
                        except json.JSONDecodeError:
                            return None
                    elif isinstance(ev_raw, dict):
                        return ev_raw
    except Exception as e:
        print(f"[Supabase] Error loading scan {scan_id}: {e}")
    return None


def _parse_incident_row(row: dict) -> dict:
    evidence = row.get("evidence_json") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {}

    risk_score = evidence.get("risk_score")
    verdict = evidence.get("verdict")
    severity = str(
        evidence.get("severity")
        or _derive_severity(risk_score, verdict)
    ).lower()

    threat_type = (
        evidence.get("threat_type")
        or evidence.get("scam_type")
        or "Suspicious Activity"
    )

    platform = evidence.get("platform") or "Telegram"
    confidence = evidence.get("confidence") or "N/A"
    recommendation = evidence.get("recommendation") or ""
    original_text = evidence.get("original_text") or evidence.get("message") or ""
    summary = _sanitize_scan_message(original_text)

    incident_number = row.get("id")
    return {
        "id": f"INC-{int(incident_number):04d}" if str(incident_number).isdigit() else str(incident_number),
        "scan_id": row.get("scan_id"),
        "title": str(threat_type),
        "channel": str(platform),
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "status": str(evidence.get("status") or "investigating").lower(),
        "created_at": row.get("created_at"),
        "summary": summary or recommendation[:180],
    }

from detector import detect_signals
from risk_engine import calculate_risk
from ai_analyzer import analyze_text
from virustotal import scan_url
from image_analyzer import analyze_image_forensics, extract_text_from_image
from audio_analyzer import analyze_audio_forensics
from audio_transcriber import transcribe_audio, _get_model
from video_analyzer import (
    VideoProcessingError,
    extract_audio,
    extract_frames,
    probe_video,
    select_frame_timestamps,
)


app = FastAPI(title="TruthLensAI Detection Engine")

@app.on_event("startup")
async def startup_warmup():
    """Pre-warm Whisper model in a daemon thread so it is cached in memory before requests arrive."""
    threading.Thread(target=_get_model, daemon=True).start()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://truthlensai-dashboard.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.middleware("http")
async def add_request_timing(request: Request, call_next):
    start = time.perf_counter()

    response = await call_next(request)

    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-ms"] = f"{elapsed_ms:.2f}"

    return response


class ScanRequest(BaseModel):
    input: str
    platform: str = "web"


class IncidentCreateRequest(BaseModel):
    scan_id: str
    platform: str = "Web"
    evidence_json: dict | str | None = None


class IncidentStatusUpdateRequest(BaseModel):
    status: str


MAX_VIDEO_BYTES = 50 * 1024 * 1024
MAX_VIDEO_DURATION_SECONDS = 120
MAX_VIDEO_WIDTH = 1920
MAX_VIDEO_HEIGHT = 1080
SUPPORTED_VIDEO_EXTENSIONS = {".mp4", ".mov", ".webm", ".mkv"}


@app.get("/")
def home():
    return {
        "status": "online",
        "service": "TruthLensAI Detection Engine"
    }


def process_text(text: str):
    pipeline_start = time.perf_counter()

    # 1. Deterministic detection
    stage_start = time.perf_counter()
    signals = detect_signals(text)
    detector_ms = (time.perf_counter() - stage_start) * 1000

    # 2. Hugging Face AI analysis
    stage_start = time.perf_counter()
    try:
        ai_result = analyze_text(text)
    except Exception:
        ai_result = {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable"
        }
    llm_ms = (time.perf_counter() - stage_start) * 1000

    # 3. VirusTotal URL analysis
    stage_start = time.perf_counter()
    vt_results = []

    for url in signals["urls"]:
        try:
            vt_result = scan_url(url)
            vt_results.append({
                "url": url,
                **vt_result
            })
        except Exception as error:
            vt_results.append({
                "url": url,
                "status": "error",
                "error": str(error)
            })

    virustotal_ms = (time.perf_counter() - stage_start) * 1000

    # 4. Combine intelligence
    combined_signals = {
        **signals,
        "ai": ai_result,
        "virustotal": vt_results
    }

    # 5. Final risk engine
    stage_start = time.perf_counter()
    result = calculate_risk(combined_signals)
    risk_engine_ms = (time.perf_counter() - stage_start) * 1000

    total_pipeline_ms = (time.perf_counter() - pipeline_start) * 1000

    res = {
        "scan_id": str(uuid4()),
        "input": text,
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "confidence": result["confidence"],
        "threat_type": result["threat_type"],
        "evidence": result["evidence"],
        "ai_analysis": ai_result,
        "virustotal": vt_results,
        "recommendation": result["recommendation"],
        "extracted_entities": {
            "urls": signals["urls"],
            "upi_ids": signals["upi_ids"],
            "phone_numbers": signals["phone_numbers"],
            "emails": signals["emails"]
        },
        "timing": {
            "detector_ms": round(detector_ms, 2),
            "llm_ms": round(llm_ms, 2),
            "virustotal_ms": round(virustotal_ms, 2),
            "risk_engine_ms": round(risk_engine_ms, 2),
            "pipeline_total_ms": round(total_pipeline_ms, 2)
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    _save_scan_result(res)
    return res


# -----------------------------------------
# TEXT SCANNING
# -----------------------------------------

@app.post("/api/scan")
async def scan(request: ScanRequest):
    res = process_text(request.input)
    asyncio.create_task(
        _persist_scan_to_supabase(
            res,
            platform=getattr(request, "platform", "Web") or "Web",
            has_image=0,
        )
    )
    return res


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    res = _get_scan_result(scan_id)
    if res:
        return res

    supabase_res = await _get_scan_from_supabase(scan_id)
    if supabase_res:
        _save_scan_result(supabase_res)
        return supabase_res

    raise HTTPException(status_code=404, detail="Scan result not found or expired")


# -----------------------------------------
# PLATFORM TELEMETRY & SHARED DATA ENDPOINTS
# -----------------------------------------

@app.get("/api/telemetry/overview")
async def get_telemetry_overview():
    try:
        # 1. Exact platform-wide counts
        total_scans = await _supabase_exact_count("scans")
        threats_detected = await _supabase_exact_count("scans", "risk_score=gte.40")
        critical_threats = await _supabase_exact_count("scans", "or=(risk_score.gte.80,verdict.eq.SCAM)")
        community_indicators = await _supabase_exact_count("community_indicator_reputation", "normalized_value=neq.")

        # 2. Historical distribution & activity timeline (bounded query)
        url = f"{SUPABASE_URL}/rest/v1/scans?select=timestamp,risk_score,verdict&order=timestamp.desc&limit=500"
        headers = _get_supabase_headers()
        distribution = {"critical": 0, "high": 0, "suspicious": 0, "safe": 0, "total": total_scans}
        activity_map: dict[str, dict[str, int]] = {}

        if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    rows = resp.json()
                    for r in rows:
                        score = r.get("risk_score")
                        verdict = r.get("verdict")
                        sev = _derive_severity(score, verdict)
                        distribution[sev] = distribution.get(sev, 0) + 1

                        # Date grouping for chart
                        ts = r.get("timestamp") or ""
                        date_key = ts[:10] if len(ts) >= 10 else "Unknown"
                        if date_key != "Unknown":
                            if date_key not in activity_map:
                                activity_map[date_key] = {"threats": 0, "clean": 0}
                            if sev in ["critical", "high", "suspicious"]:
                                activity_map[date_key]["threats"] += 1
                            else:
                                activity_map[date_key]["clean"] += 1

        # Format sorted activity series
        sorted_dates = sorted(activity_map.keys())
        threat_activity = [
            {"time": d, "threats": activity_map[d]["threats"], "clean": activity_map[d]["clean"]}
            for d in sorted_dates
        ]

        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "critical_threats": critical_threats,
            "community_reports_indexed": community_indicators,
            "severity_distribution": distribution,
            "threat_activity": threat_activity,
        }
    except Exception as e:
        print(f"[Telemetry] Overview failed: {e}")
        return {
            "total_scans": 0,
            "threats_detected": 0,
            "critical_threats": 0,
            "community_reports_indexed": 0,
            "severity_distribution": {"critical": 0, "high": 0, "suspicious": 0, "safe": 0, "total": 0},
            "threat_activity": [],
        }


@app.get("/api/scans")
async def get_scans(limit: int = 10, offset: int = 0):
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    try:
        total = await _supabase_exact_count("scans")
        url = (
            f"{SUPABASE_URL}/rest/v1/scans?"
            f"select=id,timestamp,platform,message,risk_score,verdict,scam_type,has_image&"
            f"order=id.desc&limit={limit}&offset={offset}"
        )
        headers = _get_supabase_headers()
        items = []
        if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    for row in resp.json():
                        score = row.get("risk_score") if isinstance(row.get("risk_score"), (int, float)) else 0
                        verdict = row.get("verdict")
                        items.append({
                            "id": str(row.get("id")),
                            "timestamp": row.get("timestamp") or "Recently",
                            "platform": row.get("platform") or "Web",
                            "target_input": _sanitize_scan_message(row.get("message")),
                            "modality": "image" if row.get("has_image") else "text",
                            "risk_score": score,
                            "severity": _derive_severity(score, verdict),
                            "verdict": verdict or "ANALYZING",
                            "threat_type": row.get("scam_type") or verdict or "Forensic Analysis",
                            "status": "analyzing" if verdict == "ANALYZING" else "complete",
                        })
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        print(f"[Telemetry] get_scans failed: {e}")
        return {"items": [], "total": 0, "limit": limit, "offset": offset}


@app.get("/api/incidents")
async def get_incidents(limit: int = 10, offset: int = 0):
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    try:
        total = await _supabase_exact_count("incident_reports")
        url = (
            f"{SUPABASE_URL}/rest/v1/incident_reports?"
            f"select=id,scan_id,evidence_json,created_at&"
            f"order=id.desc&limit={limit}&offset={offset}"
        )
        headers = _get_supabase_headers()
        items = []
        if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    for row in resp.json():
                        items.append(_parse_incident_row(row))
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        print(f"[Telemetry] get_incidents failed: {e}")
        return {"items": [], "total": 0, "limit": limit, "offset": offset}


@app.post("/api/incidents")
async def create_incident(req: IncidentCreateRequest):
    scan_id = req.scan_id.strip() if req.scan_id else ""
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")

    evidence_dict: dict = {}
    if isinstance(req.evidence_json, dict):
        evidence_dict = dict(req.evidence_json)
    elif isinstance(req.evidence_json, str):
        try:
            parsed = json.loads(req.evidence_json)
            if isinstance(parsed, dict):
                evidence_dict = parsed
            else:
                evidence_dict = {"original_text": req.evidence_json}
        except json.JSONDecodeError:
            evidence_dict = {"original_text": req.evidence_json}

    # If evidence is minimal, attempt to enrich from cache or scans table
    if not evidence_dict.get("risk_score") and not evidence_dict.get("threat_type"):
        cached = _get_scan_result(scan_id)
        if not cached:
            cached = await _get_scan_from_supabase(scan_id)
        if cached and isinstance(cached, dict):
            for k, v in cached.items():
                if k not in evidence_dict or not evidence_dict[k]:
                    evidence_dict[k] = v

    # Platform & status defaults
    evidence_dict["platform"] = req.platform or evidence_dict.get("platform") or "Web"
    evidence_dict["status"] = str(evidence_dict.get("status") or "investigating").lower()

    # Derive severity if missing or validate existing
    existing_sev = evidence_dict.get("severity")
    if existing_sev and str(existing_sev).lower() in ("critical", "high", "suspicious", "safe"):
        severity = str(existing_sev).lower()
    else:
        risk_score = evidence_dict.get("risk_score")
        verdict = evidence_dict.get("verdict")
        severity = _derive_severity(risk_score, verdict)
    evidence_dict["severity"] = severity.upper()
    evidence_dict["scan_id"] = scan_id

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="Supabase database not configured")

    url = f"{SUPABASE_URL}/rest/v1/incident_reports"
    headers = {
        **_get_supabase_headers(),
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    payload = {
        "scan_id": scan_id,
        "chat_id": None,
        "evidence_json": json.dumps(evidence_dict),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code not in (200, 201):
                print(f"[Supabase] Warning: Failed to create incident: {resp.status_code} {resp.text}")
                raise HTTPException(status_code=502, detail="Failed to persist incident to database")

            created_rows = resp.json()
            if not created_rows or not isinstance(created_rows, list):
                raise HTTPException(status_code=502, detail="Database did not return created incident")

            created_row = created_rows[0]
            return _parse_incident_row(created_row)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[Supabase] Error creating incident: {e}")
        raise HTTPException(status_code=502, detail="Database connection error")


ALLOWED_INCIDENT_STATUSES = {"investigating", "open", "resolved"}


@app.patch("/api/incidents/{incident_id}")
async def update_incident_status(incident_id: str, req: IncidentStatusUpdateRequest):
    incident_id = incident_id.strip()
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id is required")

    new_status = req.status.strip().lower()
    if new_status not in ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{req.status}'. Allowed statuses: {', '.join(sorted(ALLOWED_INCIDENT_STATUSES))}"
        )

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="Supabase database not configured")

    numeric_id = None
    if incident_id.upper().startswith("INC-") and incident_id[4:].isdigit():
        numeric_id = int(incident_id[4:])
    elif incident_id.isdigit():
        numeric_id = int(incident_id)

    headers = _get_supabase_headers()

    if numeric_id is not None:
        fetch_url = f"{SUPABASE_URL}/rest/v1/incident_reports?id=eq.{numeric_id}&select=id,scan_id,evidence_json,created_at"
    else:
        fetch_url = f"{SUPABASE_URL}/rest/v1/incident_reports?scan_id=eq.{incident_id}&select=id,scan_id,evidence_json,created_at&limit=1"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            fetch_resp = await client.get(fetch_url, headers=headers)
            if fetch_resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Failed to fetch incident from database")

            rows = fetch_resp.json()
            if not rows or not isinstance(rows, list):
                raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

            target_row = rows[0]
            raw_evidence = target_row.get("evidence_json") or {}
            if isinstance(raw_evidence, str):
                try:
                    evidence_dict = json.loads(raw_evidence)
                except json.JSONDecodeError:
                    evidence_dict = {"original_text": raw_evidence}
            elif isinstance(raw_evidence, dict):
                evidence_dict = dict(raw_evidence)
            else:
                evidence_dict = {}

            # Preserve all existing forensic evidence; only update/add status
            evidence_dict["status"] = new_status

            patch_url = f"{SUPABASE_URL}/rest/v1/incident_reports?id=eq.{target_row['id']}"
            patch_headers = {
                **headers,
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            }
            patch_payload = {
                "evidence_json": json.dumps(evidence_dict)
            }

            patch_resp = await client.patch(patch_url, json=patch_payload, headers=patch_headers)
            if patch_resp.status_code not in (200, 204):
                print(f"[Supabase] Warning: Failed to update incident status: {patch_resp.status_code} {patch_resp.text}")
                raise HTTPException(status_code=502, detail="Failed to persist incident status in database")

            updated_rows = patch_resp.json() if patch_resp.status_code == 200 else []
            if updated_rows and isinstance(updated_rows, list):
                return _parse_incident_row(updated_rows[0])

            target_row["evidence_json"] = json.dumps(evidence_dict)
            return _parse_incident_row(target_row)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[Supabase] Error updating incident status: {e}")
        raise HTTPException(status_code=502, detail="Database connection error")


@app.get("/api/community/feed")
async def get_community_feed(limit: int = 20):
    limit = max(1, min(limit, 50))
    try:
        total = await _supabase_exact_count("community_indicator_reputation", "normalized_value=neq.")
        url = (
            f"{SUPABASE_URL}/rest/v1/community_indicator_reputation?"
            f"normalized_value=neq.&order=report_count.desc&limit={limit}"
        )
        headers = _get_supabase_headers()
        items = []
        if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
            async with httpx.AsyncClient(timeout=8.0) as client:
                # Query blocked threat_indicators values
                blocked_values = set()
                try:
                    blocked_url = f"{SUPABASE_URL}/rest/v1/threat_indicators?status=eq.blocked&select=value"
                    blocked_resp = await client.get(blocked_url, headers=headers)
                    if blocked_resp.status_code == 200:
                        for b_row in blocked_resp.json():
                            b_val = str(b_row.get("value") or "").strip()
                            if b_val:
                                blocked_values.add(b_val)
                except Exception as b_err:
                    print(f"[Telemetry] Warning: Failed to query blocked indicators: {b_err}")

                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    for row in resp.json():
                        val = str(row.get("normalized_value") or "").strip()
                        if not val:
                            continue
                        cnt = int(row.get("report_count") or 0)
                        tier = "critical" if cnt > 50 else "high" if cnt > 10 else "suspicious" if cnt > 3 else "safe"
                        items.append({
                            "indicator": val,
                            "indicator_type": str(row.get("indicator_type") or "URL").upper(),
                            "report_count": cnt,
                            "risk_tier": tier,
                            "first_seen": row.get("first_seen"),
                            "last_seen": row.get("last_seen"),
                            "is_blocked": val in blocked_values,
                        })
        return {
            "items": items,
            "total": len(items) if total == 0 else total,
        }
    except Exception as e:
        print(f"[Telemetry] get_community_feed failed: {e}")
        return {"items": [], "total": 0}


class BlockIndicatorRequest(BaseModel):
    indicator: str
    blocked: bool = True


@app.post("/api/community/block")
async def block_community_indicator(request: BlockIndicatorRequest):
    indicator = (request.indicator or "").strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="Indicator string cannot be empty")

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="Database credentials not configured")

    headers = {
        **_get_supabase_headers(),
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

    # When blocked=True -> status="blocked", when blocked=False -> status=None
    new_status = "blocked" if request.blocked else None

    # PostgREST PATCH to threat_indicators with exact match on value
    safe_val = urllib.parse.quote(indicator, safe="")
    patch_url = f"{SUPABASE_URL}/rest/v1/threat_indicators?value=eq.{safe_val}"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.patch(
                patch_url,
                json={"status": new_status},
                headers=headers
            )
            if resp.status_code not in (200, 204):
                print(f"[Supabase] Failed to update threat_indicators: {resp.status_code} {resp.text}")
                raise HTTPException(status_code=502, detail="Failed to persist indicator block state in database")

            updated_rows = resp.json() if resp.status_code == 200 else []
            updated_count = len(updated_rows) if isinstance(updated_rows, list) else 0

            return {
                "success": True,
                "indicator": indicator,
                "blocked": request.blocked,
                "updated_count": updated_count,
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[Supabase] Error blocking indicator: {e}")
        raise HTTPException(status_code=502, detail="Database connection error")


# -----------------------------------------
# IMAGE SCANNING
# -----------------------------------------

@app.post("/api/scan/image")
async def scan_image(
    file: UploadFile | None = File(None),
    platform: str = Form("web")
):

    # Check that a file was actually uploaded
    if file is None or not file.filename:
        return {
            "error": "No image file provided"
        }

    if file.content_type and not file.content_type.startswith("image/"):
        return {
            "error": "Unsupported image type"
        }

    contents = await file.read()

    if not contents:
        return {
            "error": "Empty image file"
        }

    suffix = os.path.splitext(file.filename)[1] or ".png"

    # Save uploaded image temporarily before entering the cleanup scope.
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix
    ) as temp_file:
        temp_file.write(contents)
        temp_path = temp_file.name

    pipeline_start = time.perf_counter()

    try:
        try:
            # 1. OCR and image preprocessing
            extracted_text = extract_text_from_image(temp_path)
        except Exception:
            return {
                "error": "Could not process image"
            }

        if not extracted_text.strip():
            # A valid image can contain no readable text; forensics remain useful.
            forensics_start = time.perf_counter()
            try:
                image_forensics = analyze_image_forensics(contents)
            except Exception as error:
                image_forensics = {
                    "exif": {
                        "available": False,
                        "fields": {},
                        "error": str(error),
                    },
                    "ela": {
                        "supported": False,
                        "possible_editing_indicators": None,
                        "reason": str(error),
                    },
                }
            forensics_ms = (time.perf_counter() - forensics_start) * 1000
            total_pipeline_ms = (time.perf_counter() - pipeline_start) * 1000

            res = {
                "scan_id": str(uuid4()),
                "risk_score": 0,
                "severity": "SAFE",
                "confidence": "Low",
                "threat_type": "Clean / Informational (No Text Detected)",
                "evidence": [
                    {
                        "signal": "Image forensics evaluated (No readable text or threat patterns detected)",
                        "points": 0
                    }
                ],
                "ai_analysis": {
                    "scam_intent": False,
                    "social_engineering": False,
                    "impersonation": False,
                    "financial_manipulation": False,
                    "urgency": "none",
                    "confidence": "low",
                    "explanation": "No readable text detected in uploaded image. Forensic telemetry is informational."
                },
                "virustotal": [],
                "recommendation": "No readable text detected; image forensics are informational only.",
                "extracted_entities": {
                    "urls": [],
                    "upi_ids": [],
                    "phone_numbers": [],
                    "emails": []
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "input_type": "image",
                "platform": platform,
                "extracted_text": "",
                "ocr_status": "No readable text detected",
                "image_forensics": image_forensics,
                "timing": {
                    "detector_ms": 0.0,
                    "llm_ms": 0.0,
                    "virustotal_ms": 0.0,
                    "risk_engine_ms": round(forensics_ms, 2),
                    "pipeline_total_ms": round(total_pipeline_ms, 2)
                }
            }
            _save_scan_result(res)
            asyncio.create_task(_persist_scan_to_supabase(res, platform=platform, has_image=1))
            return res

        try:
            # 2. Run complete text pipeline
            result = process_text(extracted_text)
        except Exception:
            return {
                "error": "Could not process image"
            }

        # 3. Add image/OCR information
        result["input_type"] = "image"
        result["platform"] = platform
        result["extracted_text"] = extracted_text
        result["ocr_status"] = "Text successfully extracted"
        # Image forensics is informational and does not affect risk scoring.
        try:
            result["image_forensics"] = analyze_image_forensics(contents)
        except Exception as error:
            result["image_forensics"] = {
                "exif": {
                    "available": False,
                    "fields": {},
                    "error": str(error),
                },
                "ela": {
                    "supported": False,
                    "possible_editing_indicators": None,
                    "reason": str(error),
                },
            }

        total_pipeline_ms = (time.perf_counter() - pipeline_start) * 1000
        if "timing" in result:
            result["timing"]["pipeline_total_ms"] = round(total_pipeline_ms, 2)

        _save_scan_result(result)
        asyncio.create_task(_persist_scan_to_supabase(result, platform=platform, has_image=1))
        return result

    finally:
        # Delete temporary image
        if os.path.exists(temp_path):
            os.remove(temp_path)


# -----------------------------------------
# AUDIO FORENSICS
# -----------------------------------------

def _sync_scan_audio(contents: bytes, filename: str, suffix: str, platform: str) -> dict:
    req_start = time.perf_counter()
    print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_REQUEST_START: filename={filename}, platform={platform}", flush=True)
    print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] FILE_RECEIVED: {len(contents)} bytes, suffix={suffix}", flush=True)

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        temp_file.write(contents)
        temp_path = temp_file.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as normalized_file:
        normalized_path = normalized_file.name

    try:
        print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] FFMPEG_START: normalizing to 16kHz mono WAV...", flush=True)
        t_ff_start = time.perf_counter()
        try:
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    temp_path,
                    "-ac",
                    "1",
                    "-ar",
                    "16000",
                    "-f",
                    "wav",
                    normalized_path,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
            )
            t_ff_ms = (time.perf_counter() - t_ff_start) * 1000
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] FFMPEG_DONE: normalization finished in {t_ff_ms:.1f}ms", flush=True)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            message = getattr(error, "stderr", None) or str(error)
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] FFMPEG_FAILED: {message}", flush=True)
            try:
                audio_forensics = analyze_audio_forensics(temp_path)
            except Exception as analyzer_error:
                audio_forensics = {
                    "error": {
                        "code": "audio_forensics_failed",
                        "message": str(analyzer_error),
                    }
                }
            return {
                "error": {
                    "code": "audio_conversion_failed",
                    "message": message.strip() if isinstance(message, str) else str(message),
                },
                "audio_forensics": audio_forensics,
            }

        print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_FORENSICS_START: extracting features...", flush=True)
        t_forensics_start = time.perf_counter()
        try:
            audio_forensics = analyze_audio_forensics(normalized_path)
            t_forensics_ms = (time.perf_counter() - t_forensics_start) * 1000
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_FORENSICS_DONE: features extracted in {t_forensics_ms:.1f}ms (duration={audio_forensics.get('duration_seconds')}s)", flush=True)
        except Exception as error:
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_FORENSICS_FAILED: {error}", flush=True)
            audio_forensics = {
                "error": {
                    "code": "audio_forensics_failed",
                    "message": str(error),
                }
            }

        transcription = transcribe_audio(normalized_path)

        base_response = {
            "scan_id": str(uuid4()),
            "input_type": "audio",
            "platform": platform,
            "transcript": transcription.get("text"),
            "transcription": transcription,
            "risk_score": None,
            "severity": None,
            "confidence": None,
            "threat_type": None,
            "evidence": [],
            "ai_analysis": None,
            "virustotal": [],
            "recommendation": "No usable speech transcript was available; audio forensics are informational only.",
            "extracted_entities": {
                "urls": [],
                "upi_ids": [],
                "phone_numbers": [],
                "emails": [],
            },
            "audio_forensics": audio_forensics,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if transcription.get("status") != "success" or not transcription.get("text"):
            req_ms = (time.perf_counter() - req_start) * 1000
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_REQUEST_END: completed (no speech) in {req_ms:.1f}ms", flush=True)
            _save_scan_result(base_response)
            return base_response

        print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AI_ANALYSIS_START: classifying transcript...", flush=True)
        t_ai_start = time.perf_counter()
        try:
            result = process_text(transcription["text"])
            t_ai_ms = (time.perf_counter() - t_ai_start) * 1000
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AI_ANALYSIS_DONE: finished in {t_ai_ms:.1f}ms", flush=True)
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] RISK_ANALYSIS_DONE: risk_score={result.get('risk_score')}, severity={result.get('severity')}", flush=True)
        except Exception as error:
            print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AI_ANALYSIS_FAILED: {error}", flush=True)
            err_res = {
                **base_response,
                "error": {
                    "code": "audio_text_analysis_failed",
                    "message": str(error),
                },
            }
            _save_scan_result(err_res)
            return err_res

        result["input_type"] = "audio"
        result["platform"] = platform
        result["transcript"] = transcription["text"]
        result["transcription"] = transcription
        result["audio_forensics"] = audio_forensics

        req_ms = (time.perf_counter() - req_start) * 1000
        print(f"[{datetime.now().isoformat()}] [AUDIO_SCAN] AUDIO_REQUEST_END: total audio scan completed in {req_ms:.1f}ms (scan_id={result.get('scan_id')})", flush=True)
        _save_scan_result(result)
        return result
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if os.path.exists(normalized_path):
            os.remove(normalized_path)


@app.post("/api/scan/audio")
async def scan_audio(
    file: UploadFile | None = File(None),
    platform: str = Form("web")
):
    if file is None or not file.filename:
        return {
            "error": {
                "code": "audio_file_missing",
                "message": "No audio file provided",
            }
        }

    content_type = file.content_type or ""
    if content_type and not (
        content_type.startswith("audio/")
        or content_type == "application/octet-stream"
    ):
        return {
            "error": {
                "code": "unsupported_audio_type",
                "message": "Unsupported audio content type",
            }
        }

    contents = await file.read()
    if not contents:
        return {
            "error": {
                "code": "audio_file_empty",
                "message": "Empty audio file",
            }
        }

    suffix = Path(file.filename).suffix.lower()
    if not suffix:
        if "ogg" in content_type:
            suffix = ".ogg"
        elif "mpeg" in content_type or "mp3" in content_type:
            suffix = ".mp3"
        elif "wav" in content_type:
            suffix = ".wav"
        elif "webm" in content_type:
            suffix = ".webm"
        else:
            suffix = ".wav"

    res = await asyncio.to_thread(_sync_scan_audio, contents, file.filename, suffix, platform)
    if isinstance(res, dict) and "error" not in res and res.get("scan_id"):
        asyncio.create_task(_persist_scan_to_supabase(res, platform=platform, has_image=0))
    return res


# -----------------------------------------
# VIDEO SCANNING
# -----------------------------------------

def _sync_scan_video(contents: bytes, filename: str, suffix: str, platform: str) -> dict:
    req_start = time.perf_counter()
    print(f"[{datetime.now().isoformat()}] [VIDEO_SCAN] VIDEO_REQUEST_START: filename={filename}, platform={platform}", flush=True)
    print(f"[{datetime.now().isoformat()}] [VIDEO_SCAN] FILE_RECEIVED: {len(contents)} bytes, suffix={suffix}", flush=True)

    with tempfile.TemporaryDirectory(prefix="truthlens-video-") as temp_directory:
        video_path = str(Path(temp_directory) / f"input{suffix}")
        Path(video_path).write_bytes(contents)

        try:
            video_metadata = probe_video(video_path)
        except VideoProcessingError as error:
            return {"error": {"code": error.code, "message": error.message}}

        duration_seconds = video_metadata["duration_seconds"]
        width = video_metadata.get("width")
        height = video_metadata.get("height")
        if duration_seconds > MAX_VIDEO_DURATION_SECONDS:
            return {
                "error": {
                    "code": "video_duration_too_long",
                    "message": "Video duration exceeds the 60 second limit",
                }
            }
        if not isinstance(width, int) or not isinstance(height, int):
            return {
                "error": {
                    "code": "invalid_video_dimensions",
                    "message": "Video dimensions are unavailable",
                }
            }
        if width > MAX_VIDEO_WIDTH or height > MAX_VIDEO_HEIGHT:
            return {
                "error": {
                    "code": "video_dimensions_too_large",
                    "message": "Video dimensions must not exceed 1920x1080",
                }
            }

        try:
            frame_records = extract_frames(
                video_path,
                select_frame_timestamps(duration_seconds),
                temp_directory,
            )
        except VideoProcessingError as error:
            return {"error": {"code": error.code, "message": error.message}}

        frames = []
        frame_ocr_parts = []
        frame_editing_indicators = []
        for frame_record in frame_records:
            frame_path = frame_record["path"]
            frame_bytes = Path(frame_path).read_bytes()
            try:
                ocr_text = extract_text_from_image(frame_path)
            except Exception as error:
                ocr_text = ""
                ocr_error = str(error)
            else:
                ocr_error = None

            image_forensics = analyze_image_forensics(frame_bytes)
            frame = {
                "timestamp_seconds": frame_record["timestamp_seconds"],
                "ocr_text": ocr_text,
                "image_forensics": image_forensics,
            }
            if ocr_error:
                frame["ocr_error"] = ocr_error
            frames.append(frame)
            clean_ocr = ocr_text.strip()
            if clean_ocr and (not frame_ocr_parts or frame_ocr_parts[-1] != clean_ocr):
                frame_ocr_parts.append(clean_ocr)

            possible_editing_indicators = (
                image_forensics.get("ela", {}).get("possible_editing_indicators")
                if isinstance(image_forensics, dict)
                and isinstance(image_forensics.get("ela"), dict)
                else None
            )
            if isinstance(possible_editing_indicators, bool):
                frame_editing_indicators.append(possible_editing_indicators)

        frame_ocr_text = "\n".join(frame_ocr_parts)
        frame_possible_editing_indicators = (
            any(frame_editing_indicators)
            if frame_editing_indicators
            else None
        )
        audio_forensics = None
        if video_metadata["has_audio"]:
            audio_path = str(Path(temp_directory) / "audio.wav")
            try:
                extract_audio(video_path, audio_path)
            except VideoProcessingError as error:
                transcription = {
                    "status": "error",
                    "text": None,
                    "code": error.code,
                    "message": error.message,
                }
                audio_forensics = {
                    "error": {
                        "code": "audio_forensics_unavailable",
                        "message": error.message,
                    }
                }
            else:
                try:
                    transcription = transcribe_audio(audio_path)
                except Exception as error:
                    transcription = {
                        "status": "error",
                        "text": None,
                        "code": "transcription_failed",
                        "message": str(error),
                    }
                try:
                    audio_forensics = analyze_audio_forensics(audio_path)
                except Exception as error:
                    audio_forensics = {
                        "error": {
                            "code": "audio_forensics_failed",
                            "message": str(error),
                        }
                    }
        else:
            transcription = {
                "status": "no_audio",
                "text": None,
                "reason": "No audio stream found",
            }

        base_response = {
            "scan_id": str(uuid4()),
            "input_type": "video",
            "platform": platform,
            "transcript": transcription.get("text"),
            "transcription": transcription,
            "risk_score": None,
            "severity": None,
            "confidence": None,
            "threat_type": None,
            "evidence": [],
            "ai_analysis": None,
            "virustotal": [],
            "recommendation": "No usable speech transcript was available; visual and audio forensics are informational only.",
            "extracted_entities": {
                "urls": [],
                "upi_ids": [],
                "phone_numbers": [],
                "emails": [],
            },
            "video_metadata": video_metadata,
            "frames": frames,
            "frame_ocr_text": frame_ocr_text,
            "video_forensics": {
                "frame_possible_editing_indicators": frame_possible_editing_indicators,
            },
            "audio_forensics": audio_forensics,
            "analysis_source": "none",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transcript = transcription.get("text")
        has_transcript = isinstance(transcript, str) and bool(transcript.strip())
        has_frame_ocr = bool(frame_ocr_text)

        if has_transcript and has_frame_ocr:
            analysis_input = (
                f"SPOKEN TRANSCRIPT:\n{transcript.strip()}\n\n"
                f"ON-SCREEN TEXT:\n{frame_ocr_text}"
            )
            analysis_source = "speech_and_frame_ocr"
        elif has_transcript:
            analysis_input = transcript.strip()
            analysis_source = "speech"
        elif has_frame_ocr:
            analysis_input = frame_ocr_text
            analysis_source = "frame_ocr"
        else:
            analysis_input = None
            analysis_source = "none"

        base_response["analysis_source"] = analysis_source

        if analysis_input is None:
            _save_scan_result(base_response)
            return base_response

        try:
            result = process_text(analysis_input)
        except Exception as error:
            err_res = {
                **base_response,
                "error": {
                    "code": "video_text_analysis_failed",
                    "message": str(error),
                },
            }
            _save_scan_result(err_res)
            return err_res

        result.update({
            "input_type": "video",
            "platform": platform,
            "transcript": transcription["text"],
            "transcription": transcription,
            "video_metadata": video_metadata,
            "frames": frames,
            "frame_ocr_text": frame_ocr_text,
            "video_forensics": {
                "frame_possible_editing_indicators": frame_possible_editing_indicators,
            },
            "audio_forensics": audio_forensics,
            "analysis_source": analysis_source,
        })
        req_ms = (time.perf_counter() - req_start) * 1000
        print(f"[{datetime.now().isoformat()}] [VIDEO_SCAN] VIDEO_REQUEST_END: completed in {req_ms:.1f}ms (scan_id={result.get('scan_id')})", flush=True)
        _save_scan_result(result)
        return result


@app.post("/api/scan/video")
async def scan_video(
    file: UploadFile | None = File(None),
    platform: str = Form("web")
):
    if file is None or not file.filename:
        return {
            "error": {
                "code": "video_file_missing",
                "message": "No video file provided",
            }
        }

    suffix = Path(file.filename).suffix.lower()
    content_type = file.content_type or ""
    if suffix not in SUPPORTED_VIDEO_EXTENSIONS or (
        content_type
        and not (
            content_type.startswith("video/")
            or content_type == "application/octet-stream"
        )
    ):
        return {
            "error": {
                "code": "unsupported_video_type",
                "message": "Supported video formats are MP4, MOV, WebM, and MKV",
            }
        }

    contents = await file.read(MAX_VIDEO_BYTES + 1)
    if not contents:
        return {
            "error": {
                "code": "video_file_empty",
                "message": "Empty video file",
            }
        }
    if len(contents) > MAX_VIDEO_BYTES:
        return {
            "error": {
                "code": "video_file_too_large",
                "message": "Video file exceeds the 50 MB limit",
            }
        }

    res = await asyncio.to_thread(_sync_scan_video, contents, file.filename, suffix, platform)
    if isinstance(res, dict) and "error" not in res and res.get("scan_id"):
        asyncio.create_task(_persist_scan_to_supabase(res, platform=platform, has_image=0))
    return res