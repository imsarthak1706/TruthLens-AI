from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timezone

from detector import detect_signals
from risk_engine import calculate_risk
from ai_analyzer import analyze_text
from virustotal import scan_url

app = FastAPI(title="TruthLensAI Detection Engine")


class ScanRequest(BaseModel):
    input: str
    platform: str


@app.get("/")
def home():
    return {
        "status": "online",
        "service": "TruthLensAI Detection Engine"
    }


@app.post("/api/scan")
def scan(request: ScanRequest):

    # 1. Deterministic detection
    signals = detect_signals(request.input)

    # 2. Hugging Face AI analysis
    ai_result = analyze_text(request.input)

    # 3. VirusTotal URL analysis
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

    # 4. Combine all intelligence
    combined_signals = {
        **signals,
        "ai": ai_result,
        "virustotal": vt_results
    }

    # 5. Final Risk Engine
    result = calculate_risk(combined_signals)

    return {
        "scan_id": "test_001",
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "confidence": result["confidence"],
        "threat_type": result["threat_type"],
        "evidence": result["evidence"],
        "ai_analysis": ai_result,
        "virustotal": vt_results,
        "recommendation": result["recommendation"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }