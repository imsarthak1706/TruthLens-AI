from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
from datetime import datetime, timezone
import tempfile
import os

from detector import detect_signals
from risk_engine import calculate_risk
from ai_analyzer import analyze_text
from virustotal import scan_url
from image_analyzer import extract_text_from_image


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


def process_text(text: str):

    # 1. Deterministic detection
    signals = detect_signals(text)

    # 2. Hugging Face AI analysis
    ai_result = analyze_text(text)

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

    # 4. Combine intelligence
    combined_signals = {
        **signals,
        "ai": ai_result,
        "virustotal": vt_results
    }

    # 5. Final risk engine
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


# -----------------------------------------
# TEXT SCANNING
# -----------------------------------------

@app.post("/api/scan")
def scan(request: ScanRequest):

    return process_text(request.input)


# -----------------------------------------
# IMAGE SCANNING
# -----------------------------------------

@app.post("/api/scan/image")
async def scan_image(
    file: UploadFile = File(...),
    platform: str = Form("web")
):

    # Check that a file was actually uploaded
    if not file.filename:
        return {
            "error": "No image file provided"
        }

    # Save uploaded image temporarily
    suffix = os.path.splitext(file.filename)[1] or ".png"

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix
    ) as temp_file:

        contents = await file.read()
        temp_file.write(contents)
        temp_path = temp_file.name

    try:

        # 1. OCR
        extracted_text = extract_text_from_image(temp_path)

        if not extracted_text.strip():
            return {
                "error": "Could not extract text from image"
            }

        # 2. Run complete text pipeline
        result = process_text(extracted_text)

        # 3. Add image/OCR information
        result["input_type"] = "image"
        result["platform"] = platform
        result["extracted_text"] = extracted_text

        return result

    finally:

        # Delete temporary image
        if os.path.exists(temp_path):
            os.remove(temp_path)