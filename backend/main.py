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
        "extracted_entities": {
            "urls": signals["urls"],
            "upi_ids": signals["upi_ids"],
            "phone_numbers": signals["phone_numbers"],
            "emails": signals["emails"]
        },
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

    try:
        try:
            # 1. OCR and image preprocessing
            extracted_text = extract_text_from_image(temp_path)
        except Exception:
            return {
                "error": "Could not process image"
            }

        if not extracted_text.strip():
            return {
                "error": "Could not extract text from image"
            }

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

        return result

    finally:
        # Delete temporary image
        if os.path.exists(temp_path):
            os.remove(temp_path)