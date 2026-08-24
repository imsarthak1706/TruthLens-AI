from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
from datetime import datetime, timezone
from uuid import uuid4
import tempfile
import os
import subprocess

from detector import detect_signals
from risk_engine import calculate_risk
from ai_analyzer import analyze_text
from virustotal import scan_url
from image_analyzer import analyze_image_forensics, extract_text_from_image
from audio_analyzer import analyze_audio_forensics
from audio_transcriber import transcribe_audio


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
        "scan_id": str(uuid4()),
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
            # A valid image can contain no readable text; forensics remain useful.
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

            return {
                "scan_id": str(uuid4()),
                "risk_score": None,
                "severity": None,
                "confidence": None,
                "threat_type": None,
                "evidence": [],
                "ai_analysis": None,
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

        return result

    finally:
        # Delete temporary image
        if os.path.exists(temp_path):
            os.remove(temp_path)


# -----------------------------------------
# AUDIO FORENSICS
# -----------------------------------------

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

    suffix = os.path.splitext(file.filename)[1] or ".audio"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        temp_file.write(contents)
        temp_path = temp_file.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as normalized_file:
        normalized_path = normalized_file.name

    try:
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
            )
        except (OSError, subprocess.CalledProcessError) as error:
            message = getattr(error, "stderr", None) or str(error)
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
                    "message": message.strip(),
                },
                "audio_forensics": audio_forensics,
            }

        try:
            transcription = transcribe_audio(normalized_path)
        except Exception as error:
            transcription = {
                "status": "error",
                "text": None,
                "code": "transcription_failed",
                "message": str(error),
            }

        try:
            audio_forensics = analyze_audio_forensics(normalized_path)
        except Exception as error:
            audio_forensics = {
                "error": {
                    "code": "audio_forensics_failed",
                    "message": str(error),
                }
            }

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

        if transcription.get("status") != "success":
            return base_response

        try:
            result = process_text(transcription["text"])
        except Exception as error:
            return {
                **base_response,
                "error": {
                    "code": "audio_text_analysis_failed",
                    "message": str(error),
                },
            }

        result["input_type"] = "audio"
        result["platform"] = platform
        result["transcript"] = transcription["text"]
        result["transcription"] = transcription
        result["audio_forensics"] = audio_forensics
        return result
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if os.path.exists(normalized_path):
            os.remove(normalized_path)