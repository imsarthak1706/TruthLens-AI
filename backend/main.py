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
    platform: str


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
def scan(request: ScanRequest):
    return process_text(request.input)


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    res = _get_scan_result(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail="Scan result not found or expired")
    return res


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

    suffix = os.path.splitext(file.filename)[1] or ".audio"

    return await asyncio.to_thread(_sync_scan_audio, contents, file.filename, suffix, platform)


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

    return await asyncio.to_thread(_sync_scan_video, contents, file.filename, suffix, platform)