"""Speech-to-text helper for audio scans."""

import re
from threading import Lock
from typing import Any

from faster_whisper import WhisperModel


_MODEL: WhisperModel | None = None
_MODEL_LOCK = Lock()


def _get_model() -> WhisperModel:
    """Load the CPU model once and reuse it for subsequent requests."""

    global _MODEL

    if _MODEL is None:
        with _MODEL_LOCK:
            if _MODEL is None:
                _MODEL = WhisperModel(
                    "base",
                    device="cpu",
                    compute_type="int8",
                )
    return _MODEL


def _has_meaningful_text(text: str) -> bool:
    """Reject empty or punctuation-only output as a usable transcript."""

    normalized = re.sub(r"\s+", " ", text).strip()
    return bool(normalized and re.search(r"[\w\u0900-\u097f]", normalized))


def transcribe_audio(audio_path: str) -> dict:
    """Transcribe speech and report explicit no-speech or failure states.

    Whisper transcription provides text only; it is not a deepfake detector.
    """

    try:
        model = _get_model()
        segments, info = model.transcribe(
            audio_path,
            beam_size=1,
            condition_on_previous_text=False,
            vad_filter=True,
            no_speech_threshold=0.6,
        )

        serialized_segments = []
        transcript_parts = []
        for segment in segments:
            segment_text = segment.text.strip()
            if segment_text:
                transcript_parts.append(segment_text)
            serialized_segments.append({
                "start": round(float(segment.start), 3),
                "end": round(float(segment.end), 3),
                "text": segment_text,
            })

        transcript = " ".join(transcript_parts).strip()
        duration_seconds = round(float(info.duration), 3)

        if not serialized_segments:
            return {
                "status": "no_speech",
                "text": None,
                "reason": "No voiced speech detected",
            }

        if not _has_meaningful_text(transcript):
            return {
                "status": "unintelligible",
                "text": None,
                "reason": "Speech was detected but no reliable transcript was produced",
            }

        return {
            "status": "success",
            "text": transcript,
            "language": info.language,
            "duration_seconds": duration_seconds,
            "segments": serialized_segments,
        }
    except Exception as error:
        return {
            "status": "error",
            "text": None,
            "code": "transcription_failed",
            "message": str(error),
        }