"""Small FFmpeg helpers used by the video scan endpoint."""

import json
import math
import os
import subprocess
from pathlib import Path


FFMPEG_TIMEOUT_SECONDS = 30
FFPROBE_TIMEOUT_SECONDS = 15


class VideoProcessingError(Exception):
    """An expected media-processing failure with a stable error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise VideoProcessingError(
            "media_tool_missing",
            f"Required media tool is not installed: {error.filename}",
        ) from error
    except subprocess.TimeoutExpired as error:
        raise VideoProcessingError(
            "media_processing_timeout",
            "Video processing exceeded the time limit",
        ) from error
    except subprocess.CalledProcessError as error:
        message = (error.stderr or error.stdout or "Media processing failed").strip()
        raise VideoProcessingError("media_processing_failed", message[-1000:]) from error


def _parse_fraction(value: str | None) -> float | None:
    if not value or value in {"0/0", "N/A"}:
        return None
    try:
        numerator, denominator = value.split("/", 1)
        result = float(numerator) / float(denominator)
        return result if math.isfinite(result) else None
    except (ValueError, ZeroDivisionError):
        return None


def probe_video(video_path: str) -> dict:
    """Return the metadata needed by the video endpoint."""

    result = _run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration,format_name:stream=index,codec_type,codec_name,width,height,avg_frame_rate,duration",
            "-of",
            "json",
            video_path,
        ],
        FFPROBE_TIMEOUT_SECONDS,
    )

    try:
        probed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VideoProcessingError(
            "invalid_video_metadata",
            "FFprobe returned invalid metadata",
        ) from error

    streams = probed.get("streams", [])
    video_stream = next(
        (stream for stream in streams if stream.get("codec_type") == "video"),
        None,
    )
    audio_stream = next(
        (stream for stream in streams if stream.get("codec_type") == "audio"),
        None,
    )

    if video_stream is None:
        raise VideoProcessingError("video_stream_missing", "No video stream found")

    duration_value = video_stream.get("duration") or probed.get("format", {}).get("duration")
    try:
        duration_seconds = float(duration_value)
    except (TypeError, ValueError):
        raise VideoProcessingError(
            "invalid_video_metadata",
            "Video duration is unavailable",
        )

    if not math.isfinite(duration_seconds) or duration_seconds <= 0:
        raise VideoProcessingError("invalid_video_metadata", "Video duration is invalid")

    return {
        "duration_seconds": round(duration_seconds, 3),
        "width": video_stream.get("width"),
        "height": video_stream.get("height"),
        "fps": _parse_fraction(video_stream.get("avg_frame_rate")),
        "video_codec": video_stream.get("codec_name"),
        "audio_codec": audio_stream.get("codec_name") if audio_stream else None,
        "has_video": True,
        "has_audio": audio_stream is not None,
    }


def select_frame_timestamps(duration_seconds: float, max_frames: int = 12) -> list[float]:
    """Select approximately one frame per second, capped at max_frames."""

    if duration_seconds <= 0 or max_frames <= 0:
        return []

    usable_end = max(0.0, duration_seconds - 0.05)
    if duration_seconds <= max_frames:
        count = max(1, math.ceil(duration_seconds))
        return [round(min(index, usable_end), 3) for index in range(count)]

    if max_frames == 1:
        return [round(usable_end / 2, 3)]

    step = usable_end / (max_frames - 1)
    return [round(index * step, 3) for index in range(max_frames)]


def extract_frames(
    video_path: str,
    timestamps: list[float],
    output_directory: str,
) -> list[dict]:
    """Extract one JPEG for each requested timestamp."""

    frame_paths = []
    for index, timestamp in enumerate(timestamps):
        frame_path = Path(output_directory) / f"frame_{index:02d}.jpg"
        _run(
            [
                "ffmpeg",
                "-y",
                "-ss",
                str(timestamp),
                "-i",
                video_path,
                "-frames:v",
                "1",
                "-vf",
                "scale=1280:1280:force_original_aspect_ratio=decrease",
                "-q:v",
                "2",
                str(frame_path),
            ],
            FFMPEG_TIMEOUT_SECONDS,
        )
        if not frame_path.is_file() or frame_path.stat().st_size == 0:
            raise VideoProcessingError(
                "frame_extraction_failed",
                f"No frame was produced at {timestamp} seconds",
            )
        frame_paths.append({
            "timestamp_seconds": timestamp,
            "path": str(frame_path),
        })

    return frame_paths


def extract_audio(video_path: str, output_path: str) -> None:
    """Extract the first audio stream as mono 16 kHz PCM WAV."""

    _run(
        [
            "ffmpeg",
            "-y",
            "-i",
            video_path,
            "-map",
            "0:a:0",
            "-vn",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-c:a",
            "pcm_s16le",
            "-f",
            "wav",
            output_path,
        ],
        FFMPEG_TIMEOUT_SECONDS,
    )

    if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
        raise VideoProcessingError(
            "audio_extraction_failed",
            "FFmpeg did not produce an audio file",
        )