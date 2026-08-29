"""Lightweight audio feature extraction for forensic screening."""

import math

import librosa
import numpy as np


# This is a screening signal for unusual pitch variability, not a voice-cloning verdict.
PITCH_VARIABILITY_THRESHOLD_HZ = 100.0


def _rounded_or_none(value: float, digits: int) -> float | None:
    """Return a finite rounded value, or null for unavailable numeric data."""

    numeric_value = float(value)
    if not math.isfinite(numeric_value):
        return None
    return round(numeric_value, digits)


def _error_result(code: str, message: str) -> dict:
    """Return the stable error shape used when audio cannot be analyzed."""

    return {
        "error": {
            "code": code,
            "message": message,
        }
    }


def analyze_audio_forensics(audio_path: str) -> dict:
    """Extract lightweight audio features without claiming authenticity or cloning."""

    try:
        audio, sample_rate = librosa.load(audio_path, sr=None, mono=True)
    except Exception as error:
        return _error_result("audio_unreadable", f"Could not read audio: {error}")

    if audio.size == 0 or sample_rate <= 0:
        return _error_result("audio_empty", "Audio contains no samples")

    duration_seconds = audio.size / sample_rate

    try:
        rms = librosa.feature.rms(y=audio)
        rms_energy = _rounded_or_none(np.mean(rms), 6)
    except Exception:
        rms_energy = None

    try:
        spectral_centroid = librosa.feature.spectral_centroid(
            y=audio,
            sr=sample_rate,
        )
        spectral_bandwidth = librosa.feature.spectral_bandwidth(
            y=audio,
            sr=sample_rate,
        )
        centroid_mean_hz = _rounded_or_none(np.mean(spectral_centroid), 2)
        bandwidth_mean_hz = _rounded_or_none(np.mean(spectral_bandwidth), 2)
    except Exception:
        centroid_mean_hz = None
        bandwidth_mean_hz = None

    try:
        pitch_values, voiced_flag, _ = librosa.pyin(
            audio,
            fmin=librosa.note_to_hz("C2"),
            fmax=librosa.note_to_hz("C7"),
            sr=sample_rate,
            hop_length=1024,
        )
        valid_pitch = pitch_values[voiced_flag & np.isfinite(pitch_values)]
        mean_hz = _rounded_or_none(np.mean(valid_pitch), 2) if valid_pitch.size else None
        std_hz = _rounded_or_none(np.std(valid_pitch), 2) if valid_pitch.size else None
    except Exception:
        mean_hz = None
        std_hz = None

    possible_manipulation_indicators = bool(
        std_hz is not None and std_hz >= PITCH_VARIABILITY_THRESHOLD_HZ
    )

    return {
        "duration_seconds": _rounded_or_none(duration_seconds, 3),
        "sample_rate": int(sample_rate),
        "rms_energy": rms_energy,
        "pitch": {
            "mean_hz": mean_hz,
            "std_hz": std_hz,
        },
        "spectral": {
            "centroid_mean_hz": centroid_mean_hz,
            "bandwidth_mean_hz": bandwidth_mean_hz,
        },
        "possible_manipulation_indicators": possible_manipulation_indicators,
    }