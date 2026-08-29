"""Lightweight audio feature extraction for forensic screening."""

import math
import wave
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
        # Fast path: read WAV directly via standard library wave module
        with wave.open(audio_path, "rb") as wf:
            sample_rate = wf.getframerate()
            n_frames = wf.getnframes()
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            raw = wf.readframes(n_frames)

            if sampwidth == 2:
                audio_raw = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
            elif sampwidth == 1:
                audio_raw = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
            elif sampwidth == 4:
                audio_raw = np.frombuffer(raw, dtype=np.int32).astype(np.float32) / 2147483648.0
            else:
                audio_raw = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0

            if n_channels > 1:
                audio = np.mean(audio_raw.reshape(-1, n_channels), axis=1)
            else:
                audio = audio_raw
    except Exception:
        # Fallback to librosa if not standard PCM WAV
        try:
            import librosa
            audio, sample_rate = librosa.load(audio_path, sr=16000, mono=True)
        except Exception as error:
            return _error_result("audio_unreadable", f"Could not read audio: {error}")

    if audio.size == 0 or sample_rate <= 0:
        return _error_result("audio_empty", "Audio contains no samples")

    duration_seconds = audio.size / sample_rate

    # 1. RMS Energy
    try:
        rms_val = float(np.sqrt(np.mean(audio**2)))
        rms_energy = _rounded_or_none(rms_val, 6)
    except Exception:
        rms_energy = None

    # 2. Spectral Centroid & Bandwidth
    try:
        magnitudes = np.abs(np.fft.rfft(audio))
        freqs = np.fft.rfftfreq(len(audio), 1.0 / sample_rate)
        sum_mag = np.sum(magnitudes)
        if sum_mag > 0:
            centroid = float(np.sum(freqs * magnitudes) / sum_mag)
            bandwidth = float(np.sqrt(np.sum(((freqs - centroid) ** 2) * magnitudes) / sum_mag))
            centroid_mean_hz = _rounded_or_none(centroid, 2)
            bandwidth_mean_hz = _rounded_or_none(bandwidth, 2)
        else:
            centroid_mean_hz, bandwidth_mean_hz = None, None
    except Exception:
        centroid_mean_hz = None
        bandwidth_mean_hz = None

    # 3. Pitch Tracking (Autocorrelation)
    try:
        frame_size = int(sample_rate * 0.05)  # 50ms window
        hop_size = int(sample_rate * 0.05)
        pitches = []
        fmin, fmax = 65.0, 500.0
        min_lag = int(sample_rate / fmax)
        max_lag = int(sample_rate / fmin)

        for i in range(0, len(audio) - frame_size, hop_size):
            frame = audio[i:i + frame_size]
            if np.max(np.abs(frame)) < 0.02:
                continue
            corr = np.correlate(frame, frame, mode="full")[frame_size - 1:]
            if len(corr) > max_lag:
                lag = min_lag + np.argmax(corr[min_lag:max_lag])
                if corr[0] > 0 and corr[lag] > 0.3 * corr[0]:
                    pitches.append(sample_rate / lag)

        valid_pitch = np.array(pitches) if pitches else np.array([])
        mean_hz = _rounded_or_none(float(np.mean(valid_pitch)), 2) if valid_pitch.size else None
        std_hz = _rounded_or_none(float(np.std(valid_pitch)), 2) if valid_pitch.size else None
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