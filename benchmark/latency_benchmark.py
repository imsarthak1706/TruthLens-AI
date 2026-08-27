import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOWNLOADS = Path.home() / "Downloads"

TEXT = (
    "URGENT! Your bank account will be blocked today. "
    "Verify immediately at https://example.com"
)

IMAGE = DOWNLOADS / "scam_imgg.jpeg"
AUDIO = DOWNLOADS / "scam_audio.ogg"
VIDEO = DOWNLOADS / "scam_video.mp4"

OUTPUT_DIR = ROOT / "benchmark" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_curl(args: list[str]) -> tuple[float, str]:
    start = time.perf_counter()

    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000

    if result.returncode != 0:
        raise RuntimeError(
            f"curl failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )

    return elapsed_ms, result.stdout


def extract_header(headers: str, header_name: str) -> float | None:
    target = header_name.lower()

    for line in headers.splitlines():
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        if name.strip().lower() == target:
            try:
                return float(value.strip())
            except ValueError:
                return None

    return None


def run_text() -> float:
    temp_headers = "/tmp/truthlens_latency_text_headers.txt"
    temp_result = "/tmp/truthlens_latency_text_result.json"

    elapsed, _ = run_curl(
        [
            "curl",
            "-s",
            "-X",
            "POST",
            "http://127.0.0.1:8000/api/scan",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps({"input": TEXT, "platform": "latency-test"}),
            "-D",
            temp_headers,
            "-o",
            temp_result,
        ]
    )

    headers = Path(temp_headers).read_text()
    measured = extract_header(headers, "X-Process-Time-ms")
    return measured if measured is not None else elapsed


def run_file(endpoint: str, file_path: Path, header_path: str, result_path: str) -> float:
    if not file_path.exists():
        raise FileNotFoundError(f"Test file not found: {file_path}")

    elapsed, _ = run_curl(
        [
            "curl",
            "-s",
            "-X",
            "POST",
            f"http://127.0.0.1:8000{endpoint}",
            "-F",
            f"file=@{file_path}",
            "-F",
            "platform=latency-test",
            "-D",
            header_path,
            "-o",
            result_path,
        ]
    )

    headers = Path(header_path).read_text()
    measured = extract_header(headers, "X-Process-Time-ms")
    return measured if measured is not None else elapsed


def main() -> None:
    tests = [
        ("text", run_text),
        (
            "image",
            lambda: run_file(
                "/api/scan/image",
                IMAGE,
                "/tmp/truthlens_latency_image_headers.txt",
                "/tmp/truthlens_latency_image_result.json",
            ),
        ),
        (
            "audio",
            lambda: run_file(
                "/api/scan/audio",
                AUDIO,
                "/tmp/truthlens_latency_audio_headers.txt",
                "/tmp/truthlens_latency_audio_result.json",
            ),
        ),
        (
            "video",
            lambda: run_file(
                "/api/scan/video",
                VIDEO,
                "/tmp/truthlens_latency_video_headers.txt",
                "/tmp/truthlens_latency_video_result.json",
            ),
        ),
    ]

    results = {}

    print("\nTruthLensAI Latency Benchmark")
    print("=" * 34)

    for name, test in tests:
        values = []

        for run_number in range(1, 4):
            print(f"{name.title()} run {run_number}/3...", end=" ", flush=True)

            start = time.perf_counter()

            try:
                value = test()
            except Exception as exc:
                print(f"FAILED: {exc}")
                continue

            wall_ms = (time.perf_counter() - start) * 1000

            # Prefer the server-side X-Process-Time-ms value.
            measured_ms = float(value)

            values.append(measured_ms)
            print(f"{measured_ms:.2f} ms (wall: {wall_ms:.2f} ms)")

        if values:
            results[name] = {
                "runs_ms": [round(v, 2) for v in values],
                "mean_ms": round(statistics.mean(values), 2),
                "median_ms": round(statistics.median(values), 2),
                "min_ms": round(min(values), 2),
                "max_ms": round(max(values), 2),
            }

    output_file = OUTPUT_DIR / "latency_results.json"
    output_file.write_text(json.dumps(results, indent=2))

    print("\nSummary")
    print("-" * 34)

    for name, data in results.items():
        print(
            f"{name.title():<8} "
            f"mean={data['mean_ms']:.2f} ms  "
            f"median={data['median_ms']:.2f} ms"
        )

    print(f"\nSaved results to: {output_file}")


if __name__ == "__main__":
    main()
