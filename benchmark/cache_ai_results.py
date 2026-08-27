import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DATASET = ROOT / "benchmark" / "text_benchmark.csv"
CACHE_DIR = ROOT / "benchmark" / "ai_cache"
CACHE_FILE = CACHE_DIR / "ai_results.json"
FAILURE_FILE = CACHE_DIR / "failures.json"

sys.path.insert(0, str(BACKEND))

from ai_analyzer import analyze_text


MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 8


def is_valid_result(result):
    if not isinstance(result, dict):
        return False

    if result.get("explanation") == "AI analysis unavailable.":
        return False

    return "scam_intent" in result and "confidence" in result


def main():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with DATASET.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    cache = {}

    if CACHE_FILE.exists():
        with CACHE_FILE.open("r", encoding="utf-8") as f:
            cache = json.load(f)

    failures = []

    print(f"Dataset samples: {len(rows)}")
    print(f"Already cached: {len(cache)}")
    print()

    for index, row in enumerate(rows, 1):
        sample_id = row["id"]

        if sample_id in cache:
            print(f"[{index}/{len(rows)}] {sample_id} → cached")
            continue

        success = False

        for attempt in range(1, MAX_RETRIES + 1):
            print(
                f"[{index}/{len(rows)}] "
                f"{sample_id} → AI attempt {attempt}/{MAX_RETRIES}",
                flush=True,
            )

            result = analyze_text(row["text"])

            if is_valid_result(result):
                cache[sample_id] = {
                    "id": sample_id,
                    "language": row["language"],
                    "label": row["label"],
                    "text": row["text"],
                    "ai_analysis": result,
                }

                with CACHE_FILE.open("w", encoding="utf-8") as f:
                    json.dump(cache, f, ensure_ascii=False, indent=2)

                success = True
                print("  → cached successfully", flush=True)
                break

            if attempt < MAX_RETRIES:
                print(
                    f"  → AI unavailable; waiting {RETRY_DELAY_SECONDS}s",
                    flush=True,
                )
                time.sleep(RETRY_DELAY_SECONDS)

        if not success:
            failures.append({
                "id": sample_id,
                "language": row["language"],
                "label": row["label"],
                "text": row["text"],
            })

            print(
                f"  → FAILED after {MAX_RETRIES} attempts",
                flush=True,
            )

        time.sleep(RETRY_DELAY_SECONDS)

    with FAILURE_FILE.open("w", encoding="utf-8") as f:
        json.dump(failures, f, ensure_ascii=False, indent=2)

    print()
    print("=" * 40)
    print("CACHE COMPLETE")
    print("=" * 40)
    print(f"Cached results: {len(cache)}")
    print(f"Failed samples: {len(failures)}")
    print(f"Cache file: {CACHE_FILE}")
    print(f"Failure file: {FAILURE_FILE}")


if __name__ == "__main__":
    main()