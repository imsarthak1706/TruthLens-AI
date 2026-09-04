import csv
import sys
import time
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from main import process_text


DATASET = ROOT / "benchmark" / "text_heldout.csv"

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2


def predict_label(result: dict):
    """Map the existing production risk score to the benchmark label."""
    score = result.get("risk_score")

    if not isinstance(score, (int, float)):
        return "unknown"

    return "scam" if score >= 25 else "benign"


def is_ai_unavailable(result: dict) -> bool:
    """
    Detect the backend's explicit AI-unavailable fallback.
    This must NOT be counted as a benign prediction.
    """
    ai = result.get("ai_analysis") or {}

    return (
        ai.get("explanation") == "AI analysis unavailable."
        and ai.get("confidence") == "low"
    )


def analyze_with_retry(text: str):
    """
    Retry transient AI/backend failures.
    If AI remains unavailable, return a service-failure state
    instead of treating it as a real benign prediction.
    """
    last_result = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = process_text(text)
        except Exception as error:
            print(f"AI/BACKEND EXCEPTION: {type(error).__name__}: {error}")
            raise
        last_result = result

        if not is_ai_unavailable(result):
            return result, False

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY_SECONDS)

    return last_result, True


def main() -> None:
    if not DATASET.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET}")

    rows = []

    with DATASET.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        required = {"id", "language", "label", "text"}

        if not required.issubset(reader.fieldnames or set()):
            raise ValueError(
                f"CSV must contain: {', '.join(sorted(required))}"
            )

        for row in reader:
            if not any(row.values()):
                continue

            label = row["label"].strip().lower()

            if label not in {"scam", "benign"}:
                raise ValueError(
                    f"Invalid label for {row['id']}: {row['label']}"
                )

            rows.append(row)

    if not rows:
        raise ValueError("Dataset is empty.")

    tp = tn = fp = fn = 0
    skipped = 0

    by_language = {}

    print("\nTruthLensAI Text Benchmark")
    print("=" * 32)

    for row in rows:
        result, service_failure = analyze_with_retry(row["text"])

        actual = row["label"].strip().lower()
        score = result.get("risk_score")
        severity = result.get("severity")

        if service_failure:
            skipped += 1

            print(
                f"{row['id']:>10} | "
                f"actual={actual:<7} | "
                f"pred={'SKIPPED':<7} | "
                f"score={str(score):<3} | "
                f"AI SERVICE FAILURE"
            )

            continue

        predicted = predict_label(result)

        print(
            f"{row['id']:>10} | "
            f"actual={actual:<7} | "
            f"pred={predicted:<7} | "
            f"score={str(score):<3} | "
            f"{severity}"
        )

        if actual == "scam" and predicted == "scam":
            tp += 1

        elif actual == "benign" and predicted == "benign":
            tn += 1

        elif actual == "benign" and predicted == "scam":
            fp += 1

        elif actual == "scam" and predicted == "benign":
            fn += 1

        lang = row["language"].strip().lower()

        if lang not in by_language:
            by_language[lang] = Counter()

        by_language[lang][(actual, predicted)] += 1

    evaluated = tp + tn + fp + fn

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    accuracy = (
        (tp + tn) / evaluated
        if evaluated
        else 0.0
    )

    print("\n" + "=" * 32)
    print("Overall Results")
    print("=" * 32)

    print(f"Samples:           {len(rows)}")
    print(f"Evaluated:         {evaluated}")
    print(f"Skipped:           {skipped}")
    print(f"TP:                {tp}")
    print(f"TN:                {tn}")
    print(f"FP:                {fp}")
    print(f"FN:                {fn}")
    print(f"Accuracy:          {accuracy * 100:.2f}%")
    print(f"Precision:         {precision * 100:.2f}%")
    print(f"Recall:            {recall * 100:.2f}%")
    print(f"F1:                {f1 * 100:.2f}%")
    print(f"False Positive:    {false_positive_rate * 100:.2f}%")

    print("\nBy Language")
    print("=" * 32)

    for language, counts in sorted(by_language.items()):

        lang_tp = counts[("scam", "scam")]
        lang_tn = counts[("benign", "benign")]
        lang_fp = counts[("benign", "scam")]
        lang_fn = counts[("scam", "benign")]

        lang_precision = (
            lang_tp / (lang_tp + lang_fp)
            if (lang_tp + lang_fp)
            else 0.0
        )

        lang_recall = (
            lang_tp / (lang_tp + lang_fn)
            if (lang_tp + lang_fn)
            else 0.0
        )

        print(f"\n{language}")
        print(f"  TP: {lang_tp}")
        print(f"  TN: {lang_tn}")
        print(f"  FP: {lang_fp}")
        print(f"  FN: {lang_fn}")
        print(f"  Precision: {lang_precision * 100:.2f}%")
        print(f"  Recall:    {lang_recall * 100:.2f}%")


if __name__ == "__main__":
    main()