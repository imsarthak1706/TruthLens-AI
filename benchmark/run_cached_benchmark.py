import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
CACHE_FILE = ROOT / "benchmark" / "ai_cache" / "ai_results.json"

sys.path.insert(0, str(BACKEND))

from detector import detect_signals
from risk_engine import calculate_risk


def classify(score):
    """Use the existing production threshold."""
    if not isinstance(score, (int, float)):
        return "unknown"

    return "scam" if score >= 25 else "benign"


def main():
    if not CACHE_FILE.exists():
        raise FileNotFoundError(
            f"Cache not found: {CACHE_FILE}"
        )

    with CACHE_FILE.open("r", encoding="utf-8") as f:
        cache = json.load(f)

    if not cache:
        raise ValueError("AI cache is empty.")

    tp = tn = fp = fn = 0
    by_language = {}

    print("\nTruthLensAI Cached Text Benchmark")
    print("=" * 40)

    for sample_id, item in cache.items():
        text = item["text"]
        actual = item["label"].strip().lower()
        language = item["language"].strip().lower()
        ai_result = item["ai_analysis"]

        # Run the CURRENT detector.
        signals = detect_signals(text)

        # Reuse cached AI output instead of calling Hugging Face.
        combined = {
            **signals,
            "ai": ai_result,
            "virustotal": [],
        }

        # Run the CURRENT risk engine.
        result = calculate_risk(combined)

        predicted = classify(result.get("risk_score"))

        print(
            f"{sample_id:>12} | "
            f"actual={actual:<7} | "
            f"pred={predicted:<7} | "
            f"score={result.get('risk_score'):<3} | "
            f"{result.get('severity')}"
        )

        if actual == "scam" and predicted == "scam":
            tp += 1

        elif actual == "benign" and predicted == "benign":
            tn += 1

        elif actual == "benign" and predicted == "scam":
            fp += 1

        elif actual == "scam" and predicted == "benign":
            fn += 1

        by_language.setdefault(language, Counter())
        by_language[language][(actual, predicted)] += 1

    evaluated = tp + tn + fp + fn

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

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

    print("\n" + "=" * 40)
    print("CACHED BENCHMARK RESULTS")
    print("=" * 40)

    print(f"Evaluated:        {evaluated}")
    print(f"TP:               {tp}")
    print(f"TN:               {tn}")
    print(f"FP:               {fp}")
    print(f"FN:               {fn}")
    print(f"Accuracy:         {accuracy * 100:.2f}%")
    print(f"Precision:        {precision * 100:.2f}%")
    print(f"Recall:           {recall * 100:.2f}%")
    print(f"F1:               {f1 * 100:.2f}%")
    print(f"False Positive:   {false_positive_rate * 100:.2f}%")

    print("\nBY LANGUAGE")
    print("=" * 40)

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