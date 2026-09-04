#!/usr/bin/env python3
"""
TruthLensAI Standalone 120-Sample Text Benchmark Evaluation Script

This script evaluates the exact TruthLensAI production text detection pipeline
against all 120 samples in benchmark/text_benchmark.csv.

Language breakdown:
- English: 40 (20 scam, 20 benign)
- Hindi: 40 (20 scam, 20 benign)
- Hinglish: 40 (20 scam, 20 benign)
Total: 120 (60 scam, 60 benign)

Usage:
  python3 evaluate_120_benchmark.py [--mode http|direct] [--url http://127.0.0.1:8000]
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List

# Paths
ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
DATASET_PATH = ROOT / "benchmark" / "text_benchmark.csv"
RESULTS_DIR = ROOT / "benchmark" / "results"
JSON_OUT_PATH = RESULTS_DIR / "120_sample_reproducible_result.json"
TXT_OUT_PATH = RESULTS_DIR / "120_sample_reproducible_result.txt"

# Ensure backend directory is in sys.path for direct mode
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def parse_args():
    parser = argparse.ArgumentParser(description="TruthLensAI 120-Sample Benchmark Evaluator")
    parser.add_argument(
        "--mode",
        choices=["auto", "http", "direct"],
        default="auto",
        help="Evaluation execution mode: 'http' (calls FastAPI POST /api/scan), 'direct' (calls process_text directly), 'auto' (checks http first, falls back to direct)"
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000",
        help="Base URL for FastAPI server in http mode (default: http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay in seconds between requests to avoid rate limits (default: 0.1)"
    )
    return parser.parse_args()


def check_http_server(base_url: str) -> bool:
    """Checks if the FastAPI server is reachable."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{base_url.rstrip('/')}/", headers={"User-Agent": "TruthLens-Benchmark"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def call_api_scan_http(text: str, base_url: str, max_retries: int = 3) -> Dict[str, Any]:
    """Sends text to POST /api/scan over HTTP."""
    import urllib.request
    url = f"{base_url.rstrip('/')}/api/scan"
    payload = json.dumps({"input": text, "platform": "web"}).encode("utf-8")

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "TruthLens-Benchmark/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                time.sleep(1.5 * attempt)

    raise RuntimeError(f"HTTP scan failed after {max_retries} attempts: {last_error}")


def call_api_scan_direct(text: str, max_retries: int = 3) -> Dict[str, Any]:
    """Calls process_text directly from backend.main."""
    from main import process_text

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            return process_text(text)
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                time.sleep(1.5 * attempt)

    raise RuntimeError(f"Direct process_text failed after {max_retries} attempts: {last_error}")


def classify_prediction(scan_res: Dict[str, Any]) -> str:
    """
    Determines model prediction using production severity and risk score.
    Returns: 'scam' or 'benign'.
    """
    severity = str(scan_res.get("severity", "")).upper()
    score = scan_res.get("risk_score", 0)

    # In TruthLensAI production risk engine:
    # Severity: CRITICAL (>=80), HIGH RISK (>=55), SUSPICIOUS (>=25), SAFE (<25)
    if severity in ("CRITICAL", "HIGH RISK", "SUSPICIOUS") or (isinstance(score, (int, float)) and score >= 25):
        return "scam"
    return "benign"


def compute_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, float]:
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "total": total,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2)
    }


def main():
    args = parse_args()

    print("=" * 80)
    print("TruthLensAI 120-Sample Text Benchmark Evaluation")
    print("=" * 80)

    if not DATASET_PATH.exists():
        print(f"Error: Dataset not found at {DATASET_PATH}")
        sys.exit(1)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Determine execution mode
    use_http = False
    method_name = ""

    if args.mode == "http":
        if not check_http_server(args.url):
            print(f"Error: HTTP mode selected but server at {args.url} is not responding.")
            print("Please ensure the backend is running (e.g. uvicorn main:app --port 8000)")
            sys.exit(1)
        use_http = True
        method_name = f"FastAPI HTTP (POST {args.url.rstrip('/')}/api/scan)"
    elif args.mode == "direct":
        use_http = False
        method_name = "Direct In-Process (main.process_text)"
    else:  # auto
        if check_http_server(args.url):
            use_http = True
            method_name = f"FastAPI HTTP (POST {args.url.rstrip('/')}/api/scan)"
        else:
            use_http = False
            method_name = "Direct In-Process (main.process_text) [Server not reachable at localhost:8000]"

    print(f"Dataset:     {DATASET_PATH}")
    print(f"Method:      {method_name}")
    print(f"Timestamp:   {datetime.now(timezone.utc).isoformat()}")
    print("-" * 80)

    # Read CSV
    samples = []
    with open(DATASET_PATH, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not any(row.values()):
                continue
            samples.append({
                "id": row["id"].strip(),
                "language": row["language"].strip().lower(),
                "expected": row["label"].strip().lower(),
                "text": row["text"].strip()
            })

    total_samples = len(samples)
    print(f"Loaded {total_samples} samples from CSV.")

    if total_samples != 120:
        print(f"Warning: Expected 120 samples, found {total_samples}.")

    # Evaluate samples
    results_list = []
    misclassifications = []

    # Counters
    lang_counts = {
        "english": {"tp": 0, "tn": 0, "fp": 0, "fn": 0},
        "hindi": {"tp": 0, "tn": 0, "fp": 0, "fn": 0},
        "hinglish": {"tp": 0, "tn": 0, "fp": 0, "fn": 0},
    }
    overall_counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    pred_dist = {"scam": 0, "benign": 0}

    print("\nRunning evaluation pipeline...")
    start_eval_time = time.time()

    for idx, sample in enumerate(samples, start=1):
        sid = sample["id"]
        lang = sample["language"]
        expected = sample["expected"]
        text = sample["text"]

        try:
            if use_http:
                scan_res = call_api_scan_http(text, args.url)
            else:
                scan_res = call_api_scan_direct(text)
        except Exception as e:
            print(f"\n[ERROR] Failed evaluating {sid}: {e}")
            sys.exit(1)

        predicted = classify_prediction(scan_res)
        score = scan_res.get("risk_score", 0)
        severity = scan_res.get("severity", "UNKNOWN")
        threat_type = scan_res.get("threat_type", "Unknown")

        pred_dist[predicted] += 1
        is_correct = (predicted == expected)

        # Update confusion matrices
        if expected == "scam" and predicted == "scam":
            overall_counts["tp"] += 1
            if lang in lang_counts:
                lang_counts[lang]["tp"] += 1
        elif expected == "benign" and predicted == "benign":
            overall_counts["tn"] += 1
            if lang in lang_counts:
                lang_counts[lang]["tn"] += 1
        elif expected == "benign" and predicted == "scam":
            overall_counts["fp"] += 1
            if lang in lang_counts:
                lang_counts[lang]["fp"] += 1
        elif expected == "scam" and predicted == "benign":
            overall_counts["fn"] += 1
            if lang in lang_counts:
                lang_counts[lang]["fn"] += 1

        res_entry = {
            "id": sid,
            "language": lang,
            "expected_label": expected,
            "predicted_label": predicted,
            "risk_score": score,
            "severity": severity,
            "threat_type": threat_type,
            "is_correct": is_correct,
            "text": text
        }
        results_list.append(res_entry)

        if not is_correct:
            misclassifications.append(res_entry)

        status_tag = "MATCH" if is_correct else "MISMATCH"
        print(f"[{idx:3d}/120] {sid:10s} | {lang:8s} | exp={expected:6s} | pred={predicted:6s} | score={score:3d} ({severity}) -> {status_tag}")

        if args.delay > 0 and idx < total_samples:
            time.sleep(args.delay)

    total_eval_duration = round(time.time() - start_eval_time, 2)
    print("-" * 80)
    print(f"Evaluation completed in {total_eval_duration}s.")

    # Calculate metrics
    overall_metrics = compute_metrics(**overall_counts)
    by_lang_metrics = {lang: compute_metrics(**counts) for lang, counts in lang_counts.items()}

    # Format Text Report
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("TruthLensAI 120-Sample Text Benchmark Evaluation Report")
    report_lines.append("=" * 80)
    report_lines.append(f"Evaluation Timestamp: {datetime.now(timezone.utc).isoformat()}")
    report_lines.append(f"Method Used:          {method_name}")
    report_lines.append(f"Dataset:              {DATASET_PATH}")
    report_lines.append(f"Evaluation Duration:  {total_eval_duration}s")
    report_lines.append("")

    report_lines.append("OVERALL")
    report_lines.append(f"Samples:                 {total_samples}")
    report_lines.append(f"Ground Truth:            60 Scam, 60 Benign")
    report_lines.append(f"Prediction Distribution: {pred_dist['scam']} Scam, {pred_dist['benign']} Benign")
    report_lines.append(f"TP:                      {overall_metrics['tp']}")
    report_lines.append(f"TN:                      {overall_metrics['tn']}")
    report_lines.append(f"FP:                      {overall_metrics['fp']}")
    report_lines.append(f"FN:                      {overall_metrics['fn']}")
    report_lines.append(f"Accuracy:                {overall_metrics['accuracy']:.2f}%")
    report_lines.append(f"Precision:               {overall_metrics['precision']:.2f}%")
    report_lines.append(f"Recall:                  {overall_metrics['recall']:.2f}%")
    report_lines.append(f"F1:                      {overall_metrics['f1']:.2f}%")
    report_lines.append("")

    for lang in ["english", "hindi", "hinglish"]:
        lm = by_lang_metrics[lang]
        report_lines.append(lang.upper())
        report_lines.append(f"Samples:    {lm['total']} (20 Scam, 20 Benign)")
        report_lines.append(f"TP:         {lm['tp']}")
        report_lines.append(f"TN:         {lm['tn']}")
        report_lines.append(f"FP:         {lm['fp']}")
        report_lines.append(f"FN:         {lm['fn']}")
        report_lines.append(f"Accuracy:   {lm['accuracy']:.2f}%")
        report_lines.append(f"Precision:  {lm['precision']:.2f}%")
        report_lines.append(f"Recall:     {lm['recall']:.2f}%")
        report_lines.append(f"F1:         {lm['f1']:.2f}%")
        report_lines.append("")

    report_lines.append(f"MISCLASSIFICATIONS ({len(misclassifications)} total)")
    if not misclassifications:
        report_lines.append("None (100% accuracy)")
    else:
        for m in misclassifications:
            report_lines.append(
                f"- [{m['id']}] ({m['language']}): expected {m['expected_label'].upper()} but predicted {m['predicted_label'].upper()} "
                f"(risk_score: {m['risk_score']}, severity: {m['severity']}, threat_type: {m['threat_type']})"
            )
            report_lines.append(f"  Text: \"{m['text'][:120]}\"")
    report_lines.append("")

    report_text = "\n".join(report_lines)
    print("\n" + report_text)

    # Save text report
    with open(TXT_OUT_PATH, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\nSaved text report to: {TXT_OUT_PATH}")

    # Prepare JSON Report
    json_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dataset": str(DATASET_PATH),
            "total_samples": total_samples,
            "method": method_name,
            "duration_seconds": total_eval_duration
        },
        "overall": {
            "total_samples": total_samples,
            "total_scam": 60,
            "total_benign": 60,
            "prediction_distribution": pred_dist,
            **overall_metrics
        },
        "by_language": by_lang_metrics,
        "misclassifications": misclassifications,
        "samples": [
            {
                "id": r["id"],
                "language": r["language"],
                "expected_label": r["expected_label"],
                "predicted_label": r["predicted_label"],
                "risk_score": r["risk_score"],
                "severity": r["severity"],
                "threat_type": r["threat_type"],
                "is_correct": r["is_correct"]
            }
            for r in results_list
        ]
    }

    with open(JSON_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"Saved JSON report to: {JSON_OUT_PATH}")


if __name__ == "__main__":
    main()
