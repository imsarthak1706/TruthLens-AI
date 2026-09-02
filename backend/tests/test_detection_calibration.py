import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
for p in (str(ROOT), str(BACKEND_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.main import process_text
from backend.detector import detect_signals


def test_benign_p2p_payment_request():
    """
    Issue #1: An ordinary personal reimbursement request must be classified as SAFE.
    """
    text = "Can you send me ₹500 for dinner? I'll pay you back tomorrow."
    
    # 1. Verify detector does not emit payment scam signals for benign repayment
    signals = detect_signals(text)
    assert signals["payment_signals"] == [], f"Expected empty payment_signals, got {signals['payment_signals']}"

    # 2. Verify end-to-end pipeline severity and threat type
    res = process_text(text)
    assert res["risk_score"] < 25, f"Expected risk_score < 25, got {res['risk_score']}"
    assert res["severity"] == "SAFE", f"Expected SAFE, got {res['severity']}"
    assert res["threat_type"] == "No Strong Threat Detected", f"Expected 'No Strong Threat Detected', got {res['threat_type']}"
    print("PASS: test_benign_p2p_payment_request")


def test_upi_refund_collect_scam_without_url():
    """
    Issue #2: UPI collect refund scam without a URL must NOT be classified as 'Malicious Link'.
    """
    text = "Your UPI refund is pending. Open this link and approve the payment request to receive the refund."
    
    res = process_text(text)
    assert res["threat_type"] != "Malicious Link", "Cannot classify as 'Malicious Link' when no URL exists in input"
    assert res["threat_type"] == "Payment Scam", f"Expected 'Payment Scam', got {res['threat_type']}"
    assert res["severity"] in ("SUSPICIOUS", "HIGH RISK", "CRITICAL"), f"Expected suspicious/high risk, got {res['severity']}"
    assert len(res["extracted_entities"]["urls"]) == 0, "Expected no extracted URLs"
    print("PASS: test_upi_refund_collect_scam_without_url")


def test_genuine_malicious_url():
    """
    Ensure genuine phishing links with extracted URLs are still classified as Malicious Link / Phishing.
    """
    text = "Your account is locked. Verify here: https://secure-bank-login.xyz/auth"
    
    res = process_text(text)
    assert res["threat_type"] in ("Malicious Link", "Credential Phishing"), f"Unexpected threat_type: {res['threat_type']}"
    assert res["risk_score"] >= 25, f"Expected risk_score >= 25, got {res['risk_score']}"
    assert len(res["extracted_entities"]["urls"]) == 1, "Expected 1 extracted URL"
    print("PASS: test_genuine_malicious_url")


def test_strong_phishing_payment_scam():
    """
    Ensure strong multi-vector phishing and payment scams remain high risk / critical.
    """
    text = (
        "URGENT: Your SBI bank account is suspended due to pending KYC. "
        "Pay Rs 500 penalty immediately at sbi-kyc-update.com/pay or account will be permanently closed today."
    )
    
    res = process_text(text)
    assert res["risk_score"] >= 80, f"Expected critical score >= 80, got {res['risk_score']}"
    assert res["severity"] == "CRITICAL", f"Expected CRITICAL, got {res['severity']}"
    assert res["threat_type"] in ("Payment Scam", "Credential Phishing", "Bank / Account Impersonation"), f"Unexpected threat_type: {res['threat_type']}"
    print("PASS: test_strong_phishing_payment_scam")


if __name__ == "__main__":
    test_benign_p2p_payment_request()
    test_upi_refund_collect_scam_without_url()
    test_genuine_malicious_url()
    test_strong_phishing_payment_scam()
    print("\nALL FOCUSED CALIBRATION REGRESSION TESTS PASSED CLEANLY!")
