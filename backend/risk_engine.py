def calculate_risk(signals):

    score = 0
    evidence = []

    # -------------------------
    # BASIC INDICATORS
    # -------------------------

    if signals["urls"]:
        score += 10
        evidence.append({
            "signal": "URL detected in message",
            "points": 10
        })

    if signals["upi_ids"]:
        score += 15
        evidence.append({
            "signal": "UPI ID detected in message",
            "points": 15
        })

    if signals["phone_numbers"]:
        score += 5
        evidence.append({
            "signal": "Phone number detected in message",
            "points": 5
        })

    # -------------------------
    # OTP / VERIFICATION
    # -------------------------

    if signals["otp_signals"]:
        score += 25
        evidence.append({
            "signal": "OTP or verification request detected",
            "points": 25
        })

    # -------------------------
    # URGENCY
    # -------------------------

    if signals["urgency_signals"]:
        score += 15
        evidence.append({
            "signal": "Artificial urgency detected",
            "points": 15
        })

    # -------------------------
    # PAYMENT
    # -------------------------

    if signals["payment_signals"]:
        score += 20
        evidence.append({
            "signal": "Payment-related request detected",
            "points": 20
        })

    # -------------------------
    # CREDENTIALS
    # -------------------------

    if signals["credential_signals"]:
        score += 20
        evidence.append({
            "signal": "Credential or sensitive login information requested",
            "points": 20
        })

    # -------------------------
    # PERSONAL INFORMATION
    # -------------------------

    if signals["personal_info_signals"]:
        score += 15
        evidence.append({
            "signal": "Personal or identity information requested",
            "points": 15
        })

    # -------------------------
    # BRAND / IMPERSONATION
    # -------------------------

    if signals["brand_signals"]:
        score += 10
        evidence.append({
            "signal": "Known organization or brand mentioned",
            "points": 10
        })

    # -------------------------
    # THREAT / ACCOUNT PRESSURE
    # -------------------------

    if signals["threat_signals"]:
        score += 20
        evidence.append({
            "signal": "Threat or account-pressure language detected",
            "points": 20
        })

    # -------------------------
    # AI ANALYSIS
    # -------------------------

    ai = signals.get("ai", {})

    if ai.get("scam_intent") is True:
        score += 10
        evidence.append({
            "signal": "AI detected likely scam intent",
            "points": 10
        })

    if ai.get("social_engineering") is True:
        score += 5
        evidence.append({
            "signal": "AI detected social-engineering behavior",
            "points": 5
        })

    if ai.get("impersonation") is True:
        score += 5
        evidence.append({
            "signal": "AI detected possible impersonation",
            "points": 5
        })

    if ai.get("financial_manipulation") is True:
        score += 5
        evidence.append({
            "signal": "AI detected financial manipulation",
            "points": 5
        })

    if ai.get("urgency") == "high":
        score += 5
        evidence.append({
            "signal": "AI detected high-pressure urgency",
            "points": 5
        })

    # -------------------------
    # VIRUSTOTAL
    # -------------------------

    vt_results = signals.get("virustotal", [])

    for vt in vt_results:

        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        # Strong external confirmation
        if malicious >= 10:
            score += 40
            evidence.append({
                "signal": f"VirusTotal strongly flagged URL as malicious ({malicious} engines)",
                "points": 40
            })

        elif malicious >= 3:
            score += 30
            evidence.append({
                "signal": f"VirusTotal flagged URL as malicious ({malicious} engines)",
                "points": 30
            })

        elif malicious > 0:
            score += 20
            evidence.append({
                "signal": f"VirusTotal flagged URL as malicious ({malicious} engines)",
                "points": 20
            })

        elif suspicious > 0:
            score += 15
            evidence.append({
                "signal": f"VirusTotal flagged URL as suspicious ({suspicious} engines)",
                "points": 15
            })

    # -------------------------
    # CROSS-SIGNAL CORROBORATION
    # -------------------------
    # Multiple independent systems
    # agreeing should increase confidence/risk.

    has_malicious_url = any(
        vt.get("malicious", 0) > 0
        for vt in vt_results
    )

    if has_malicious_url and ai.get("scam_intent") is True:
        score += 10
        evidence.append({
            "signal": "AI and VirusTotal independently confirmed scam risk",
            "points": 10
        })

    if has_malicious_url and ai.get("impersonation") is True:
        score += 5
        evidence.append({
            "signal": "Malicious URL combined with suspected impersonation",
            "points": 5
        })

    # -------------------------
    # CAP SCORE
    # -------------------------

    score = min(score, 100)

    # -------------------------
    # SEVERITY
    # -------------------------

    if score >= 80:
        severity = "CRITICAL"

    elif score >= 55:
        severity = "HIGH RISK"

    elif score >= 25:
        severity = "SUSPICIOUS"

    else:
        severity = "SAFE"

    # -------------------------
    # CONFIDENCE
    # -------------------------

    number_of_signals = len(evidence)
    ai_confidence = ai.get("confidence", "low")

    if ai_confidence == "high" or number_of_signals >= 5:
        confidence = "High"

    elif ai_confidence == "medium" or number_of_signals >= 2:
        confidence = "Medium"

    else:
        confidence = "Low"

    # -------------------------
    # THREAT TYPE
    # -------------------------

    if signals["otp_signals"] and signals["brand_signals"]:
        threat_type = "Bank / Account Impersonation"

    elif signals["otp_signals"]:
        threat_type = "OTP / Verification Scam"

    elif signals["upi_ids"] and signals["payment_signals"]:
        threat_type = "Payment Scam"

    elif signals["credential_signals"] and signals["brand_signals"]:
        threat_type = "Credential Phishing"

    elif signals["personal_info_signals"] and signals["brand_signals"]:
        threat_type = "Identity / KYC Scam"

    elif signals["urgency_signals"] and signals["payment_signals"]:
        threat_type = "Financial Social Engineering"

    elif signals["threat_signals"]:
        threat_type = "Threat / Account Scam"

    elif has_malicious_url:
        threat_type = "Malicious Link"

    elif signals["urls"]:
        threat_type = "Suspicious Link"

    elif ai.get("impersonation") is True:
        threat_type = "Possible Impersonation Scam"

    elif ai.get("financial_manipulation") is True:
        threat_type = "Financial Social Engineering"

    elif ai.get("social_engineering") is True:
        threat_type = "Social Engineering"

    elif ai.get("scam_intent") is True:
        threat_type = "Potential Scam"

    else:
        threat_type = "No Strong Threat Detected"

    # -------------------------
    # RECOMMENDATION
    # -------------------------

    if severity == "CRITICAL":
        recommendation = (
            "Do not click links, share OTPs, credentials, or make payments. "
            "Verify the sender through an official channel."
        )

    elif severity == "HIGH RISK":
        recommendation = (
            "Do not take the requested action until the sender and request "
            "are independently verified."
        )

    elif severity == "SUSPICIOUS":
        recommendation = (
            "Be cautious and verify the message before clicking links, "
            "sharing information, or making payments."
        )

    else:
        recommendation = (
            "No strong scam indicators were detected, but remain cautious "
            "with unexpected requests."
        )

    return {
        "risk_score": score,
        "severity": severity,
        "confidence": confidence,
        "threat_type": threat_type,
        "evidence": evidence,
        "recommendation": recommendation
    }