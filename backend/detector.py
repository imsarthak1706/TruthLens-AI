import re


def detect_signals(text: str):

    text = str(text)
    lower_text = text.lower()

    # -------------------------
    # URL DETECTION
    # -------------------------
    urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text,
        re.IGNORECASE
    )

    # -------------------------
    # UPI ID DETECTION
    # -------------------------
    upi_ids = re.findall(
        r"\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b",
        text
    )

    # -------------------------
    # PHONE NUMBER DETECTION
    # -------------------------
    phone_numbers = re.findall(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
        text
    )

    # -------------------------
    # EMAIL DETECTION
    # -------------------------
    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text
    )

    # -------------------------
    # OTP / VERIFICATION
    # -------------------------
    otp_keywords = [
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "verification",
        "verify",
        "security code",
        "authentication code"
    ]

    otp_signals = [
        word for word in otp_keywords
        if word in lower_text
    ]

    # -------------------------
    # URGENCY
    # -------------------------
    urgency_keywords = [
        "urgent",
        "urgently",
        "immediately",
        "right now",
        "act now",
        "hurry",
        "as soon as possible",
        "within 10 mins",
        "within 10 minutes",
        "within 5 mins",
        "within 5 minutes",
        "expires",
        "expire",
        "expiring",
        "limited time",
        "last chance"
    ]

    urgency_signals = [
        word for word in urgency_keywords
        if word in lower_text
    ]

    # -------------------------
    # PAYMENT
    # -------------------------
    payment_keywords = [
        "send money",
        "send rs",
        "send ₹",
        "transfer",
        "payment",
        "pay",
        "upi",
        "refund",
        "bank account",
        "account number",
        "credit card",
        "debit card",
        "transaction",
        "deposit",
        "cash"
    ]

    payment_signals = [
        word for word in payment_keywords
        if word in lower_text
    ]

    # -------------------------
    # CREDENTIAL / LOGIN
    # -------------------------
    credential_keywords = [
        "password",
        "passcode",
        "login",
        "log in",
        "username",
        "pin",
        "cvv",
        "card number",
        "credentials"
    ]

    credential_signals = [
        word for word in credential_keywords
        if word in lower_text
    ]

    # -------------------------
    # PERSONAL INFORMATION
    # -------------------------
    personal_info_keywords = [
        "aadhaar",
        "aadhar",
        "pan card",
        "pan number",
        "date of birth",
        "dob",
        "address",
        "bank details",
        "personal details"
    ]

    personal_info_signals = [
        word for word in personal_info_keywords
        if word in lower_text
    ]

    # -------------------------
    # IMPERSONATION / BRAND
    # -------------------------
    brands = [
        "sbi",
        "hdfc",
        "icici",
        "axis bank",
        "paytm",
        "phonepe",
        "google pay",
        "gpay",
        "amazon",
        "flipkart",
        "income tax",
        "government",
        "police",
        "customs",
        "courier"
    ]

    brand_signals = [
        brand for brand in brands
        if brand in lower_text
    ]

    # -------------------------
    # THREAT / ACCOUNT PRESSURE
    # -------------------------
    threat_keywords = [
        "account blocked",
        "account suspended",
        "account will be blocked",
        "account will be suspended",
        "legal action",
        "police complaint",
        "arrest",
        "penalty",
        "fine",
        "blacklisted",
        "kyc expired",
        "kyc will expire"
    ]

    threat_signals = [
        word for word in threat_keywords
        if word in lower_text
    ]

    # -------------------------
    # RETURN ALL SIGNALS
    # -------------------------
    return {
        "urls": urls,
        "upi_ids": upi_ids,
        "phone_numbers": phone_numbers,
        "emails": emails,

        "otp_signals": otp_signals,
        "urgency_signals": urgency_signals,
        "payment_signals": payment_signals,

        "credential_signals": credential_signals,
        "personal_info_signals": personal_info_signals,

        "brand_signals": brand_signals,
        "threat_signals": threat_signals
    }