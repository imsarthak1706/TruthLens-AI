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
        # English
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "security code",
        "authentication code",

        # Hindi
        "सत्यापन कोड",
        "otp बताइए",
        "otp बताओ",
        "otp साझा करें",
        "otp साझा करो",

        # Hinglish
        "otp batao",
        "otp batayiye",
        "otp share karo",
        "otp share kijiye",
        "otp abhi share karo",
        "verification ke liye otp",
        "security verification ke liye otp",
        "verification ke liye otp share karo",
    ]

    otp_signals = [
        phrase for phrase in otp_keywords
        if phrase in lower_text
    ]

    # Generic "verify" alone must NOT trigger a strong OTP signal.
    contextual_verification_patterns = [
        # English
        "verify your otp",
        "verify otp",
        "verify the otp",
        "verify using otp",
        "verify with otp",
        "verify your password",
        "verify bank details",
        "verify your card details",
        "verify account details",

        # Hinglish
        "verification ke liye otp",
        "otp ke liye verification",
        "verify otp abhi",
        "otp verify karo",

        # Hindi
        "सत्यापन के लिए otp",
        "otp द्वारा सत्यापन",
        "otp से सत्यापन",
    ]

    contextual_verification_signals = [
        phrase
        for phrase in contextual_verification_patterns
        if phrase in lower_text
    ]

    for phrase in contextual_verification_signals:
        if phrase not in otp_signals:
            otp_signals.append(phrase)

    # -------------------------
    # URGENCY
    # -------------------------

    urgency_keywords = [
        # English
        "urgent",
        "urgently",
        "immediately",
        "right now",
        "act now",
        "hurry",
        "as soon as possible",
        "within 5 mins",
        "within 5 minutes",
        "within 10 mins",
        "within 10 minutes",
        "within 24 hours",
        "expires",
        "expire",
        "expiring",
        "limited time",
        "last chance",
        "tonight",
        "today",

        # Hindi
        "अभी करें",
        "तुरंत करें",
        "तुरंत भुगतान",
        "अभी भुगतान",
        "आज ही",
        "तुरंत साझा",
        "तुरंत बताइए",
        "तुरंत बताओ",
        "अभी पूरा करें",
        "अभी जमा करें",
        "अभी ट्रांसफर करें",
        "आज समाप्त",
        "आज समाप्त हो रहे",
        "आज बंद",
        "आज रात",

        # Hinglish
        "abhi share karo",
        "abhi share kijiye",
        "abhi karo",
        "turant karo",
        "turant pay karo",
        "turant share karo",
        "immediately karo",
        "aaj hi",
        "24 ghante mein",
        "24 hours mein",
        "within 24 hours",
        "abhi complete karo",
        "abhi jama karo",
        "abhi transfer karo",
        "aaj expire",
        "aaj band",
        "aaj raat",
    ]

    urgency_signals = [
        phrase for phrase in urgency_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # PAYMENT
    # -------------------------

    payment_keywords = [
        # English
        "send money",
        "send rs",
        "send ₹",
        "transfer",
        "payment",
        "pay now",
        "pay here",
        "pay fee",
        "pay to",
        "must pay",
        "pay immediately",
        "payment request",
        "approve payment",
        "approve the payment",
        "approve request",
        "payment approve",
        "payment approval",
        "upi",
        "refund",
        "bank account",
        "account number",
        "credit card",
        "debit card",
        "transaction",
        "deposit",
        "cash",
        "fee",
        "processing fee",
        "security deposit",
        "customs fee",
        "registration fee",
        "clearance fee",

        # Hindi
        "भुगतान करें",
        "भुगतान करो",
        "भुगतान करें",
        "पैसे जमा करें",
        "पैसे जमा करो",
        "पैसे ट्रांसफर करें",
        "पैसे ट्रांसफर करो",
        "प्रोसेसिंग फीस",
        "प्रोसेसिंग शुल्क",
        "इनाम लेने के लिए फीस",
        "पुरस्कार लेने के लिए फीस",
        "फीस जमा करें",
        "फीस जमा करो",
        "शुल्क जमा करें",
        "शुल्क जमा करो",
        "शुल्क अभी जमा करें",
        "जुर्माना भरें",
        "जुर्माना भरना",
        "बकाया भुगतान",
        "बकाया भुगतान करें",
        "पंजीकरण शुल्क",
        "डिलीवरी के लिए शुल्क",

        # Hinglish
        "payment karo",
        "payment kijiye",
        "pay karo",
        "pay kijiye",
        "fee pay karo",
        "fee pay kijiye",
        "processing fee",
        "processing fee pay karo",
        "paise jama karo",
        "paise jama kijiye",
        "paise transfer karo",
        "fee bhejo",
        "prize claim karne ke liye fee",
        "registration fee pay karo",
        "customs fee pay karo",
        "clearance fee pay karo",
    ]

    payment_signals = [
        phrase for phrase in payment_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # CREDENTIAL / LOGIN
    # -------------------------

    credential_keywords = [
        # English
        "password",
        "passcode",
        "login",
        "log in",
        "username",
        "pin",
        "cvv",
        "card number",
        "credentials",
        "card details",
        "card information",

        # Hindi
        "पासवर्ड",
        "यूज़रनेम",
        "पिन",
        "गोपनीय जानकारी",
        "कार्ड की जानकारी",
        "कार्ड विवरण",
        "कार्ड डिटेल",

        # Hinglish
        "password batao",
        "password share karo",
        "login details",
        "bank password",
        "pin batao",
        "pin share karo",
        "card details share karo",
        "card information share karo",
    ]

    credential_signals = [
        phrase for phrase in credential_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # PERSONAL INFORMATION
    # -------------------------

    personal_info_keywords = [
        # English
        "aadhaar",
        "aadhar",
        "pan card",
        "pan number",
        "date of birth",
        "dob",
        "address",
        "bank details",
        "personal details",

        # Hindi
        "आधार",
        "पैन कार्ड",
        "पैन नंबर",
        "जन्म तिथि",
        "पता",
        "बैंक विवरण",
        "व्यक्तिगत जानकारी",
        "बैंक की जानकारी",

        # Hinglish
        "aadhaar details",
        "pan details",
        "bank details share karo",
        "personal details share karo",
        "bank details dekar",
    ]

    personal_info_signals = [
        phrase for phrase in personal_info_keywords
        if phrase in lower_text
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
        "courier",
        "bank",
    ]

    brand_signals = [
        brand for brand in brands
        if brand in lower_text
    ]

    # -------------------------
    # THREAT / ACCOUNT PRESSURE
    # -------------------------

    threat_keywords = [
        # English
        "account blocked",
        "account suspended",
        "account will be blocked",
        "account will be suspended",
        "account restricted",
        "account will be restricted",
        "card has been suspended",
        "card is suspended",
        "card will be blocked",
        "card has been blocked",
        "mobile number will be disconnected",
        "mobile number will be disabled",
        "legal action",
        "police complaint",
        "police notice",
        "arrest",
        "penalty",
        "fine",
        "blacklisted",
        "kyc expired",
        "kyc will expire",
        "kyc update is pending",
        "unusual activity",
        "electricity connection will be disconnected",
        "electricity connection will be cut",
        "connection will be disconnected",
        "service will be disconnected",

        # Hindi
        "खाता बंद हो जाएगा",
        "खाता ब्लॉक हो जाएगा",
        "खाता बंद कर दिया जाएगा",
        "खाता निलंबित",
        "खाता प्रतिबंधित",
        "बैंक खाता बंद",
        "कार्ड बंद हो जाएगा",
        "कार्ड ब्लॉक हो जाएगा",
        "कार्ड बंद है",
        "मोबाइल नंबर बंद हो जाएगा",
        "मोबाइल नंबर बंद कर दिया जाएगा",
        "बिजली कनेक्शन काट दिया जाएगा",
        "बिजली कनेक्शन बंद हो जाएगा",
        "कनेक्शन काट दिया जाएगा",
        "सेवा बंद हो जाएगी",
        "कानूनी कार्रवाई",
        "पुलिस शिकायत",
        "पुलिस नोटिस",
        "गिरफ्तारी",
        "जुर्माना",
        "केवाईसी समाप्त",
        "केवाईसी अपडेट नहीं हुआ",
        "केवाईसी समाप्त हो गया",
        "खाता प्रतिबंधित कर दिया जाएगा",

        # Hinglish
        "account block ho jayega",
        "account blocked ho jayega",
        "account band ho jayega",
        "account permanently band",
        "account permanently disabled",
        "account restricted",
        "card block ho jayega",
        "card blocked hai",
        "card suspend ho gaya",
        "mobile number disconnect ho jayega",
        "mobile number band ho jayega",
        "service band ho jayegi",
        "connection cut ho jayega",
        "connection disconnect ho jayega",
        "legal action hoga",
        "police complaint hogi",
    ]

    threat_signals = [
        phrase for phrase in threat_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # INVESTMENT / GUARANTEED RETURN
    # -------------------------

    investment_keywords = [
        # English
        "double your money",
        "double my money",
        "guaranteed returns",
        "guaranteed return",
        "guaranteed profit",
        "risk-free investment",
        "risk free investment",
        "instant profit",
        "quick profit",
        "invest now",
        "double your investment",

        # Hindi
        "पैसा दोगुना",
        "पैसे दोगुने",
        "पैसा दोगुना होगा",
        "पैसा बढ़ाने",
        "गारंटीड रिटर्न",
        "रिटर्न की गारंटी",
        "गारंटी वाला रिटर्न",
        "बिना जोखिम निवेश",
        "तुरंत मुनाफा",
        "निवेश करें",
        "निवेश योजना",
        "निवेश की योजना",

        # Hinglish
        "paisa double",
        "paise double",
        "money double",
        "guaranteed return",
        "guaranteed profit",
        "risk free investment",
        "invest karo",
        "paisa double karega",
        "money double karega",
    ]

    investment_signals = [
        phrase for phrase in investment_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # TECH SUPPORT / REMOTE ACCESS
    # -------------------------

    tech_support_keywords = [
        # English
        "technical support",
        "tech support",
        "remote access",
        "remote access tool",
        "remote access app",
        "remote desktop",
        "install this app",
        "install this software",
        "virus on your computer",
        "computer has a virus",
        "security software",
        "remote support",

        # Hindi
        "तकनीकी सहायता",
        "कंप्यूटर में वायरस",
        "कंप्यूटर में वायरस है",
        "रिमोट एक्सेस",
        "यह ऐप इंस्टॉल करें",
        "सॉफ्टवेयर इंस्टॉल करें",

        # Hinglish
        "technical support se",
        "tech support se",
        "remote access app",
        "remote access tool",
        "remote desktop",
        "computer mein virus hai",
        "computer mein virus",
        "app install karo",
        "software install karo",
        "remote support se",
    ]

    tech_support_signals = [
        phrase for phrase in tech_support_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # PRIZE / REWARD SCAM
    # -------------------------

    prize_keywords = [
        # English
        "you won a cash prize",
        "you won a prize",
        "cash prize",
        "claim your prize",
        "claim the prize",
        "processing fee",
        "reward claim",
        "reward points",
        "prize release",

        # Hindi
        "आपने लकी ड्रॉ जीता है",
        "आपने पुरस्कार जीता है",
        "नकद पुरस्कार",
        "पुरस्कार लेने के लिए",
        "इनाम लेने के लिए",
        "प्रोसेसिंग फीस जमा करें",
        "प्रोसेसिंग शुल्क जमा करें",
        "रिवॉर्ड पॉइंट",
        "इनाम मिला है",
        "पुरस्कार मिला है",

        # Hinglish
        "aapne prize jeeta hai",
        "aapne cash prize jeeta hai",
        "aapne fifty thousand rupees jeete hain",
        "prize claim karne ke liye",
        "processing fee pay karo",
        "cash prize jeeta hai",
        "prize release karne ke liye",
        "prize release",
        "reward points expire",
    ]

    prize_signals = [
        phrase for phrase in prize_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # KYC / ACCOUNT UPDATE
    # -------------------------

    kyc_keywords = [
        # English
        "kyc update",
        "kyc expired",
        "kyc has expired",
        "kyc verification",
        "update your kyc",
        "kyc update is pending",
        "account restriction",
        "account restricted",

        # Hindi
        "केवाईसी अपडेट",
        "केवाईसी सत्यापन",
        "केवाईसी समाप्त",
        "केवाईसी समाप्त हो गया",
        "केवाईसी अपडेट नहीं हुआ",
        "केवाईसी पूरा करें",

        # Hinglish
        "kyc update karo",
        "kyc verification",
        "kyc complete karo",
        "kyc update pending",
    ]

    kyc_signals = [
        phrase for phrase in kyc_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # REWARD / CARD EXPIRY
    # -------------------------

    reward_keywords = [
        # English
        "reward points are expiring",
        "reward points are expired",
        "reward points expire",
        "card rewards",
        "credit card rewards",

        # Hindi
        "रिवॉर्ड पॉइंट आज समाप्त",
        "रिवॉर्ड पॉइंट समाप्त",
        "क्रेडिट कार्ड के रिवॉर्ड",
        "कार्ड की जानकारी दें",

        # Hinglish
        "reward points expire",
        "reward points aaj expire",
        "card rewards expire",
    ]

    reward_signals = [
        phrase for phrase in reward_keywords
        if phrase in lower_text
    ]

    # -------------------------
    # BENIGN REPAYMENT SUPPRESSION
    # -------------------------

    benign_repayment_patterns = [
        "pay you back",
        "pay back",
        "will pay back",
        "pay tomorrow",
        "pay later",
        "repay you",
        "repay tomorrow",
        "wapas kar dunga",
        "waapis kar dunga",
        "lautaa dunga",
        "वापस कर दूंगा",
        "लौटा दूंगा",
    ]

    has_benign_repayment = any(
        phrase in lower_text for phrase in benign_repayment_patterns
    )
    if has_benign_repayment:
        has_corroborating_scam_signals = any([
            bool(urls),
            bool(upi_ids),
            bool(otp_signals),
            bool(urgency_signals),
            bool(credential_signals),
            bool(threat_signals),
            bool(investment_signals),
            bool(tech_support_signals),
            bool(prize_signals),
            bool(kyc_signals),
            bool(reward_signals),
        ])
        if not has_corroborating_scam_signals:
            payment_signals = []

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
        "threat_signals": threat_signals,
        "investment_signals": investment_signals,
        "tech_support_signals": tech_support_signals,
        "prize_signals": prize_signals,
        "kyc_signals": kyc_signals,
        "reward_signals": reward_signals,
    }