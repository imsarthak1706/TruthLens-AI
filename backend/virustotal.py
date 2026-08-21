import os
import base64
import requests

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY not found in .env")


def scan_url(url: str):

    headers = {
        "x-apikey": VT_API_KEY
    }

    # VirusTotal uses a URL-safe base64 identifier
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers,
        timeout=20
    )

    if response.status_code == 404:
        return {
            "status": "not_found",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    response.raise_for_status()

    data = response.json()

    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    return {
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }