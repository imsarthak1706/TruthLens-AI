import os
import json
import re

from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()

token = os.getenv("HF_TOKEN")

if not token:
    raise RuntimeError("HF_TOKEN not found in .env")

client = InferenceClient(
    api_key=token
)


def analyze_text(text: str):

    prompt = f"""
You are the scam detection engine of TruthLensAI.

Analyze this message:

{text}

Return ONLY one valid JSON object.

Do not explain your reasoning.
Do not use markdown.
Do not use code fences.

Use exactly these fields:

{{
    "scam_intent": false,
    "social_engineering": false,
    "impersonation": false,
    "financial_manipulation": false,
    "urgency": "low",
    "confidence": "high",
    "explanation": "Short explanation.",
    "threat_type": "benign"
}}

Rules:
- scam_intent: true or false
- social_engineering: true or false
- impersonation: true or false
- financial_manipulation: true or false
- urgency: low, medium, or high
- confidence: low, medium, or high
- explanation: maximum 20 words

- threat_type must be exactly one of:
  malicious_link, credential_phishing, payment_scam, identity_scam,
  impersonation, social_engineering, malware, benign, unknown

- Do not classify based on keywords alone.
- Judge the complete context of the message.
- Words such as verify, payment, account, login, urgent, or link can appear in legitimate messages.
- threat_type must represent the primary threat.
- Use benign when there is no meaningful scam behavior.
- Use unknown when there is insufficient information to classify.

Return the JSON immediately.
"""

    try:
        for max_tokens in (1500, 3000):
            response = client.chat.completions.create(
                model="Qwen/Qwen3-8B",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=max_tokens,

                # Disable Qwen3 thinking/reasoning mode
                extra_body={
                    "chat_template_kwargs": {
                        "enable_thinking": False
                    }
                }
            )

            message = response.choices[0].message
            if message.content or getattr(response.choices[0], "finish_reason", None) != "length":
                break
    except Exception:
        return {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable."
        }

    # We only want the actual answer.
    content = message.content

    if not content:
        return {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable."
        }

    content = content.strip()

    # Remove accidental markdown fences.
    content = re.sub(
        r"```json\s*",
        "",
        content,
        flags=re.IGNORECASE
    )

    content = re.sub(
        r"```\s*",
        "",
        content
    )

    # Find JSON object.
    match = re.search(
        r"\{.*\}",
        content,
        re.DOTALL
    )

    if not match:
        return {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable."
        }

    json_text = match.group(0)

    try:
        result = json.loads(json_text)
    except json.JSONDecodeError:
        return {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable."
        }

    if not isinstance(result, dict):
        return {
            "scam_intent": False,
            "social_engineering": False,
            "impersonation": False,
            "financial_manipulation": False,
            "urgency": "low",
            "confidence": "low",
            "explanation": "AI analysis unavailable."
        }

    for key, default_value in {
        "scam_intent": False,
        "social_engineering": False,
        "impersonation": False,
        "financial_manipulation": False,
        "urgency": "low",
        "confidence": "low",
        "explanation": "AI analysis unavailable.",
        "threat_type": "unknown"
    }.items():
        if key not in result or result[key] is None:
            result[key] = default_value

    if result.get("urgency") not in ["low", "medium", "high"]:
        result["urgency"] = "low"

    if result.get("confidence") not in ["low", "medium", "high"]:
        result["confidence"] = "low"

    if not isinstance(result.get("explanation"), str) or not result["explanation"]:
        result["explanation"] = "AI analysis unavailable."

    return result