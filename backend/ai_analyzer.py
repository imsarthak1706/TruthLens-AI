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
    "explanation": "Short explanation."
}}

Rules:
- scam_intent: true or false
- social_engineering: true or false
- impersonation: true or false
- financial_manipulation: true or false
- urgency: low, medium, or high
- confidence: low, medium, or high
- explanation: maximum 20 words

Return the JSON immediately.
"""

    response = client.chat.completions.create(
        model="Qwen/Qwen3-8B",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        max_tokens=500,

        # Disable Qwen3 thinking/reasoning mode
        extra_body={
            "chat_template_kwargs": {
                "enable_thinking": False
            }
        }
    )

    message = response.choices[0].message

    # We only want the actual answer.
    content = message.content

    if not content:
        raise RuntimeError(
            "Hugging Face returned no JSON content."
        )

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
        raise RuntimeError(
            "AI response did not contain valid JSON.\n\n"
            f"Raw response:\n{content}"
        )

    json_text = match.group(0)

    try:
        result = json.loads(json_text)

    except json.JSONDecodeError as error:

        raise RuntimeError(
            f"Could not parse AI JSON: {error}\n\n"
            f"Raw response:\n{content}"
        )

    return result