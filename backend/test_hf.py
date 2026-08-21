import os
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()

token = os.getenv("HF_TOKEN")

if not token:
    raise RuntimeError("HF_TOKEN not found in .env")

client = InferenceClient(
    api_key=token
)

response = client.chat.completions.create(
    model="Qwen/Qwen3-8B",
    messages=[
        {
            "role": "user",
            "content": (
                "Analyze this message for scam intent: "
                "'Your bank account will be blocked today. "
                "Send money immediately to verify your account.' "
                "Reply with ONLY one short sentence explaining why it is suspicious."
            )
        }
    ],
    max_tokens=250,
)

message = response.choices[0].message

print(message.content or message.reasoning_content)