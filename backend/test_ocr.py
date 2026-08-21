from image_analyzer import extract_text_from_image
from ai_analyzer import analyze_text
import json

# Step 1: OCR
text = extract_text_from_image(
    "/Users/sarthak/Downloads/scam_imgg.jpeg"
)

print("\n--- OCR RESULT ---\n")
print(text)

# Step 2: AI analysis
result = analyze_text(text)

print("\n--- AI ANALYSIS ---\n")
print(json.dumps(result, indent=2))