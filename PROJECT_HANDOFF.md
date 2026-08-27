# TruthLensAI — Project Handoff

Last updated: 2026-08-27

## 1. PROJECT OVERVIEW

TruthLensAI is a multimodal scam detection system.

Core idea:

User sends suspicious text/image/audio/video
→ TruthLensAI analyzes multiple signals
→ produces risk score + severity + confidence + evidence + recommendation
→ Telegram delivers the result
→ community intelligence adds reputation/history
→ incident reporting creates a feedback loop.

Primary current integration:
- n8n
- Telegram
- Supabase
- TruthLensAI backend

---

# 2. CURRENT PROJECT STATUS

## WORKING / VERIFIED

### Text
- Scam detection ✅
- Deterministic signal detection ✅
- AI analysis via Hugging Face/Qwen ✅
- Risk scoring ✅
- Evidence generation ✅
- Recommendations ✅
- URL/entity extraction ✅

### URL intelligence
- VirusTotal URL analysis ✅
- VirusTotal malicious/suspicious scoring ✅
- Cross-signal corroboration with AI ✅

### Image
- Image scanning ✅
- OCR/frame/text analysis where implemented ✅
- ELA/forensic work exists but is not currently the priority

### Audio
- Whisper transcription ✅
- Hindi/Hinglish audio tested ✅
- Audio forensic analysis via Librosa ✅
- Pitch analysis ✅
- Spectral analysis ✅
- Telegram audio response ✅

Verified Hinglish/Hindi audio example:
- Transcript successfully extracted
- Risk score was high/critical
- Scam signals were detected

### Video
- Video metadata extraction ✅
- Frame sampling ✅
- OCR on sampled frames ✅
- Audio extraction ✅
- Whisper transcription ✅
- Audio forensics ✅
- Speech + on-screen text fusion ✅
- Hindi/Hinglish video tested ✅
- Telegram video response ✅

Verified video example:
- Risk Score: 100/100
- Severity: CRITICAL
- Confidence: High
- Threat: Credential Phishing / Social Engineering depending on run
- Speech + on-screen text analysis worked

---

# 3. N8N STATUS

Production workflow:
- `My workflow`
- Production workflow was previously kept untouched during Community Test modifications.

Test workflow:
- `My workflow - Community Test`
- Workflow ID: `kxurUwMHLrPuFoH9`

Community subworkflow:
- Earlier `Community Intelligence Test`
- It was inaccessible from the working n8n project scope.
- The community lookup was therefore implemented inline instead.
- Orphaned `Call 'Community Intelligence Test'` node was later removed.

Current community architecture:

Text / schedule path:
Code
→ Community Reputation Lookup
→ Build Community Intelligence
→ Risk Engine
→ Update a row
→ response builder
→ Telegram

Text path community lookup was also added:
HTTP Request3
→ Community Reputation Lookup (Text)
→ Build Community Intelligence (Text)
→ Send a text message

Production workflow was not modified during those changes.

IMPORTANT:
Do not redesign the working n8n workflow unless a specific issue requires it.

---

# 4. COMMUNITY INTELLIGENCE

Supabase view:
`community_indicator_reputation`

Known tested URL:
`http://amazon-account-verify.xyz/login`

Known result:
- report_count = 103

Verified behavior:
- known URL → community intelligence displayed ✅
- unknown URL → previously_reported=false / report_count=0 ✅
- no URL → safe path ✅
- Supabase error is distinguished from no-match ✅

Telegram community section currently displays:
- Indicator
- Previously reported
- Community reports
- First seen
- Last seen

Incident reporting:
- Reported incident successfully
- Email confirmation was successfully received
- This proves reporting flow is working ✅

Current remaining community upgrade:
Community WRITE-BACK / reputation feedback loop.

Target:

Scan
→ user reports
→ indicator stored/updated
→ report count increases
→ future scans see updated reputation

Start with URL/domain first.

---

# 5. BACKEND CURRENT ARCHITECTURE

Important files:

backend/
- main.py
- detector.py
- risk_engine.py
- ai_analyzer.py
- audio_transcriber.py
- audio_analyzer.py

Main text flow:

process_text()
→ deterministic detector
→ Hugging Face AI analysis
→ VirusTotal
→ combined signals
→ risk_engine.calculate_risk()
→ final result

Audio flow:
audio upload
→ transcription
→ process_text(transcript)
→ audio forensics
→ final result

Video flow:
video upload
→ metadata
→ frame sampling/OCR
→ audio extraction
→ transcription
→ multimodal analysis
→ final result

---

# 6. AI ANALYZER

AI model currently used:
`Qwen/Qwen3-8B`

AI output schema includes:
- scam_intent
- social_engineering
- impersonation
- financial_manipulation
- urgency
- confidence
- explanation
- threat_type

Important:
AI inference through Hugging Face sometimes fails during high-volume sequential benchmark calls.

Therefore:
DO NOT repeatedly hammer Hugging Face with full benchmark runs.

A local AI-result cache was created for benchmarking.

---

# 7. BENCHMARK STATUS

Benchmark files:

benchmark/
- text_benchmark.csv
- run_text_benchmark.py
- cache_ai_results.py
- run_cached_benchmark.py
- ai_cache/
  - ai_results.json
  - failures.json

Dataset:
120 total samples

Language distribution:
- English: 40
- Hindi: 40
- Hinglish: 40

Labels:
- Scam: 60
- Benign: 60

No duplicate IDs were found.

---

# 8. CURRENT 120-SAMPLE BENCHMARK RESULT

IMPORTANT:
This is a DEVELOPMENT benchmark, not a claim of real-world accuracy.

All 120 AI results were eventually cached successfully.

Current cached benchmark:

Evaluated: 120

TP: 56
TN: 60
FP: 0
FN: 4

Accuracy: 96.67%
Precision: 100.00%
Recall: 93.33%
F1: 96.55%
False Positive Rate: 0.00%

By language:

English:
- TP: 20
- TN: 20
- FP: 0
- FN: 0
- Precision: 100%
- Recall: 100%

Hindi:
- TP: 16
- TN: 20
- FP: 0
- FN: 4
- Precision: 100%
- Recall: 80%

Hinglish:
- TP: 20
- TN: 20
- FP: 0
- FN: 0
- Precision: 100%
- Recall: 100%

Current benchmark conclusion:
- English = strong
- Hinglish = strong
- Hindi = weakest remaining language
- False positives = 0%
- Do NOT endlessly tune against this dataset

---

# 9. IMPORTANT BACKEND IMPROVEMENTS ALREADY MADE

## Detector
Multilingual Hindi/Hinglish signals were added.

Added/expanded categories include:
- OTP / verification
- urgency
- payment
- credentials
- personal information
- threat/account pressure
- investment scam
- technical support / remote access
- prize/reward scam
- KYC/account update
- reward/card expiry

Generic `verify` was deliberately removed from the strong OTP signal so ordinary legitimate messages such as:
- attendance verification
- order verification

are not automatically treated as OTP scams.

## Risk engine
Added scoring for:
- prize/reward
- investment
- tech support
- KYC/account update
- reward/card expiry

Also fixed the AI-benign cap.

Old problem:
A confident AI `benign` response could cap the final risk score at 20 even when strong deterministic scam evidence existed.

New behavior:
AI-benign suppression is only applied when strong deterministic scam evidence is absent.

This improved the cached benchmark from:

90.60% accuracy
81.36% recall
89.72% F1

to:

96.58% accuracy
93.22% recall
92.73% F1

and then the complete 120-sample result became:

96.67% accuracy
93.33% recall
96.55% F1
100% precision
0% FPR

---

# 10. CURRENT STRONGEST PROJECT DIFFERENTIATORS

1. Multimodal scam detection
2. Hindi/Hinglish support
3. Speech + visual text fusion for videos
4. VirusTotal external intelligence
5. Community reputation intelligence
6. Incident reporting
7. Evidence-backed risk scoring
8. Telegram deployment
9. Community feedback/reputation potential

---

# 11. WHAT IS LEFT TO IMPLEMENT

## PRIORITY 1 — COMPLETE BENCHMARK PHASE
Current 120 benchmark is complete.

Do NOT keep endlessly tuning it.

Remaining:
- Review the 4 remaining false negatives
- Decide whether the remaining misses are worth one controlled fix
- Then LOCK the evaluation benchmark

Do not use the final evaluation set for repeated tuning.

---

## PRIORITY 2 — COMMUNITY WRITE-BACK

Build:

Detect
→ Report
→ Update community reputation
→ Future scan sees higher reputation

Start with:
- URL/domain only

Then later:
- phone
- UPI
- email

---

## PRIORITY 3 — REPUTATION HISTORY

Improve community intelligence from:

"103 reports"

toward:

- report count
- first seen
- last seen
- repeated offender
- emerging indicator
- threat category history

---

## PRIORITY 4 — FEEDBACK LOOP

Add:
- Correct result
- Incorrect result

Store against `scan_id`.

Potential future loop:

Detection
→ user feedback
→ stored examples
→ future model/detector improvement

---

## PRIORITY 5 — PRIVACY / RETENTION

Document what happens to:
- uploaded files
- transcripts
- OCR text
- incident evidence
- database records

Do not claim deletion or retention behavior unless actually implemented.

---

## PRIORITY 6 — LATENCY / COST

Measure:
- text scan time
- audio scan time
- video scan time
- VirusTotal lookup
- community lookup
- AI inference

Estimate/record AI cost where measurable.

---

## PRIORITY 7 — MEDIA FORENSICS POLISH

Potential:
- cleaner ELA presentation
- better OCR quality
- better forensic wording
- better audio manipulation explanation

Lower priority than community feedback loop.

---

## PRIORITY 8 — DISTRIBUTION

Optional later:
- WhatsApp
- Browser extension

Both should reuse the existing backend.

Do NOT build a second detection engine.

---

## PRIORITY 9 — FINAL UI / DASHBOARD

Planned for final stage.

Suggested dashboard:
- Risk score
- Severity
- Evidence
- AI analysis
- Community reputation
- Incident history
- Scan statistics
- Media analysis details

Do this near the final 4–5 days.

---

## PRIORITY 10 — WOW FEATURES

Only after the core is stable:
- real-time/live detection
- broader platform integration
- more advanced forensic analysis

Do not let these destabilize the current MVP.

---

# 12. RECOMMENDED FINAL ROADMAP

CURRENT
↓
120-sample benchmark ✅
↓
Review final 4 FN
↓
LOCK benchmark
↓
Community write-back
↓
Reputation/history
↓
User feedback loop
↓
Privacy + latency/cost
↓
Audio/video forensic polish
↓
WhatsApp / browser extension
↓
Final UI/dashboard
↓
Optional live detection

---

# 13. IMPORTANT ENGINEERING RULES

1. Do not modify the working n8n production workflow casually.
2. Keep backups before backend changes.
3. Make one controlled backend change at a time.
4. Use cached AI benchmark results for repeated evaluation.
5. Do not tune endlessly against the same evaluation dataset.
6. Do not claim benchmark accuracy as real-world accuracy.
7. Preserve the current multimodal pipeline while adding features.
8. Prefer backend reuse over creating separate platform-specific detection logic.

---

# 14. CURRENT IMMEDIATE NEXT ACTION

The next major product feature should be:

COMMUNITY WRITE-BACK

Target flow:

User scans suspicious content
→ sees community intelligence
→ clicks Report Incident
→ URL/domain is written/updated in Supabase
→ report count increases
→ future users receive stronger community intelligence

This is the next major step after the benchmark.

---

# 15. PROJECT PHILOSOPHY

TruthLensAI should become:

DETECT
+
EXPLAIN
+
CORROBORATE
+
REPORT
+
LEARN
+
WARN

The differentiator is not just "AI detects scams".

The goal is an explainable, multimodal, community-informed scam intelligence system.