# 🛡️ TruthLensAI

Multimodal AI-Powered Threat Detection & Response Platform

Detect → Explain → Enrich → Investigate → Respond

TruthLensAI is a multimodal cybersecurity platform designed to detect and respond to modern digital scams across text, images, audio, and video.

The platform combines deterministic security signals, Hugging Face LLM analysis, OCR, audio processing, video multimodal fusion, VirusTotal threat intelligence, community intelligence, forensic evidence, and automated incident response.

Instead of stopping at a simple "Safe / Scam" prediction, TruthLensAI connects detection with explanation, investigation, and response.

---

## 🌐 Live Demo

Security Dashboard:
https://truthlensai-dashboard.onrender.com

Telegram Bot:
@TruthLensAI_bot

---

## 🚨 Problem

Modern scams are no longer limited to plain text or malicious URLs.

Attackers increasingly use:

• Phishing messages and malicious links
• Fake screenshots and visual impersonation
• Voice and audio-based social engineering
• Deceptive videos containing both visual and spoken signals
• Urgency, credential requests, payment manipulation, and impersonation

Many existing solutions focus on a single modality or provide only a simple binary classification without enough evidence, context, or response capability.

This creates a gap between:

Detecting a threat

and

Understanding, investigating, and responding to the threat.

---

## 💡 Solution

TruthLensAI provides a unified multimodal threat detection and response pipeline.

A suspicious input is routed to the appropriate modality-specific analysis pipeline. Deterministic security signals and AI reasoning are combined, relevant indicators are enriched using external and community threat intelligence, and the result is converted into an explainable security assessment.

For actionable threats, the workflow can continue through:

Forensic Evidence → Incident Response → IOC Blocking → STIX 2.1 Export

---

## ✨ Key Features

### 🔎 Multimodal Threat Detection

TruthLensAI supports:

• Text
• URLs / Domains
• Images / Screenshots
• Audio / Voice
• Video

Each modality follows an appropriate processing pipeline rather than forcing all inputs through a single detection method.

### 🧠 Hybrid AI + Deterministic Detection

TruthLensAI combines:

• Deterministic security signals
• Hugging Face LLM analysis
• Risk scoring
• Severity assessment
• Confidence estimation
• Threat classification

The AI model is combined with deterministic security signals instead of being treated as the only source of truth.

### 🎬 Video Multimodal Fusion

Video analysis combines multiple sources of evidence:

Visual Frame Analysis + Audio/Speech Analysis → Multimodal Fusion → Combined Threat Assessment

This allows TruthLensAI to consider:

• What is shown
• What is spoken
• The combination of visual and audio/speech signals

### 🖼️ Image Intelligence

Images and screenshots are processed using OCR to extract embedded text and make that information available for downstream threat analysis.

This is useful for suspicious screenshots, impersonation, fake alerts, payment-related content, and other visual scam material.

### 🎧 Audio Intelligence

Audio / voice inputs are processed through:

• Audio processing
• librosa
• Speech / transcription analysis
• Deterministic security signals
• AI analysis

This allows spoken scam content and social-engineering signals to be incorporated into the threat assessment.

### 🌐 Threat Intelligence

TruthLensAI enriches detections using:

• VirusTotal
• Community Intelligence
• Indicator reputation
• Community reports
• Reputation / consensus context

This adds external context to the current scan instead of relying only on the content being analyzed.

### 📋 Explainable Security Results

Instead of returning only:

"Scam detected."

TruthLensAI provides:

• Risk Score
• Severity
• Confidence
• Threat Type
• Detected Signals
• AI Explanation
• Recommended Action

Users can understand why the system considers content suspicious and what they should do next.

### 🚨 Automated Incident Response

Actionable / high-confidence threats can continue into:

• Incident eligibility
• Evidence packaging
• Incident creation
• Investigation
• Resolution
• Evidence persistence
• Incident reporting

Incident lifecycle:

OPEN → INVESTIGATING → RESOLVED

### 🛡️ Security Response

TruthLensAI supports:

• IOC blocking
• STIX 2.1 export
• User feedback
• Interactive Telegram actions
• Incident response workflows

### 📑 Forensic Reporting

Structured evidence-backed reports can include:

• Incident ID
• Scan ID
• Risk Score
• Severity
• Confidence
• Threat Type
• Original Content
• Extracted Entities
• Detected Signals
• AI Analysis
• VirusTotal Results
• Recommendation

Reports are available through the security dashboard and incident email workflow.

---

## 🧬 Multimodal Processing

### 📝 Text Pipeline

Text / URL
↓
URL & Domain Extraction
↓
Deterministic Security Signals
↓
Hugging Face LLM Analysis
↓
Threat Intelligence
↓
Risk Assessment

### 🖼️ Image Pipeline

Image / Screenshot
↓
OCR
↓
Extracted Text + Visual Signals
↓
Deterministic Analysis + AI Analysis
↓
Risk Assessment

### 🎧 Audio Pipeline

Audio / Voice
↓
Audio Processing
↓
librosa
↓
Speech / Transcription Analysis
↓
Deterministic Analysis + AI Analysis
↓
Risk Assessment

### 🎬 Video Pipeline

Video
↓
Visual Frame Analysis
+
Audio Extraction
↓
librosa / Audio Processing
↓
Speech / Transcription Analysis
↓
Visual Signals + Audio/Speech Signals
↓
MULTIMODAL FUSION
↓
Combined Video Threat Assessment
↓
Risk Engine

---

## 🏗️ System Architecture

TruthLensAI connects user intake, event-driven orchestration, modality-specific analysis, hybrid AI and deterministic detection, threat intelligence, forensic reporting, and incident response into one integrated workflow.

Architecture:

[Architecture diagram will be added here]

Core Architecture Flow:

USER INPUT
↓
TELEGRAM
↓
n8n CLOUD ORCHESTRATION
↓
MODALITY ROUTING
↓
TEXT / IMAGE / AUDIO / VIDEO
↓
SPECIALIZED PROCESSING
↓
TRUTHLENSAI ANALYSIS ENGINE
↓
DETERMINISTIC SIGNALS + HUGGING FACE LLM
↓
RISK ENGINE
↓
VIRUSTOTAL + COMMUNITY INTELLIGENCE
↓
ENRICHED THREAT CONTEXT
↓
EXPLAINABLE RESULT
↓
FORENSIC EVIDENCE
↓
DASHBOARD / TELEGRAM
↓
INCIDENT RESPONSE
↓
IOC BLOCKING / STIX 2.1

---

## ⚙️ n8n Cloud Orchestration

n8n Cloud acts as the event-driven orchestration layer of TruthLensAI.

It coordinates:

• Telegram event intake
• Modality routing
• API coordination
• VirusTotal enrichment
• Community intelligence
• Scan result delivery
• Telegram callback actions
• Incident automation
• Scheduled scan re-scoring
• Evidence and reporting workflows

High-level workflow:

User Input
↓
n8n Routing
↓
TruthLensAI Analysis
↓
Threat Intelligence
↓
Explainable Result
↓
Incident Response

n8n connects the different parts of TruthLensAI into one event-driven security workflow.

---

## 🌐 Threat Intelligence

### VirusTotal

Relevant URLs and indicators can be submitted to VirusTotal and enriched with external reputation and detection results.

URL / Indicator
↓
Submit to VirusTotal
↓
Poll Analysis
↓
Reputation / Detection Results

### Community Intelligence

Indicators can be correlated with community reports to provide additional context.

Indicator
↓
Community Reports
↓
Reputation
↓
Consensus / Context

This helps determine whether an indicator has already been reported by the community and provides additional context around its reputation.

### Supabase Persistence

Supabase provides persistent storage for application data including:

• Scan records
• Evidence
• Threat indicators
• Incidents
• Feedback
• Community intelligence

---

## 📋 Explainability & User Interaction

TruthLensAI provides interactive security actions through Telegram.

Available actions:

🔎 Why Suspicious?
🛡️ What Should I Do?
✅ Mark Safe
🚨 Report Scam
📄 Full Report
✅ Correct
❌ Incorrect

### Why Suspicious?

Loads relevant scan evidence and provides:

• Detected signals
• AI explanation
• Supporting context

### What Should I Do?

Provides:

• Recommended action
• Severity
• Confidence
• Safety guidance

### Feedback

Users can indicate:

• Mark Safe
• Report Scam
• Correct
• Incorrect

These actions are routed through the existing n8n callback workflow.

---

## 🚨 Incident Response

When a threat is considered actionable, it can enter the incident workflow.

Threat Assessment
↓
Incident Eligibility
↓
Evidence Pack
↓
Incident Creation
↓
Investigation
↓
Resolution

Incident lifecycle:

OPEN → INVESTIGATING → RESOLVED

The incident workflow preserves the relevant security evidence and supports investigation and reporting.

---

## 📦 Evidence Pack

The evidence workflow can combine:

• Scan information
• Threat assessment
• Extracted indicators
• Detected signals
• AI analysis
• Threat intelligence
• Relevant evidence

This creates a structured evidence package for incident investigation and persistence.

---

## 📊 Security Dashboard

The Next.js / React dashboard provides a centralized security interface.

Major areas include:

• Overview
• New Scan
• Scan History
• Community Intelligence
• Incident Center
• Analytics
• Forensic Scan Reports

The dashboard provides analysts with visibility from initial detection through incident response.

---

## 🛡️ IOC Blocking

Malicious indicators can be acted upon through the response workflow.

Malicious URL / Domain
↓
Block IOC
↓
BLOCKED

IOC blocking connects detection and investigation to an actionable security response.

---

## 📡 STIX 2.1 Export

Threat indicators can be represented using STIX 2.1.

Threat Indicator
↓
STIX 2.1
↓
Threat Intelligence Sharing

STIX provides a standardized representation for sharing structured threat intelligence.

---

## 📧 Incident Reporting

High-confidence incidents can generate structured HTML incident reports.

Reports can contain:

• Incident overview
• Threat classification
• Risk and severity
• Evidence
• Extracted entities
• AI analysis
• VirusTotal intelligence
• Recommendation

The report is delivered through the configured incident email workflow.

---

## 🧰 Technology Stack

Frontend:
Next.js + React + TypeScript

Backend:
Python + FastAPI

AI:
Hugging Face LLM

Orchestration:
n8n Cloud

Image Processing:
OCR

Audio Processing:
librosa + faster-whisper

Video Processing:
Frame Analysis + Audio/Speech Analysis + Multimodal Fusion

Threat Intelligence:
VirusTotal + Community Intelligence

Database:
Supabase

User Interface:
Telegram Bot API

Deployment:
Render

Threat Sharing:
STIX 2.1

---

## 🔄 End-to-End Workflow

1. USER SUBMITS CONTENT

Telegram receives suspicious text, image, audio, or video.

2. n8n ROUTES THE INPUT

The workflow identifies the modality and selects the appropriate processing pipeline.

3. MODALITY-SPECIFIC PROCESSING

Text → URL/domain and content analysis

Image → OCR + visual analysis

Audio → audio processing + transcription

Video → visual frames + audio/speech + multimodal fusion

4. HYBRID THREAT ANALYSIS

Deterministic security signals
+
Hugging Face LLM analysis

5. RISK ASSESSMENT

Risk Score + Severity + Confidence + Threat Type

6. THREAT INTELLIGENCE

VirusTotal + Community Intelligence

7. EXPLAINABLE RESULT

Telegram and the dashboard receive evidence-backed results.

8. INCIDENT RESPONSE

Actionable threats can become persistent incidents.

9. SECURITY RESPONSE

IOC Blocking + STIX 2.1 Export

---

## 🧪 Evaluation

The project includes benchmark and calibration workflows used to evaluate detection behavior.

### Validated Benchmark Results

Accuracy: 95%

Precision: 100%

Recall: 90%

F1 Score: 94.74%

The project also includes dedicated detection calibration tests covering:

• Benign payment requests
• Scam scenarios without URLs
• Genuine malicious URLs
• Strong phishing/payment scams

---

## 📁 Project Structure

TruthLensAI/
│
├── backend/
│   ├── main.py
│   ├── detector.py
│   ├── risk_engine.py
│   ├── ai_analyzer.py
│   ├── audio_analyzer.py
│   └── ...
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── services/
│   └── ...
│
├── benchmark/
│
├── docs/
│   ├── architecture.png
│   ├── dashboard.png
│   ├── telegram.png
│   ├── forensic-report.png
│   ├── incident-center.png
│   └── n8n-workflow.png
│
├── n8n-workflow.json
├── n8n-community-test.json
├── PROJECT_HANDOFF.md
├── .gitignore
└── README.md

---

## 🖥️ Platform

### Telegram

Provides:

• Threat submission
• Scan results
• Explanations
• Recommendations
• User feedback
• Incident actions
• Full forensic report access

### Security Dashboard

Provides:

• Overview
• New Scan
• Scan History
• Community Intelligence
• Incident Center
• Analytics
• Forensic Scan Reports

---

## 🚀 Deployment

TruthLensAI is deployed using cloud-hosted services.

Telegram
↓
n8n Cloud
↓
Render
├── FastAPI Backend
└── Next.js / React Dashboard
↓
Supabase

External Services:

• Hugging Face
• VirusTotal

The production system is designed so the application does not depend on the local development machine for normal operation.

---

## 🔐 Security Considerations

Secrets and credentials should remain in environment variables and secure deployment configuration.

Never commit:

• API keys
• Database service-role credentials
• .env files
• Private credentials

The public repository should contain code and documentation, not secrets.

---

## 🔮 Future Scope

Potential future extensions include:

• Broader multimodal threat coverage
• Larger threat-intelligence knowledge bases
• Improved low-latency media processing
• Deeper analyst automation
• Expanded community-driven intelligence
• Additional deployment integrations
• Improved multimodal detection capabilities
• Wider real-world security integrations

---

## 🏆 Why TruthLensAI?

Traditional scam detection often answers:

"Is this suspicious?"

TruthLensAI aims to answer the bigger security question:

"Why is it suspicious, what evidence supports the assessment, what should I do, what intelligence is associated with it, and what can I do about the threat?"

The platform connects:

Multimodal Detection
+
Hybrid AI + Deterministic Signals
+
Threat Intelligence
+
Community Intelligence
+
Explainability
+
Forensic Evidence
+
Incident Response
+
IOC Blocking
+
STIX 2.1

into one connected security workflow.

TruthLensAI moves beyond simple classification toward an end-to-end threat detection and response platform.

---

## 💭 Core Differentiator

TruthLensAI does more than simply say whether something is a scam.

It:

Detects the threat
↓
Explains why it is suspicious
↓
Enriches the result with threat intelligence
↓
Provides forensic evidence
↓
Creates an incident when actionable
↓
Enables investigation
↓
Blocks malicious indicators
↓
Exports structured threat intelligence

This connects the full journey from detection to response in a single platform.

---

## 👥 Team

### Bug_Makers

Built for Decode SIH 2026.

---

## ⭐ Core Philosophy

DETECT
↓
EXPLAIN
↓
ENRICH
↓
INVESTIGATE
↓
RESPOND

TruthLensAI

From detecting a scam to understanding and responding to the threat.