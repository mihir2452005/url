# URL Sentinel: Advanced Three-Layer URL Threat Detection System

## Overview
Advanced local URL threat detection system without external API dependencies. Implements a three-layer architecture for comprehensive URL analysis with machine learning integration.

## Three-Layer Architecture

### Layer 1: Static Analysis (The "Syntax" Check)
**Goal:** Instant rejection of obviously bad URLs.
**How it works:** Runs locally without internet, analyzes string patterns.
**What it detects:** IP addresses, double extensions, high entropy, keyword stuffing, homograph attacks.

### Layer 2: Reputation Analysis (The "History" Check)
**Goal:** Trust existing intelligence.
**How it works:** Uses ML models trained on organized datasets to identify known threats.
**What it detects:** Known malware sites, malicious patterns, EICAR test files, suspicious domains.

### Layer 3: Content Analysis (The "Intent" Check)
**Goal:** Detect Zero-Day Phishing attacks.
**How it works:** Analyzes webpage content, detects brand impersonation, suspicious forms, and malicious scripts.

## Setup
1. pip install -r requirements.txt
2. python app.py
3. Visit http://127.0.0.1:5000

## Usage
Submit URL; view risk score, classification, and detailed explanations.

## Modules
- lexical.py: Parses obfuscation/typosquatting (Layer 1).
- domain.py: WHOIS/DNS checks (Layer 1 & 2).
- ssl_checker.py: Cert validation (Layer 1).
- content_analyzer.py: Static content analysis (Layer 3).
- ml_model.py: Machine learning classification (Layer 2).
- malicious_file_detector.py: Malicious file detection (Layer 2).
- layered_analysis.py: Three-layer integrated analysis.
- combined_analyzer.py: ML + Rule-based integration.
- scorer.py: Weighted aggregation.

## Testing
pytest tests/test_analyzer.py

## Features
- Three-layer URL analysis (Static, Reputation, Content)
- SSL/TLS validation
- Lexical analysis
- Domain reputation checks
- Content analysis
- Machine learning integration
- Real-time scanning
- Detailed risk scoring
- EICAR test file detection
- Malicious file detection
- Phishing detection
- Advanced heuristics

## Architecture Details
For detailed information about the three-layer architecture, see [THREE_LAYER_ARCHITECTURE.md](THREE_LAYER_ARCHITECTURE.md).

## Educational Notes
Each check explains theory (e.g., young domains = phishing infra).
ML integration enhances detection accuracy and reduces false positives.

License: MIT