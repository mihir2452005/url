# URL Sentinel: Heuristic Malicious URL Analyzer

## Overview
Educational Flask app for static URL risk assessment. Analyzes structure, domain, SSL, and content using rules-based heuristics.

## Setup
1. pip install -r requirements.txt
2. flask run
3. Visit http://127.0.0.1:5000

## Usage
Submit URL; view risk score and explanations.

## Modules
- lexical.py: Parses obfuscation/typosquatting.
- domain.py: WHOIS/DNS checks.
- ssl_checker.py: Cert validation.
- content_analyzer.py: Static parse.
- scorer.py: Weighted aggregation.

## Testing
pytest tests/test_analyzer.py

## Educational Notes
Each check explains theory (e.g., young domains = phishing infra).
Extend: Add ML in scorer.py via scikit-learn.

License: MIT