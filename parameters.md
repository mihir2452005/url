# URL Sentinel Scoring Parameters

This document outlines the numerical parameters, weights, and thresholds used by the URL Sentinel to determine the safety status of a URL.

## 1. Classification Thresholds
The final risk score ranges from **0 to 100**.

| Status | Score Range | Description |
| :--- | :--- | :--- |
| **🟢 SAFE** | **0 - 39** | Low risk. No significant threats detected. |
| **🟠 SUSPICIOUS** | **40 - 69** | Moderate risk. Some heuristics triggered (e.g., young domain, unusual lexical patterns). |
| **🔴 MALICIOUS** | **70 - 100** | High risk. Strong evidence of phishing, malware, or known threats. |

## 2. Feature Weights
The final score is a weighted sum of individual module scores.

### Primary Detection Modules
| Module | Weight | Impact Description |
| :--- | :--- | :--- |
| **Lexical Analysis** | **0.20** | URLs with suspicious patterns (IPs, typos, excessive length). |
| **Domain Analysis** | **0.30** | Domain age, reputation, and DNS health (New/expiring domains are risky). |
| **SSL/TLS Check** | **0.25** | Certificate validity and issuer trust. |
| **Content Analysis** | **0.15** | HTML content analysis (forms, hidden fields, obfuscation). |
| **AI Pattern Match** | **0.10** | Semantic similarity to known phishing signatures (RAG). |
| **Malicious File** | **0.40** | Detection of dangerous file types (e.g., `.exe`, `.py` download). |

### Advanced Detection Features
These features complement the primary modules.

| Feature | Weight | Impact Description |
| :--- | :--- | :--- |
| **Advanced Behavioral** | **0.12** | Suspicious browser behavior (e.g., anti-bot scripts). |
| **Advanced JavaScript** | **0.10** | Malicious JS patterns or obfuscated code. |
| **Advanced Certificate**| **0.09** | CA authority reputation and validity period anomalies. |
| **Advanced Heuristic** | **0.08** | Complex combination of risk factors. |
| **Advanced Lexical** | **0.08** | Deeper analysis of URL structure. |
| **Advanced Structural** | **0.07** | HTML structure anomalies. |
| **Advanced Domain** | **0.06** | Granular domain reputation checks. |
| **Advanced Content** | **0.05** | Text and keyword analysis. |

## 3. Scoring Logic
1.  **Individual Scoring**: Each module calculates a raw risk score (0-100).
2.  **Weighting**: Raw scores are multiplied by their respective weights defined in `config.py`.
3.  **Aggregation**: Weighted scores are summed up.
4.  **Capping**: The final score is capped at **100**.
5.  **Critical Overrides**: Certain high-confidence detections (like **EICAR** test files or **Phishing Pattern Clusters**) can override the score to **95+** immediately, bypassing the sum.

## 4. Trusted Domain Whitelist
URLs matching the following domains (and their subdomains) are automatically classified as **Safe (Score 0)**:
*   **Tech**: google.com, microsoft.com, apple.com, github.com, etc.
*   **Social**: facebook.com, twitter.com, linkedin.com, etc.
*   **Finance**: paypal.com, stripe.com, visa.com, etc.
*   **E-commerce**: amazon.com, ebay.com, etc.
