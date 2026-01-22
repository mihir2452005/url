# Titan-Tier: Maximum Accuracy Parameters (The 99.9% Protocol)

To achieve maximum detection accuracy beyond the standard ~190 parameters, the "Titan" system must integrate these advanced forensic and behavioral indicators. These checks target sophisticated threat actors who use cloaking, fast-flux networks, and zero-day evasion techniques.

## 1. Network Forensics & Infrastructure (The "God's Eye" View)
These parameters analyze the physical and logical infrastructure hosting the URL.

| Parameter | Risk Score | Description |
| :--- | :--- | :--- |
| **DNSSEC Validation Failure** | 75 | Domain has DNSSEC enabled but validation fails (common in hijacked domains). |
| **BGP Prefix Hijacking** | 95 | The IP block hosting the domain was recently announced by a suspicious ASN or differs from historical routes. |
| **ASN Reputation Score** | Variable | Hosting provider's Autonomous System Number (ASN) has a high ratio of abuse reports (e.g., "Bulletproof" hosting). |
| **TTL Anomaly (Fast-Flux)** | 85 | DNS Time-To-Live (TTL) is extremely short (< 300s) with rapidly changing A-records (indicates botnet infrastructure). |
| **Certificate Transparency (CT) Void** | 90 | TLS certificate is NOT present in public CT logs (highly suspicious for valid CAs). |
| **"Let's Encrypt" Abuse Pattern** | 50 | Certificate is free (Let's Encrypt), issued < 24 hours ago, and used on a high-value target (e.g., "login-secure-bank"). |
| **MX Record Mismatch** | 60 | Domain claims to be a corporate entity (e.g., bank) but lacks valid MX (email) records or uses a free email provider. |
| **Domain Shadowing** | 80 | Subdomain points to a malicious IP while the root domain points to a legitimate IP (compromised legitimate site). |

## 2. Advanced Content Analysis (The "Microscope")
Deep inspection of the rendered page content to detect hidden threats.

| Parameter | Risk Score | Description |
| :--- | :--- | :--- |
| **Steganography Trigger** | 80 | Image files contain statistical anomalies suggesting hidden code or data (payload delivery via images). |
| **Zero-Width Obfuscation** | 90 | Text contains zero-width joiners/non-joiners to bypass keyword filters (e.g., "B&#8205;a&#8205;n&#8205;k"). |
| **CSS Exfiltration** | 85 | CSS rules that trigger network requests based on input values (captures keystrokes without JS). |
| **Font-Based Obfuscation** | 70 | Uses custom fonts to map random characters to readable text (e.g., typing "A" displays "B" visually). |
| **DOM Clobbering** | 75 | HTML markup designed to overwrite global JS variables (hijacking legitimate scripts). |
| **Favicon Hash Mismatch** | 90 | Site uses the favicon of a known brand (e.g., Google's "G") but is hosted on a different domain. |
| **Canvas Fingerprinting Code** | 60 | Scripts attempting to draw invisible canvas elements to uniquely identify the user/analyst. |

## 3. Behavioral & Client-Side Analysis (The "Psychologist")
Detecting how the page behaves when interacting with the client.

| Parameter | Risk Score | Description |
| :--- | :--- | :--- |
| **User-Agent Cloaking** | 95 | Server returns different content to a mobile UA vs. a desktop/bot UA (hiding phishing kit from analysts). |
| **Mouse-Tracking Evasion** | 85 | Page executes payloads ONLY after detecting human-like mouse movement (evading automated sandboxes). |
| **Time-Zone Mismatch** | 70 | Browser IP location (e.g., Russia) mismatches the claimed business Time-Zone (e.g., New York) in page defaults. |
| **Debugger Detection** | 90 | Scripts actively trying to detect if DevTools are open or if functions are hooked (anti-analysis). |
| **Back-Button Hijacking** | 65 | Modifies browser history state to prevent the user from navigating back to safety. |
| **Focus-Stealing** | 50 | Aggressively refocuses input fields or prevents tab switching. |

## 4. Visual AI & OCR (The "Visionary")
Using Computer Vision to "see" the page like a human.

| Parameter | Risk Score | Description |
| :--- | :--- | :--- |
| **Logo Spatial Analysis** | 80 | Detects brand logo placement in standard "login" positions (center/top-left) on unknown domains. |
| **Visual Structural Similarity** | 90 | The visual layout (SSIM score) matches a known target (e.g., Microsoft Login) > 95% despite different HTML code. |
| **OCR Keyword Extraction** | 75 | Text drawn inside images (immune to HTML filters) contains sensitive keywords like "Password", "SSN". |
| **Input Field Proximity** | 70 | Detects "Password" labels physically close to input fields in a layout that mimics legitimate sites. |

## Total Potential Parameters
Implementing all above adds **24** high-precision indicators, bringing the total system capability to **212+** distinct checks.
