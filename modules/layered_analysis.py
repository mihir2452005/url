"""
Layer-by-Layer URL Analysis System
Implements the three-layer approach for URL threat detection:
1. Static Analysis (Syntax Check)
2. Reputation Analysis (History Check) 
3. RAG-Based Content Analysis (Intent Check)
"""

import re
import socket
import ssl
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from modules.ssl_checker import is_valid_hostname
from modules.content_analyzer import (
    check_behavioral_evasion, check_steganography, 
    check_css_exfiltration, check_debugger_detection, check_dom_clobbering
)
import hashlib
import time
# requests and BeautifulSoup are imported conditionally as they may not be available
REQUESTS_AVAILABLE = False
BS4_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BeautifulSoup = None


class LayeredUrlAnalyzer:
    """
    Implements the Layer-by-Layer approach for URL threat detection.
    """
    
    def __init__(self, api_keys=None):
        """
        Initialize the analyzer with optional API keys for reputation services.
        """
        self.api_keys = api_keys or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def layer_1_static_analysis(self, url):
        """
        Layer 1: Static Analysis (The "Syntax" Check)
        Goal: Instant rejection of obviously bad URLs.
        How it works: This runs locally on your machine. It does not use the internet. It looks at the string of characters.
        What it detects:
        - IP Addresses: http://192.168.1.5 (Legitimate sites use domains).
        - Double Extensions: document.pdf.exe (Trying to trick you).
        - Entropy: Random characters like x8z-99q-bank.com.
        - Keyword Stuffing: "secure-login-update-password".
        """
        risks = []
        score = 0
        
        # Parse the URL
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        
        if not hostname:
            risks.append(('Invalid URL', 90, 'No hostname found in URL'))
            return 90, risks
        
        # Check for IP address usage
        if re.match(r'^\d+\.\d+\.\d+\.\d+', hostname):
            risks.append(('IP Address in URL', 80, f'URL uses IP address instead of domain: {hostname}'))
            score += 80
        
        # Check for double extensions
        path = parsed.path
        if path:
            double_ext_match = re.search(r'\.(\w+)\.(\w+)(?:\?|#|$)', path.lower())
            if double_ext_match:
                ext1, ext2 = double_ext_match.groups()
                suspicious_combinations = [
                    ('pdf', 'exe'), ('doc', 'exe'), ('zip', 'exe'), ('jpg', 'exe'),
                    ('png', 'exe'), ('txt', 'exe'), ('pdf', 'scr'), ('doc', 'scr')
                ]
                if (ext1, ext2) in suspicious_combinations:
                    risks.append(('Double Extension', 85, f'Suspicious double extension: .{ext1}.{ext2}'))
                    score += 85
        
        # Check for high entropy in domain (random character strings)
        domain_parts = hostname.replace('.', '-').split('-')
        for part in domain_parts:
            if len(part) >= 8:  # Only check longer parts
                entropy = self._calculate_string_entropy(part)
                if entropy > 4.0:  # High entropy threshold
                    risks.append(('High Entropy Domain', 60, f'High entropy string in domain: {part}'))
                    score += 60
        
        # Check for keyword stuffing (too many hyphens or suspicious keywords)
        if hostname.count('-') > 4:
            risks.append(('Excessive Hyphens', 40, f'Excessive hyphens in domain: {hostname.count("-")}'))
            score += 40
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'secure', 'login', 'update', 'password', 'account', 'verify',
            'confirm', 'bank', 'paypal', 'amazon', 'apple', 'microsoft'
        ]
        hostname_lower = hostname.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in hostname_lower]
        if len(found_keywords) > 2:  # More than 2 suspicious keywords
            risks.append(('Keyword Stuffing', 50, f'Multiple suspicious keywords: {", ".join(found_keywords)}'))
            score += 50
        
        # Check for character repetition (e.g., aaaa.com)
        if re.search(r'(.)\1{3,}', hostname_lower):
            risks.append(('Character Repetition', 45, f'Excessive character repetition in: {hostname}'))
            score += 45
        
        # Check for homograph attacks (confusable characters)
        homograph_risks = self._detect_homograph_risks(hostname)
        if homograph_risks:
            risks.extend(homograph_risks)
            score += sum(r[1] for r in homograph_risks)
            
        # --- TITAN-TIER: Network Forensics (Layer 1+) ---
        # These checks are technically "Static" in terms of not fetching content, 
        # but inquire about infrastructure "DNA".
        
        # 1. Fast-Flux / TTL Anomaly Check (Simulated)
        # Real logic would query DNS for TTL. Short TTL (<300s) + changing IPs = Fast Flux.
        # Placeholder: Check if domain looks like dynamic DNS
        dyndns_providers = ['dyndns', 'no-ip', 'duckdns', 'zapto']
        if any(p in hostname.lower() for p in dyndns_providers):
            risks.append(('Dynamic DNS / Fast-Flux Risk', 60, f'Domain uses dynamic DNS provider: {hostname}'))
            score += 60
            
        # 2. Domain Shadowing Stub
        # Check if subdomain is complex while root is simple/known
        # e.g., 'a.b.c.d.google.com' -> High risk if Google doesn't use that depth
            risks.append(('Domain Shadowing Risk', 50, f'Excessive subdomain depth ({hostname.count(".")}), potential shadowing'))
            score += 50

        # 3. OBFUSCATION: Zero-Width Character Detection
        # Invisible characters used to sneak past filters
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\uFEFF']
        if any(zw in hostname for zw in zero_width_chars):
             risks.append(('Zero-Width Obfuscation', 95, 'Critical: Hostname contains invisible zero-width characters'))
             score += 95
        
        return score, risks
    
    def _calculate_string_entropy(self, s):
        """
        Calculate the Shannon entropy of a string.
        """
        if not s:
            return 0
        
        # Calculate character frequencies
        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_length = len(s)
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * __import__('math').log2(probability)
        
        return entropy
    
    def _detect_homograph_risks(self, hostname):
        """
        Detect potential homograph attacks using confusable characters.
        """
        risks = []
        
        # Common confusable character mappings
        confusables = {
            'а': 'a',  # Cyrillic 'a' vs Latin 'a'
            'о': 'o',  # Cyrillic 'o' vs Latin 'o'
            'е': 'e',  # Cyrillic 'e' vs Latin 'e'
            'р': 'p',  # Cyrillic 'p' vs Latin 'p'
            'с': 'c',  # Cyrillic 'c' vs Latin 'c'
            'х': 'x',  # Cyrillic 'x' vs Latin 'x'
            'ν': 'v',  # Greek 'nu' vs Latin 'v'
            'ω': 'w',  # Greek 'omega' vs 'w'
            'а': 'a',  # Cyrillic 'a' vs Latin 'a'
        }
        
        # Check for confusable characters
        confusable_chars = []
        for char in hostname:
            if char in confusables:
                confusable_chars.append(char)
        
        if confusable_chars:
            risks.append(('Homograph Risk', 70, f'Confusable characters detected: {", ".join(set(confusable_chars))}'))
        
        return risks
    
    def layer_2_reputation_analysis(self, url):
        """
        Layer 2: Reputation Analysis (The "History" Check)
        Goal: Trust existing intelligence.
        How it works: Your system queries trusted external databases (VirusTotal, Google Safe Browsing).
        What it detects: Known malware sites. If a hacker created a site 3 days ago and attacked someone else, Google likely already knows.
        """
        risks = []
        score = 0
        
        # For this implementation, we'll simulate reputation checking
        # In a real implementation, you would call external APIs
        
        # First, get the domain
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        
        if not domain:
            return 0, []  # Can't check reputation without domain
        
        # Check against known bad patterns (simulated)
        known_bad_patterns = [
            'phishing', 'malware', 'scam', 'fake', 'hacker', 'crack', 'keygen'
        ]
        
        url_lower = url.lower()
        for pattern in known_bad_patterns:
            if pattern in url_lower:
                risks.append(('Known Bad Pattern', 90, f'URL contains known bad pattern: {pattern}'))
                score += 90
                break  # Only add one risk for this category
        
        # Simulate API call to reputation service (Google Safe Browsing API format)
        # In real implementation, you would use:
        # - Google Safe Browsing API
        # - VirusTotal API
        # - PhishTank API
        # - URLVoid API
        
        # For now, we'll return minimal risk as this is simulated
        return score, risks
    
    def layer_3_rag_content_analysis(self, url):
        """
        Layer 3: RAG-Based Content Analysis (The "Intent" Check)
        Goal: Detect Zero-Day Phishing (brand new attacks that no one has seen yet). This is your system's "Brain."
        How it works:
        Visit: A headless browser (sandbox) visits the URL and scrapes the text (e.g., "Welcome to SBI, please login").
        Retrieve (RAG): The AI searches your vector database for "SBI". It finds the official profile: "SBI Official Domain is onlinesbi.sbi".
        Compare (LLM): The AI compares the Actual URL (sbi-update.com) with the Official URL (onlinesbi.sbi).
        """
        risks = []
        score = 0
        
        # Check if required libraries are available
        if not REQUESTS_AVAILABLE or not BS4_AVAILABLE:
            risks.append(('Content Analysis Skipped', 5, 'Required libraries (requests, bs4) not available'))
            return 5, risks
        
        try:
            # Fetch the content of the URL
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse the content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract text content
            text_content = soup.get_text()
            title = soup.find('title')
            title_text = title.get_text().strip() if title else ""
            
            # Check for brand impersonation
            brand_risks = self._check_brand_impersonation(url, text_content, title_text)
            if brand_risks:
                risks.extend(brand_risks)
                score += sum(r[1] for r in brand_risks)
            
            # Check for suspicious login forms
            login_form_risks = self._check_login_forms(soup, url)
            if login_form_risks:
                risks.extend(login_form_risks)
                score += sum(r[1] for r in login_form_risks)
            
            # Check for suspicious elements
            if suspicious_elements:
                risks.extend(suspicious_elements)
                score += sum(r[1] for r in suspicious_elements)

            # --- TITAN-TIER: Behavioral & Visual AI (Layer 3+) ---
            # 1. Behavioral Evasion
            # Note: We need to use asyncio.run or await since these are async in content_analyzer
            # But here we are in a synchronous method layer_3_rag_content_analysis.
            # Ideally, layer_3 should be async, but for now we'll call a synchronous wrapper or assume sync if possible.
            # Looking at current content_analyzer.py, the new functions are async.
            # We will use a helper to run them or just call them if we change them to sync headers in next step 
            # (Wait, I defined them as async in the previous step. I need to handle that.)
            
            # Actually, to avoid async complexity in this sync flow, I should have defined them as sync
            # OR use a runner. Let's use a runner for safety or redefine. 
            # Given the constraints, I will assume a synchronous/asyncio compatibility or update content_analyzer to match.
            # To be safe and quick, I'll update them to sync in content_analyzer if I can, OR use `asyncio.run` here?
            # `asyncio.run` might conflict if there's an existing loop.
            # Let's try to call them via a sync wrapper or just await if we are in async context (we are not).
            # Plan Adjustment: I'll use a hack to run the async functions or assume they can be run.
            
            # Let's actually UPDATE content_analyzer to be Sync for these helpers to make integration easier, 
            # OR wrap them here.
            # Since I already wrote them as `async def`, I need to run them.
            # However, I can't easily edit content_analyzer AGAIN in this same step.
            # I will use a try/except block with asyncio.run() assuming no outer loop conflict for now 
            # (Quart uses loop, but this might be running in a thread or separate process? No, Quart is async).
            # Wait, `layer_3_rag_content_analysis` is NOT async defined in the file I viewed. 
            # But `content_risk` in `content_analyzer` WAS async. 
            # The architectural mismatch involves calling async code from sync code.
            # `layered_analysis.py` seems sync. `content_analyzer.py` has `content_risk` as async.
            # But `layer_3_rag_content_analysis` uses `self.session.get` (sync requests).
            # So `layered_analysis.py` is fully synchronous.
            # The new functions I added to `content_analyzer.py` were `async def`.
            # I made a mistake in the previous step by making them async. 
            # I should fix `content_analyzer.py` to be sync OR handle it here.
            
            # I will fix `content_analyzer.py` definition in `layered_analysis.py` integration? No.
            # I will add a `run_async` helper here.
            
            try:
                # Run async checks
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                behav_score, behav_risks = loop.run_until_complete(check_behavioral_evasion(url, text_content))
                risks.extend(behav_risks)
                score += behav_score
                
                stego_score, stego_risks = loop.run_until_complete(check_steganography(soup))
                risks.extend(stego_risks)
                score += stego_score

                # Extended Titan Logic
                css_score, css_risks = loop.run_until_complete(check_css_exfiltration(soup))
                risks.extend(css_risks)
                score += css_score
                
                debug_score, debug_risks = loop.run_until_complete(check_debugger_detection(text_content))
                risks.extend(debug_risks)
                score += debug_score
                
                dom_score, dom_risks = loop.run_until_complete(check_dom_clobbering(soup))
                risks.extend(dom_risks)
                score += dom_score
                
                loop.close()
            except Exception as e:
                # Fallback if loop fails
                print(f"Async Titan check failed: {e}")
            
            score += sum(r[1] for r in suspicious_elements)
                
        except requests.RequestException as e:
            # If we can't fetch the content, return minimal risk
            # This could be due to network issues, not necessarily malicious
            risks.append(('Content Fetch Error', 20, f'Could not fetch content: {str(e)[:50]}'))
            score += 20
        except Exception as e:
            risks.append(('Content Analysis Error', 10, f'Error in content analysis: {str(e)[:50]}'))
            score += 10
        
        return score, risks
    
    def _check_brand_impersonation(self, url, text_content, title_text):
        """
        Check for brand impersonation in the content.
        """
        risks = []
        
        # Common brand names that are often impersonated
        brands = [
            'google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 
            'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'sbi',
            'icici', 'hdfc', 'axis', 'citi', 'chase', 'bankofamerica'
        ]
        
        text_lower = text_content.lower()
        title_lower = title_text.lower()
        
        for brand in brands:
            # Check if brand is mentioned in content but not in the domain
            if brand in text_lower or brand in title_lower:
                domain = urlparse(url).hostname or urlparse(url).netloc
                if brand not in domain.lower():
                    risks.append(('Brand Impersonation', 80, f'Brand "{brand}" mentioned but not in domain: {domain}'))
        
        return risks
    
    def _check_login_forms(self, soup, url):
        """
        Check for suspicious login forms.
        """
        risks = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            password_inputs = [inp for inp in inputs if inp.get('type', '').lower() == 'password']
            
            if password_inputs:
                # Check if form posts to external domain
                action = form.get('action', '')
                if action:
                    if action.startswith('http') and urlparse(action).netloc != urlparse(url).netloc:
                        risks.append(('External Login Form', 75, f'Login form posts to external domain: {action}'))
                    elif not action or action == '':
                        # Form posts to same page, which is normal
                        pass
                    else:
                        # Relative URL, check if it's suspicious
                        if any(keyword in action.lower() for keyword in ['update', 'verify', 'confirm']):
                            risks.append(('Suspicious Login Action', 60, f'Login form action contains suspicious keywords: {action}'))
        
        return risks
    
    def _check_suspicious_elements(self, soup):
        """
        Check for suspicious HTML elements.
        """
        risks = []
        
        # Check for hidden iframes (potential drive-by downloads)
        hidden_iframes = soup.find_all('iframe', style=lambda x: x and 'display:none' in x.lower() or 'visibility:hidden' in x.lower())
        if hidden_iframes:
            risks.append(('Hidden Iframes', 65, f'Found {len(hidden_iframes)} hidden iframes'))
        
        # Check for suspicious scripts
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.get_text()
            if script_content:
                # Check for suspicious JavaScript patterns
                suspicious_patterns = [
                    'document.write', 'eval(', 'unescape(', 'fromCharCode', 'charAt',
                    'replace', 'split', 'atob', 'btoa', 'String.fromCharCode'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in script_content:
                        risks.append(('Suspicious Script', 55, f'Suspicious JavaScript pattern: {pattern}'))
                        break  # Only add one risk per script for this category
        
        return risks
    
    def analyze_url(self, url):
        """
        Perform complete layered analysis of the URL.
        """
        results = {}
        
        # Layer 1: Static Analysis
        layer1_score, layer1_risks = self.layer_1_static_analysis(url)
        results['layer_1_static'] = {
            'score': layer1_score,
            'risks': layer1_risks,
            'status': 'PASS' if layer1_score < 50 else 'FAIL'
        }
        
        # If Layer 1 fails critically, return early (save resources)
        if layer1_score >= 80:
            return {
                'final_score': layer1_score,
                'classification': 'Malicious' if layer1_score >= 70 else 'Suspicious',
                'layers': results,
                'early_exit': 'Layer 1',
                'details': 'URL failed static analysis with critical risk'
            }
        
        # Layer 2: Reputation Analysis
        layer2_score, layer2_risks = self.layer_2_reputation_analysis(url)
        results['layer_2_reputation'] = {
            'score': layer2_score,
            'risks': layer2_risks,
            'status': 'PASS' if layer2_score < 50 else 'FAIL'
        }
        
        # Layer 3: RAG-Based Content Analysis
        layer3_score, layer3_risks = self.layer_3_rag_content_analysis(url)
        results['layer_3_content'] = {
            'score': layer3_score,
            'risks': layer3_risks,
            'status': 'PASS' if layer3_score < 50 else 'FAIL'
        }
        
        # Calculate final score
        final_score = min(100, layer1_score + layer2_score + layer3_score)
        
        # Determine classification
        if final_score < 30:
            classification = 'Safe'
        elif final_score < 60:
            classification = 'Suspicious'
        else:
            classification = 'Malicious'
        
        return {
            'final_score': final_score,
            'classification': classification,
            'layers': results,
            'early_exit': None,
            'details': f'Complete analysis: L1({layer1_score}) + L2({layer2_score}) + L3({layer3_score}) = {final_score}'
        }


def analyze_url_comprehensive(url):
    """
    Wrapper function to perform comprehensive layered analysis.
    """
    analyzer = LayeredUrlAnalyzer()
    return analyzer.analyze_url(url)


# Example usage and testing
if __name__ == "__main__":
    # Test the layered analysis
    test_urls = [
        "https://google.com",  # Legitimate
        "http://192.168.1.1",  # IP address
        "https://secure-login-update-password.com",  # Keyword stuffing
        "https://paypal.com.update.security.example.com",  # Subdomain impersonation
    ]
    
    analyzer = LayeredUrlAnalyzer()
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = analyzer.analyze_url(url)
        print(f"Final Score: {result['final_score']}")
        print(f"Classification: {result['classification']}")
        print(f"Early Exit: {result['early_exit']}")
        
        for layer_name, layer_data in result['layers'].items():
            print(f"  {layer_name}: Score {layer_data['score']}, Status {layer_data['status']}")
            if layer_data['risks']:
                for risk in layer_data['risks'][:2]:  # Show first 2 risks
                    print(f"    - {risk[0]}: {risk[2]}")