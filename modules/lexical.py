import re
from collections import Counter
import math
from urllib.parse import urlparse
import unicodedata
from modules.rust_bridge import is_ip_address, count_special_chars, has_suspicious_keywords

def is_likely_legitimate(url, netloc):
    """Check if URL matches known legitimate patterns to reduce false positives."""
    from config import Config
    url_lower = url.lower()
    netloc_lower = netloc.lower()
    
    # Check against known legitimate patterns
    for pattern in Config.KNOWN_LEGITIMATE_PATTERNS:
        if pattern in url_lower or pattern in netloc_lower:
            return True
    
    # NEW: Enhanced educational institution detection
    # Check if domain has educational TLD AND educational keyword
    educational_tlds = ['.edu', '.ac.', '.edu.']
    has_edu_tld = any(tld in netloc_lower for tld in educational_tlds)
    
    if has_edu_tld:
        # If has educational TLD, it's very likely legitimate
        return True
    
    # Check for educational keywords in domain name
    if any(keyword in netloc_lower for keyword in Config.EDUCATIONAL_KEYWORDS):
        # Domain contains educational keyword, likely legitimate
        # But verify it's not phishing (e.g., not paypal-university.tk)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if not any(tld in netloc_lower for tld in suspicious_tlds):
            return True
    
    # NEW: Check for subdomains of known legitimate domains
    # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
    for trusted_domain in Config.TRUSTED_DOMAINS:
        if netloc_lower.endswith('.' + trusted_domain.lower()) or netloc_lower == trusted_domain.lower():
            return True
    
    return False

def lexical_risk(url):
    """
    Enhanced lexical analysis with improved Layer 1 static analysis detection.
    Implements comprehensive checks for IP addresses, double extensions, entropy, keyword stuffing, and homograph attacks.
    """
    try:
        risks = []
        score = 0
        
        parsed = urlparse(url)
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        
        # Early legitimacy check - if matches known legitimate patterns, reduce sensitivity
        is_legit_pattern = is_likely_legitimate(url, netloc)
        sensitivity_multiplier = 0.5 if is_legit_pattern else 1.0
        
        # 1. Enhanced IP Address Detection (Rust Accelerated)
        if is_ip_address(url):
            # Check if it's a private/localhost IP (less risky)
            if re.match(r'^(http://|https://)?(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)', netloc):
                risks.append(('Private IP Address', 15, 'Uses private/localhost IP (dev/testing environment).'))
                score += 15
            else:
                risks.append(('Public IP Address URL', 100, 'URL uses raw public IP address instead of domain - high risk.'))
                score += 100
        
        # 2. Enhanced Double Extension Detection
        # Check for dangerous double extensions in path
        dangerous_exts = ['exe', 'scr', 'bat', 'com', 'pif', 'cmd', 'vbs', 'js', 'jse', 'ws', 'wsf', 'msi', 'mht', 'mhtml', 'lnk']
        double_ext_pattern = r'\.({})\.({})'.format('|'.join(dangerous_exts), '|'.join(dangerous_exts + ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar']))
        double_matches = re.findall(double_ext_pattern, path.lower())
        if double_matches:
            for match in double_matches:
                ext_risk = 95
                score += ext_risk
                risks.append(('Dangerous Double Extension', ext_risk, f'Dangerous double file extension detected: .{match[0]}.{match[1]}'))
        
        # Check for any double extension (not just dangerous ones)
        general_double_ext = r'\.\w+\.\w+'  # Any double extension
        general_matches = re.findall(general_double_ext, path.lower())
        if general_matches and not double_matches:  # Only if not already caught by dangerous check
            for match in general_matches[:3]:  # Limit to first 3 matches
                ext_risk = 70
                score += ext_risk
                risks.append(('Double Extension', ext_risk, f'Double file extension detected: {match}'))
        
        # 3. Enhanced Entropy Calculation
        content_to_check = path + query
        chars = [c for c in content_to_check if c.isalnum()]  # Only alphanumeric for entropy calc
        if chars and len(chars) > 8:  # Need sufficient sample size
            freq = Counter(chars)
            total = len(chars)
            entropy = -sum((count / total) * math.log2(count / total) for count in freq.values() if count > 0)
            
            # Very high entropy in path/query is suspicious
            if entropy > 4.5:
                entropy_risk = min(90, max(40, int(entropy * 18)))
                score += entropy_risk
                risks.append(('Very High Entropy', entropy_risk, f'Very high randomness in URL path/query: {entropy:.2f}'))
            elif entropy > 3.8:
                entropy_risk = min(70, max(25, int(entropy * 15)))
                score += entropy_risk
                risks.append(('High Entropy', entropy_risk, f'High randomness in URL path/query: {entropy:.2f}'))
        
        # 4. Enhanced Keyword Stuffing Detection (Rust Accelerated)
        if has_suspicious_keywords(url):
            # We need to find WHICH keyword for the message, but usage is already flagged
            pass # Continue to detailed check for reporting
            
        security_keywords = ['login', 'secure', 'bank', 'account', 'signin', 'password', 'update', 'confirm', 
                           'verify', 'secure', 'official', 'ebay', 'paypal', 'amazon', 'apple', 'microsoft', 
                           'facebook', 'google', 'twitter', 'instagram', 'sbi', 'hdfc', 'icici', 'axis', 
                           'citibank', 'hsbc', 'chase', 'wellsfargo', 'bofa', 'santander', 'netflix', 'spotify', 
                           'adobe', 'office', 'microsoftonline', 'salesforce', 'zendesk', 'slack', 'dropbox', 
                           'onedrive', 'sharepoint', 'admin', 'webmail', 'owa', 'portal']
        
        # Count unique security keywords in URL
        found_keywords = [kw for kw in security_keywords if kw.lower() in url.lower()]
        unique_keywords = list(set(found_keywords))
        
        if len(unique_keywords) > 2:
            keyword_risk = min(80, len(unique_keywords) * 20)
            score += keyword_risk
            risks.append(('Keyword Stuffing', keyword_risk, f'Keyword stuffing detected: {", ".join(unique_keywords[:5])}{"..." if len(unique_keywords) > 5 else ""} ({len(unique_keywords)} unique keywords)'))
        
        # 5. Enhanced Percent Encoding Detection
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        if encoded_count > 2:
            ratio = encoded_count / len(url) if len(url) > 0 else 0
            if ratio > 0.25:
                encoding_risk = min(80, encoded_count * 10)
                score += encoding_risk
                risks.append(('Very High Encoding', encoding_risk, f'Very high percent encoding: {encoded_count} encoded chars ({ratio*100:.1f}%)'))
            elif ratio > 0.15:
                encoding_risk = min(60, encoded_count * 8)
                score += encoding_risk
                risks.append(('High Encoding', encoding_risk, f'High percent encoding: {encoded_count} encoded chars ({ratio*100:.1f}%)'))
            elif encoded_count > 5:
                encoding_risk = min(40, encoded_count * 6)
                score += encoding_risk
                risks.append(('Moderate Encoding', encoding_risk, f'Moderate percent encoding: {encoded_count} encoded chars'))
        
        # 6. Enhanced Subdomain Analysis
        labels = [s for s in netloc.split('.') if s]
        subdomain_count = len(labels)
        if subdomain_count > 5:
            subdomain_risk = min(70, (subdomain_count - 4) * 15)
            score += subdomain_risk
            risks.append(('Excessive Subdomains', subdomain_risk, f'Excessive subdomains: {subdomain_count} parts'))
        elif subdomain_count > 4 and not is_legit_pattern:
            weight = int(35 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Many Subdomains', weight, f'Many subdomains: {subdomain_count} parts'))
                score += weight
        
        # 7. Enhanced Long URL Check
        if len(url) > 4000:
            long_url_risk = 60
            score += long_url_risk
            risks.append(('Very Long URL', long_url_risk, f'Very long URL: {len(url)} chars'))
        elif len(url) > 2048:
            long_url_risk = 40
            score += long_url_risk
            risks.append(('Long URL', long_url_risk, f'Long URL: {len(url)} chars'))
        
        # 8. Enhanced Homograph Attack Detection
        homograph_chars = {
            # Cyrillic homographs
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'к': 'k', 'в': 'b', 'м': 'm',
            # Greek homographs
            'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'χ': 'x',
            # Other similar characters
            'і': 'i', 'ӏ': 'l', 'ј': 'j', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ԁ': 'd', 'ѕ': 's', 'ѓ': 'g',
        }
        
        homograph_matches = [(c, homograph_chars[c]) for c in url if c in homograph_chars]
        if homograph_matches:
            unique_chars = list(set([char for char, _ in homograph_matches]))
            homograph_risk = min(90, len(unique_chars) * 25)
            score += homograph_risk
            risks.append(('Homograph Attack', homograph_risk, f'Potential homograph attack characters: {unique_chars[:5]}{"..." if len(unique_chars) > 5 else ""}'))
        
        # 9. Character Repetition Detection
        repeat_pattern = r'(.)\1{5,}'  # 6+ consecutive identical characters
        repeat_matches = re.findall(repeat_pattern, netloc + path)
        if repeat_matches:
            repeat_risk = min(70, len(set(repeat_matches)) * 20)
            score += repeat_risk
            risks.append(('Character Repetition', repeat_risk, f'Excessive character repetition: {len(set(repeat_matches))} unique repeated characters'))
        
        # 10. Suspicious Patterns in Domain
        if re.search(r'[0-9]{4,}', netloc):  # 4+ consecutive digits in domain
            digit_seq_risk = 45
            score += digit_seq_risk
            risks.append(('Sequential Digits', digit_seq_risk, f'Consecutive digits in domain: {re.search(r"[0-9]{4,}", netloc).group()}'))
        
        # 11. Suspicious TLD Combinations (Enhanced)
        tld_parts = netloc.split('.')[-3:] if len(netloc.split('.')) >= 3 else []
        if len(tld_parts) >= 2:
            legitimate_cctlds = ['uk', 'au', 'ca', 'de', 'fr', 'br', 'in', 'jp', 'kr', 'cn', 'ru', 'nl', 'it', 'es', 'pl', 'se', 'no', 'dk']
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'work', 'click', 'stream', 'download', 'cricket', 'date', 'faith', 'review', 'science', 'site', 'space', 'tech', 'win']
            
            has_legit = any(tld in legitimate_cctlds for tld in tld_parts)
            has_suspicious = any(tld in suspicious_tlds for tld in tld_parts)
            
            if has_legit and has_suspicious:
                mixed_tld_risk = 75
                risks.append(('Mixed TLD Pattern', mixed_tld_risk, 
                            f'Suspicious TLD combination: {".".join(tld_parts)}'))
                score += mixed_tld_risk
        
        # 12. Enhanced Obfuscation Checks
        if '@' in netloc:
            # @ in netloc is almost always malicious
            risks.append(('Obfuscated Authority', 85, 'Uses "@" in domain to hide actual host - credential harvesting.'))
            score += 85
            
        # Double slash in path - but allow it in query params
        if '//' in path and '?' not in url[:url.index('//') if '//' in url else 0]:
            weight = int(50 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Double Slash in Path', weight, 'Contains "//" in path, may indicate open redirect.'))
                score += weight
        
        # Normalize to 0-100 scale
        score = min(100, score)
        
        return score, risks
    except Exception as e:
        # Return safe values in case of error
        return 0, [('Lexical Analysis Error', 0, f'Error analyzing URL: {str(e)[:50]}')]
