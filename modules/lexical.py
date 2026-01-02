import re
from collections import Counter
import math
from urllib.parse import urlparse
import unicodedata

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
    Analyzes URL for lexical phishing indicators with reduced false positives.
    Uses multi-condition validation similar to VirusTotal's approach.
    """
    risks = []
    score = 0
    
    parsed = urlparse(url)
    netloc = parsed.netloc or ''
    path = parsed.path or ''
    
    # Early legitimacy check - if matches known legitimate patterns, reduce sensitivity
    is_legit_pattern = is_likely_legitimate(url, netloc)
    sensitivity_multiplier = 0.5 if is_legit_pattern else 1.0
    
    # 1. IP Address Usage (High Risk) - but verify it's not localhost/private
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    if re.search(ip_pattern, netloc):
        # Check if it's a private/localhost IP (less risky)
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)', netloc):
            risks.append(('Private IP Address', 15, 'Uses private/localhost IP (dev/testing environment).'))
            score += 15
        else:
            risks.append(('Public IP Address URL', 70, 'URL uses raw public IP address instead of domain.'))
            score += 70

    # 2. URL Length & Structure - more nuanced scoring
    url_len = len(url)
    if url_len > 150:
        # Very long URLs are suspicious
        extra_score = min(50, 15 * ((url_len - 150) // 50))
        risks.append(('Excessive Length', 45 + extra_score, f'URL is {url_len} chars, often used to hide malicious content.'))
        score += (45 + extra_score)
    elif url_len > 100:
        # Moderately long - less penalty for legitimate sites
        weight = int(25 * sensitivity_multiplier)
        if weight > 0:
            risks.append(('Long URL', weight, f'URL is {url_len} chars, somewhat suspicious.'))
            score += weight
    
    # 3. Obfuscation Techniques - with context
    if '@' in netloc:
        # @ in netloc is almost always malicious
        risks.append(('Obfuscated Authority', 75, 'Uses "@" in domain to hide actual host.'))
        score += 75
        
    # Double slash in path - but allow it in query params
    if '//' in path and '?' not in url[:url.index('//') if '//' in url else 0]:
        weight = int(40 * sensitivity_multiplier)
        if weight > 0:
            risks.append(('Double Slash in Path', weight, 'Contains "//" in path, may indicate open redirect.'))
            score += weight
    
    # 4. Suspicious Keywords - only trigger if combined with other factors
    keywords = [
        'login', 'secure', 'account', 'verify', 'update', 'banking', 'confirm',
        'wallet', 'crypto', 'unlock', 'bonus', 'free', 'gift', 'prize'
    ]
    
    # Legitimate sites can have these keywords, so reduce weight significantly
    keyword_found = False
    leet_map = {'l': '1', 'e': '3', 'o': '0', 's': '5', 'a': '4', 'i': '1'}
    
    for kw in keywords:
        # Only flag if keyword + digit (more suspicious pattern)
        if re.search(rf'{kw}\d', url.lower()):
            weight = int(15 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Keyword Variation', weight, f'Suspicious keyword variation: {kw}.'))
                score += weight
                keyword_found = True
                break
        
        # Leetspeak is more suspicious
        pattern = ''.join(f'[{c}{leet_map[c]}]' if c in leet_map else c for c in kw)
        for match in re.finditer(pattern, url.lower()):
            if match.group() != kw:
                weight = int(45 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Leetspeak Typosquatting', weight, f'Detected leetspeak: {match.group()}.'))
                    score += weight
                    keyword_found = True
                    break
        if keyword_found:
            break
    
    # 5. Encoding & Special Characters - more intelligent detection
    encoded = sum(1 for c in url if c == '%')
    if encoded > 0:
        ratio = encoded / len(url)
        if ratio > 0.30:
            # Very high encoding is suspicious
            risks.append(('High Hex Encoding', 50, f'Heavy use of % encoding ({int(ratio*100)}%) to bypass filters.'))
            score += 50
        elif ratio > 0.20 and not is_legit_pattern:
            # Moderate encoding, only flag if not legitimate pattern
            weight = int(35 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Moderate Hex Encoding', weight, f'Notable % encoding ({int(ratio*100)}%).'))
                score += weight
    
    # 6. Subdomain Abuse - but many legitimate sites use multiple subdomains
    labels = [s for s in netloc.split('.') if s]
    subdomain_count = len(labels)
    if subdomain_count > 5:
        # 5+ subdomains is very suspicious
        risks.append(('Excessive Subdomains', 40, f'{subdomain_count} subdomain levels detected.'))
        score += 40
    elif subdomain_count > 3 and not is_legit_pattern:
        # 4 subdomains might be legitimate (e.g., cdn.assets.example.com)
        weight = int(20 * sensitivity_multiplier)
        if weight > 0:
            risks.append(('Many Subdomains', weight, f'{subdomain_count} subdomain levels.'))
            score += weight
    
    # 7. Entropy (Randomness) - with better thresholds
    chars = [c for c in netloc if c.isalnum()]  # Only check domain, not full URL
    if chars and len(chars) > 8:  # Need sufficient sample size
        freq = Counter(chars)
        total = len(chars)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values() if count > 0)
        
        # High entropy in domain name is very suspicious (DGA)
        if entropy > 4.8:
            risks.append(('Very High Entropy', 60, f'Domain has very random appearance (entropy: {entropy:.2f}).'))
            score += 60
        elif entropy > 4.5 and not is_legit_pattern:
            weight = int(35 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('High Entropy', weight, f'Domain appears random (entropy: {entropy:.2f}).'))
                score += weight
    
    # 8. Homograph / Punycode - strong indicator
    if 'xn--' in netloc:
        risks.append(('Punycode/IDN', 55, 'Uses Punycode (xn--) which can hide non-Latin characters.'))
        score += 55

    scripts = set()
    for char in netloc:
        try:
            name = unicodedata.name(char)
            script = name.split()[0]
            if script in ['LATIN', 'CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW']:
                scripts.add(script)
        except ValueError:
            pass
    
    if len(scripts) > 1:
        # Mixed scripts in domain is highly suspicious
        risks.append(('Homograph Attack', 70, f'Mixes character scripts ({scripts}) to spoof domains.'))
        score += 70
    
    # 9. Suspicious TLDs & Extensions - refined list and scoring
    # Some TLDs are heavily abused, others less so
    highly_suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']  # Free domains, very high abuse
    suspicious_tlds = ['.xyz', '.top', '.club', '.cn', '.zip', '.mov', '.work', '.click']
    
    url_lower = url.lower()
    if any(url_lower.endswith(tld) for tld in highly_suspicious_tlds):
        risks.append(('High-Risk TLD', 55, 'TLD is frequently abused (free domain service).'))
        score += 55
    elif any(url_lower.endswith(tld) for tld in suspicious_tlds) and not is_legit_pattern:
        weight = int(30 * sensitivity_multiplier)
        if weight > 0:
            risks.append(('Suspicious TLD', weight, 'TLD has elevated abuse rates.'))
            score += weight

    # Direct download links to executables - strong malware indicator
    if re.search(r'\.(exe|scr|bat|cmd|vbs|ps1)$', path, re.IGNORECASE):
        risks.append(('Executable Download', 65, 'Direct link to executable file.'))
        score += 65
    elif re.search(r'\.(zip|rar|7z|dmg|iso|bin|apk)$', path, re.IGNORECASE):
        # Archives are less suspicious but still notable
        weight = int(30 * sensitivity_multiplier)
        if weight > 0:
            risks.append(('Archive Download', weight, 'Direct link to archive file.'))
            score += weight

    # 10. Port Check - with more context
    if parsed.port:
        if parsed.port in [22, 23, 3389]:  # SSH, Telnet, RDP
            risks.append(('Remote Access Port', 45, f'Uses remote access port {parsed.port}.'))
            score += 45
        elif parsed.port not in [80, 443, 8080, 8443, 3000, 5000, 8000]:  # Common dev/web ports
            weight = int(40 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Non-Standard Port', weight, f'Uses unusual port {parsed.port}.'))
                score += weight

    # 11. Shorteners - strong obfuscation indicator
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'cli.gs',
        'ow.ly', 'buff.ly', 'adf.ly', 'bc.vc', 'soo.gd'
    ]
    if any(s in netloc.lower() for s in shorteners):
        risks.append(('URL Shortener', 50, 'Uses URL shortener to hide destination.'))
        score += 50

    # 12. Suspicious query redirect parameters - refined detection
    query = (parsed.query or '').lower()
    if query:
        redirect_params = ['redirect', 'redirect_uri', 'url', 'next', 'goto', 'dest', 'destination', 'continue', 'return']
        # Check if redirect param points to external domain
        if any(p + '=' in query for p in redirect_params):
            # Try to extract the redirect target
            redirect_suspicious = False
            for param in redirect_params:
                if param + '=' in query:
                    param_val = query.split(param + '=')[1].split('&')[0]
                    # If it looks like an external URL (has http or another domain)
                    if 'http' in param_val or '//' in param_val:
                        redirect_suspicious = True
                        break
            
            if redirect_suspicious:
                risks.append(('Open Redirect Risk', 40, 'Query contains redirect to external URL.'))
                score += 40
            elif not is_legit_pattern:
                weight = int(20 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Redirect Parameter', weight, 'Query has redirect parameter.'))
                    score += weight

    # 13. Suspicious character repetition - but be more selective
    if re.search(r'([/?&%._=-])\1{5,}', url):  # 5+ repetitions instead of 3
        risks.append(('Character Repetition', 30, 'Unusually repeated special characters.'))
        score += 30
    
    # 14. NEW PARAMETER: Mixed TLD Detection (legitimate + suspicious)
    # Detects patterns like .com.br.tk (mixing country code with free TLD)
    tld_parts = netloc.split('.')[-3:] if len(netloc.split('.')) >= 3 else []
    if len(tld_parts) >= 2:
        legitimate_cctlds = ['uk', 'au', 'ca', 'de', 'fr', 'br', 'in', 'jp']
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
        
        has_legit = any(tld in legitimate_cctlds for tld in tld_parts)
        has_suspicious = any(tld in suspicious_tlds for tld in tld_parts)
        
        if has_legit and has_suspicious:
            risks.append(('Mixed TLD Pattern', 65, 
                        f'Suspicious TLD combination: {"." + ".".join(tld_parts)}'))
            score += 65

    return score, risks