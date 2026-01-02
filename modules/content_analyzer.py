import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

# Global variable to store last soup object for advanced analysis
_last_soup = None

def get_last_soup():
    """Return the last parsed BeautifulSoup object for advanced analysis."""
    global _last_soup
    return _last_soup

def content_risk(url):
    """
    Static content analysis with reduced false positives.
    Enhanced to avoid flagging legitimate sites.
    """
    risks = []
    score = 0
    
    # Check if URL matches known legitimate patterns
    from config import Config
    
    # Check against trusted domains first
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower()
    if domain in [d.lower() for d in Config.TRUSTED_DOMAINS]:
        # Skip content analysis for trusted domains
        return 0, []
    
    # NEW: Enhanced legitimacy check for educational institutions
    is_legit = any(pattern in url.lower() for pattern in Config.KNOWN_LEGITIMATE_PATTERNS)
    
    # Check for educational TLDs and keywords
    educational_tlds = ['.edu', '.ac.', '.edu.']
    has_edu_tld = any(tld in domain for tld in educational_tlds)
    
    has_edu_keyword = any(keyword in domain for keyword in Config.EDUCATIONAL_KEYWORDS)
    
    # NEW: Check for subdomains of known legitimate domains
    # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
    is_trusted_subdomain = False
    for trusted_domain in Config.TRUSTED_DOMAINS:
        if domain.endswith('.' + trusted_domain) or domain == trusted_domain:
            is_trusted_subdomain = True
            break
    
    # If educational institution, apply very low sensitivity
    if has_edu_tld or (has_edu_keyword and is_legit) or is_trusted_subdomain:
        sensitivity_multiplier = 0.1  # Very lenient for educational sites
        is_legit = True  # Treat as legitimate
    elif is_legit:
        sensitivity_multiplier = 0.3  # Much more lenient for legitimate patterns
    else:
        sensitivity_multiplier = 1.0
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Store soup object globally for advanced analysis
        global _last_soup
        _last_soup = soup
        
        domain = urlparse(url).netloc
        
        # 1. Suspicious Forms - refined detection
        forms = soup.find_all('form')
        if forms:
            for form in forms:
                action = form.get('action', '')
                # Check if form posts to entirely different domain
                if action and action.startswith('http'):
                    action_domain = urlparse(action).netloc
                    if action_domain and action_domain != domain and domain not in action_domain:
                        # Posting to different domain is suspicious
                        weight = int(75 * sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('External Form Action', weight, f'Form posts to {action_domain}.'))
                            score += weight
                            break
        
        # 2. Insecure Password Fields - critical issue
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            if not url.startswith('https'):
                # Password over HTTP is very bad
                risks.append(('Insecure Password Field', 70, 'Password field on non-HTTPS page.'))
                score += 70
            
            # Hidden password fields are very suspicious
            for pw in password_inputs:
                style = pw.get('style', '').lower()
                if any(h in style for h in ['display:none', 'visibility:hidden', 'opacity:0']):
                    risks.append(('Hidden Password Field', 35, 'Hidden password input detected.'))
                    score += 35
                    break

        # 3. JavaScript Obfuscation & Behaviors - refined detection
        scripts = soup.find_all('script')
        dangerous_js_found = False
        for script in scripts:
            text = script.string or ''
            if not text:
                continue
            
            # High Entropy / Packed Code - more sophisticated check
            long_strings = re.findall(r'[a-zA-Z0-9]{60,}', text)
            if len(long_strings) > 10:  # Many long strings indicates packing
                char_count = len(text)
                unique = len(set(text))
                entropy_proxy = unique / char_count if char_count else 0
                if entropy_proxy < 0.08:  # Very low uniqueness = highly packed
                    weight = int(70 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Obfuscated JavaScript', weight, 'Highly packed/obfuscated code detected.'))
                        score += weight
                        dangerous_js_found = True
                        break
            
            # Dangerous Functions - context matters
            dangerous_patterns = ['eval(', 'unescape(', 'document.write(', 'innerHTML=']
            dangerous_count = sum(1 for p in dangerous_patterns if p in text)
            if dangerous_count >= 2:
                # Multiple dangerous functions is more suspicious
                weight = int(55 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Dangerous JS Functions', weight, 'Multiple risky functions (eval, document.write, etc.).'))
                    score += weight
                    dangerous_js_found = True
                    break
                
            # Right-Click Disable - minor indicator
            if not is_legit and ('event.button==2' in text or 'oncontextmenu' in text):
                weight = int(20 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Right-Click Disabled', weight, 'Script blocks right-click.'))
                    score += weight
                    break
        
        # 4. Iframe & Frame Injection - context matters
        iframes = soup.find_all('iframe')
        if len(iframes) > 0:
            # Check for suspicious iframe usage
            suspicious_iframes = 0
            for iframe in iframes:
                src = iframe.get('src', '')
                if 'data:text/html' in src or 'base64' in src:
                    # Embedded HTML iframe is very suspicious
                    weight = int(60 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Embedded HTML Iframe', weight, 'Iframe uses embedded/base64 HTML.'))
                        score += weight
                    suspicious_iframes += 1
                elif src and src.startswith('http'):
                    iframe_domain = urlparse(src).netloc
                    if iframe_domain != domain:
                        suspicious_iframes += 1
            
            # Multiple iframes from other domains can be suspicious
            if suspicious_iframes >= 3 and not is_legit:
                weight = int(30 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Multiple External Iframes', weight, f'{suspicious_iframes} iframes from external domains.'))
                    score += weight
            elif len(iframes) > 5 and not is_legit:
                # Many iframes, only flag if not legitimate
                weight = int(15 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Many Iframes', weight, f'Page has {len(iframes)} iframes.'))
                    score += weight

        # 5. Social Engineering Keywords - refined detection
        text = soup.get_text().lower()
        urgency_patterns = [
            r'verify.*account', r'update.*payment', r'suspended.*access', 
            r'unusual.*activity', r'confirm.*identity', r'click.*here.*secure',
            r'account.*locked', r'immediate.*action', r'expire.*today'
        ]
        
        # Count how many patterns match
        matches = sum(1 for p in urgency_patterns if re.search(p, text))
        if matches >= 3:
            # Multiple urgency patterns is very suspicious
            weight = int(50 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Social Engineering Lure', weight, f'{matches} urgency/threat patterns detected.'))
                score += weight
        elif matches >= 1 and not is_legit:
            # Single pattern, only flag for non-legitimate
            weight = int(25 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Urgency Language', weight, 'Text contains urgency/account threat language.'))
                score += weight
            
        # 6. External Resource Ratio - refined
        imgs = soup.find_all('img')
        if len(imgs) > 5:  # Need meaningful sample size
            external_imgs = sum(1 for img in imgs if img.get('src', '').startswith('http') and domain not in img.get('src', ''))
            external_ratio = external_imgs / len(imgs) if len(imgs) > 0 else 0
            
            if external_ratio > 0.9 and not is_legit:
                # Almost all images from external sources
                weight = int(25 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('High External Resources', weight, f'{int(external_ratio*100)}% images from foreign domains.'))
                    score += weight

        # 7. Meta Refresh / Auto-Redirect - refined
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.IGNORECASE)})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if content:
                # Check if it redirects to external domain
                if 'url=' in content.lower():
                    redirect_url = content.lower().split('url=')[1]
                    if redirect_url.startswith('http') and domain not in redirect_url:
                        # Redirects to external domain - suspicious
                        weight = int(45 * sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('External Meta Redirect', weight, 'Meta refresh redirects to external domain.'))
                            score += weight
                elif not is_legit:
                    weight = int(25 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Meta Refresh', weight, 'Page uses meta refresh tag.'))
                        score += weight

        # 8. JavaScript-based redirects - refined
        redirect_patterns = [
            r'window\.location\s*=\s*["\'][^"\']',
            r'location\.href\s*=\s*["\'][^"\']',
            r'location\.replace\(["\'][^"\']'
        ]
        redirect_matches = sum(1 for p in redirect_patterns if re.search(p, response.text))
        if redirect_matches >= 2 and not is_legit:
            # Multiple redirect methods
            weight = int(40 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Multiple JS Redirects', weight, 'Multiple JavaScript redirect methods found.'))
                score += weight
        elif redirect_matches == 1 and not is_legit:
            # Single redirect, less suspicious
            weight = int(20 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('JavaScript Redirect', weight, 'JavaScript performs redirection.'))
                score += weight

        # 9. Credential harvesting fields - refined scoring
        inputs = soup.find_all('input')
        sensitive_names = ['password', 'passwd', 'passcode', 'ssn', 'social', 'cvv', 'card', 'otp', 'token', 'pin']
        sensitive_count = sum(1 for inp in inputs if any(s in ' '.join([inp.get('name', ''), inp.get('type', ''), inp.get('placeholder', '')]).lower() for s in sensitive_names))
        
        if sensitive_count >= 4:
            # Many sensitive fields is very suspicious
            weight = int(55 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Multiple Sensitive Fields', weight, f'Form collects {sensitive_count} sensitive data types.'))
                score += weight
        elif sensitive_count >= 3 and not is_legit:
            # 3 fields, only flag for non-legitimate
            weight = int(35 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('Sensitive Data Collection', weight, f'Form collects {sensitive_count} sensitive data types.'))
                score += weight
    
    except Exception as e:
        risks.append(('Content Fetch Error', 10, f'Could not analyze content: {str(e)[:30]}'))
        score += 10
    
    return score, risks