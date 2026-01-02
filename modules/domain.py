import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse

def is_known_legitimate_domain(netloc):
    """Check if domain matches known legitimate patterns."""
    from config import Config
    netloc_lower = netloc.lower()
    
    # Check against known patterns
    for pattern in Config.KNOWN_LEGITIMATE_PATTERNS:
        if pattern in netloc_lower:
            return True
    
    # NEW: Enhanced check for educational institutions
    # Educational TLDs are highly trusted
    educational_tlds = ['.edu', '.ac.', '.edu.']
    has_edu_tld = any(tld in netloc_lower for tld in educational_tlds)
    
    if has_edu_tld:
        return True
    
    # Check for educational keywords with legitimate TLDs
    if any(keyword in netloc_lower for keyword in Config.EDUCATIONAL_KEYWORDS):
        # Domain contains educational keyword
        # Verify it's not on a suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if not any(tld in netloc_lower for tld in suspicious_tlds):
            return True
    
    # NEW: Check for subdomains of known legitimate domains
    # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
    from config import Config
    for trusted_domain in Config.TRUSTED_DOMAINS:
        if netloc_lower.endswith('.' + trusted_domain.lower()) or netloc_lower == trusted_domain.lower():
            return True
    
    return False

def domain_risk(netloc):
    """
    Evaluates domain infrastructure with reduced false positives.
    Enhanced with trusted domain bypass.
    """
    risks = []
    score = 0
    
    # Check if it's a known legitimate domain pattern
    is_legit = is_known_legitimate_domain(netloc)
    
    # CRITICAL FIX: If domain is very old (>1 year), it's likely legitimate
    # This prevents false positives on established sites
    domain_is_established = False
    
    try:
        w = whois.whois(netloc)
        
        # 1. Domain Age - more nuanced scoring
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation and hasattr(creation, 'tzinfo') and creation.tzinfo:
            creation = creation.replace(tzinfo=None)
        
        if creation:
            age_days = (datetime.now() - creation).days
            
            # CRITICAL FIX: Domains over 1 year old are likely legitimate
            if age_days > 365:
                domain_is_established = True
                # No penalty for established domains
            elif age_days > 180:
                # 6-12 months: minimal penalty
                if not is_legit:
                    weight = int(10)
                    risks.append(('Moderately Young Domain', weight, f'Domain is {age_days} days old.'))
                    score += weight
            elif age_days > 90:
                # 3-6 months
                if not is_legit:
                    weight = int(20)
                    risks.append(('Young Domain', weight, f'Registered {age_days} days ago.'))
                    score += weight
            elif age_days > 30:
                # 1-3 months
                weight = int(40)
                risks.append(('Recently Registered', weight, f'Registered {age_days} days ago.'))
                score += weight
            elif age_days >= 7:
                # 1-4 weeks
                weight = int(60)
                risks.append(('Newly Registered Domain', weight, f'Registered {age_days} days ago.'))
                score += weight
            else:
                # Very new domains are high risk
                weight = int(80)
                risks.append(('Very Newly Registered', weight, f'Domain registered {age_days} days ago.'))
                score += weight
                
        # 2. Expiry - short-lived domains are suspicious (but not for established domains)
        if not domain_is_established:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                if hasattr(expiration, 'tzinfo') and expiration.tzinfo:
                    expiration = expiration.replace(tzinfo=None)
                days_to_expire = (expiration - datetime.now()).days
                
                # Very short remaining lifetime is suspicious (burner domain)
                if days_to_expire < 14:
                    weight = int(45)
                    risks.append(('Expiring Very Soon', weight, f'Domain expires in {days_to_expire} days.'))
                    score += weight
                elif days_to_expire < 30 and not is_legit:
                    weight = int(25)
                    risks.append(('Expiring Soon', weight, f'Domain expires in {days_to_expire} days.'))
                    score += weight

    except Exception as e:
        # WHOIS failures are common for privacy-protected domains
        # Don't penalize as heavily for legitimate patterns
        if is_legit:
            # Legitimate sites often use privacy protection
            risks.append(('WHOIS Privacy', 5, 'WHOIS data is private/protected.'))
            score += 5
        else:
            # Unknown domains with no WHOIS are more suspicious
            weight = int(30)
            risks.append(('WHOIS Hidden/Fail', weight, 'Could not retrieve WHOIS data.'))
            score += weight

    # 3. DNS Infrastructure Checks - refined scoring (skip for established domains)
    if not domain_is_established:
        try:
            # MX Records - but many legitimate sites don't have MX
            dns.resolver.resolve(netloc, 'MX')
        except Exception:
            # No MX is only concerning for certain types of sites
            if not is_legit:
                # Unknown sites without MX are slightly suspicious
                weight = int(15)
                risks.append(('No MX Records', weight, 'Domain cannot receive email.'))
                score += weight
            # Legitimate sites might not need email (CDNs, APIs, etc.)
        
        # 4. Fast Flux / IP Anomalies - strong indicators
        try:
            answers = dns.resolver.resolve(netloc, 'A')
            ip_count = len(answers)
            
            # Many IPs can be legitimate (CDN, load balancing) or malicious (fast-flux)
            if ip_count > 20:
                # Very high IP count is suspicious even for CDNs
                risks.append(('Very High IP Count', 40, f'Resolves to {ip_count} IPs. Possible Fast-Flux.'))
                score += 40
            elif ip_count > 10 and not is_legit:
                # Moderate IP count, only flag if not legitimate
                weight = int(20)
                risks.append(('High IP Count', weight, f'Resolves to {ip_count} IPs.'))
                score += weight
            
            # Very short TTL is a strong fast-flux indicator
            ttl = answers.rrset.ttl
            if ttl < 30:
                # TTL under 30 seconds is highly suspicious
                risks.append(('Very Short DNS TTL', 60, f'TTL is {ttl}s. Strong Fast-Flux indicator.'))
                score += 60
            elif ttl < 60 and not is_legit:
                # TTL under 1 minute
                weight = int(35)
                risks.append(('Short DNS TTL', weight, f'TTL is {ttl}s. Possible Fast-Flux.'))
                score += weight
        except Exception:
            # DNS resolution failure is suspicious for unknown sites
            if not is_legit:
                risks.append(('DNS Resolution Failed', 30, 'Could not resolve domain to IP.'))
                score += 30
    
    return score, risks