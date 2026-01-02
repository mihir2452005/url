import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

def ssl_risk(target):
    """
    Inspects SSL/TLS properties with reduced false positives.
    Validates certificates and protocol usage with nuanced scoring.
    """
    risks = []
    score = 0

    # Normalize input: accept either full URL or bare host
    try:
        parsed = urlparse(target if '://' in target else f'https://{target}')
    except Exception as e:
        risks.append(('Invalid Host', 10, f'Could not parse host: {str(e)[:30]}'))
        return 10, risks

    host = parsed.hostname
    scheme = parsed.scheme

    # Protocol verification - HTTP is concerning but context matters
    if scheme != 'https':
        # Check if it's localhost/dev environment
        if host and ('localhost' in host.lower() or '127.0.0.1' in host):
            risks.append(('HTTP on Localhost', 5, 'Using HTTP on localhost (development).'))
            score += 5
        else:
            risks.append(('No HTTPS', 35, 'Not using secure HTTPS protocol.'))
            score += 35
        return score, risks

    if not host:
        risks.append(('Invalid Host', 10, 'Hostname missing for SSL check.'))
        score += 10
        return score, risks

    # Check if it's a known legitimate domain
    from config import Config
    is_legit = any(pattern in host.lower() for pattern in Config.KNOWN_LEGITIMATE_PATTERNS)
    
    # NEW: Check for subdomains of known legitimate domains
    # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
    is_trusted_subdomain = False
    for trusted_domain in Config.TRUSTED_DOMAINS:
        if host.lower().endswith('.' + trusted_domain.lower()) or host.lower() == trusted_domain.lower():
            is_trusted_subdomain = True
            break
    
    if is_legit or is_trusted_subdomain:
        sensitivity_multiplier = 0.5
    else:
        sensitivity_multiplier = 1.0

    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol_version = ssock.version()

                # Check for obsolete protocols - strong indicator
                if protocol_version in ['SSLv2', 'SSLv3']:
                    risks.append(('Very Obsolete SSL', 70, f'Uses insecure {protocol_version}.'))
                    score += 70
                elif protocol_version in ['TLSv1', 'TLSv1.1']:
                    # TLS 1.0/1.1 deprecated but some legacy systems still use
                    weight = int(50 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Obsolete TLS Version', weight, f'Uses deprecated {protocol_version}.'))
                        score += weight

                # Certificate expiry validation
                expiry_str = cert.get('notAfter')
                if expiry_str:
                    try:
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        if hasattr(expiry, 'tzinfo') and expiry.tzinfo:
                            expiry = expiry.replace(tzinfo=None)
                        days_left = (expiry - datetime.now()).days
                        
                        if days_left < 0:
                            # Expired cert is critical
                            risks.append(('SSL Expired', 85, 'Certificate has already expired.'))
                            score += 85
                        elif days_left < 7:
                            # Expiring very soon
                            weight = int(50 * sensitivity_multiplier)
                            if weight > 0:
                                risks.append(('SSL Expiring Imminently', weight, f'Expires in {days_left} days.'))
                                score += weight
                        elif days_left < 30 and not is_legit:
                            # Expiring soon, only flag for non-legitimate
                            weight = int(25 * sensitivity_multiplier)
                            if weight > 0:
                                risks.append(('SSL Expiring Soon', weight, f'Expires in {days_left} days.'))
                                score += weight
                    except Exception:
                        risks.append(('SSL Expiry Parse Error', 10, 'Could not parse expiry.'))
                        score += 10

                # Subject/Domain mismatch - strong phishing indicator
                subject_alt = cert.get('subjectAltName', [])
                if subject_alt:
                    # Check if host matches any SAN entry
                    host_matches = any(host in str(item) or str(item).endswith(host) for item in subject_alt)
                    if not host_matches:
                        risks.append(('SSL Domain Mismatch', 80, 'Certificate does not match domain.'))
                        score += 80

                # Self-signed certificate detection
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                if issuer and subject and issuer == subject:
                    # Self-signed is suspicious unless it's localhost/dev
                    if 'localhost' in host.lower() or '127.0.0.1' in host:
                        risks.append(('Self-Signed (Dev)', 15, 'Self-signed cert on localhost.'))
                        score += 15
                    else:
                        risks.append(('Self-Signed Cert', 75, 'Certificate is self-signed.'))
                        score += 75
    except Exception as e:
        # SSL handshake failures can indicate problems but also network issues
        error_msg = str(e).lower()
        
        # Distinguish between different error types
        if 'certificate verify failed' in error_msg or 'certificate has expired' in error_msg:
            risks.append(('SSL Verification Failed', 70, 'Certificate verification failed.'))
            score += 70
        elif 'timed out' in error_msg or 'connection refused' in error_msg:
            # Network issues, less suspicious
            weight = int(30 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('SSL Connection Failed', weight, f'Could not connect: {error_msg[:40]}'))
                score += weight
        else:
            weight = int(50 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('SSL Handshake Failed', weight, f'TLS connection issue: {str(e)[:50]}'))
                score += weight

    return score, risks