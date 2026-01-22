import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import re

def is_valid_hostname(hostname):
    """
    Validates hostname format according to RFC standards.
    """
    if len(hostname) > 253:
        return False
    
    # Check for IP address format
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        # Validate IP address
        parts = hostname.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True
    
    # Validate domain name format
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    
    allowed = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split('.'))

def parse_certificate_date(date_str):
    """
    Parse certificate date string in multiple possible formats.
    """
    formats = [
        '%b %d %H:%M:%S %Y %Z',  # Original format: 'Jan 1 00:00:00 2024 GMT'
        '%Y-%m-%d %H:%M:%S %Z',   # ISO format: '2024-01-01 00:00:00 GMT'
        '%Y-%m-%d %H:%M:%S',      # ISO without timezone: '2024-01-01 00:00:00'
        '%Y%m%d%H%M%SZ',          # ASN.1 format: '20240101000000Z'
        '%Y-%m-%dT%H:%M:%SZ',     # ISO 8601: '2024-01-01T00:00:00Z'
    ]
    
    for fmt in formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            # If timezone is present, convert to naive datetime
            if hasattr(parsed_date, 'tzinfo') and parsed_date.tzinfo:
                parsed_date = parsed_date.replace(tzinfo=None)
            return parsed_date
        except ValueError:
            continue
    
    # If all formats fail, return None
    return None

def is_domain_match(hostname, san_list):
    """
    Check if hostname matches any Subject Alternative Name with proper wildcard handling.
    """
    hostname_lower = hostname.lower()
    
    for san_type, san_value in san_list:
        if san_type != 'DNS':
            continue
            
        san_lower = san_value.lower()
        
        # Exact match
        if san_lower == hostname_lower:
            return True
        
        # Wildcard match (e.g., *.example.com matches subdomain.example.com)
        if san_lower.startswith('*.'):
            wildcard_domain = san_lower[2:]  # Remove '*.'
            if hostname_lower.endswith('.' + wildcard_domain):
                # Ensure it's not matching a partial domain (e.g., evil-example.com shouldn't match *.example.com)
                hostname_prefix = hostname_lower[:-len(wildcard_domain)-1]  # Remove the domain and dot
                if '.' not in hostname_prefix:  # Only one subdomain level
                    return True
        
        # Regular subdomain match
        if san_lower.startswith('*.') and hostname_lower.endswith(san_lower[1:]):
            return True
    
    return False

def ssl_risk(target):
    """
    Inspects SSL/TLS properties with reduced false positives.
    Validates certificates and protocol usage with nuanced scoring.
    Handles both full URLs with protocol prefix and bare hostnames.
    """
    risks = []
    score = 0

    # Parameter validation
    if not target or not isinstance(target, str):
        risks.append(('Invalid Host', 10, f'Target must be a non-empty string: {str(target)[:30] if target else "empty"}'))
        return 10, risks

    # Normalize input: accept either full URL or bare host
    target = target.strip()
    if not target:
        risks.append(('Invalid Host', 10, 'Target cannot be empty after trimming.'))
        return 10, risks

    # Check if target already contains a protocol scheme
    if ':' in target and '//' in target:
        # Full URL with protocol
        try:
            parsed = urlparse(target)
        except Exception as e:
            risks.append(('Invalid Host', 10, f'Could not parse host: {str(e)[:30]}'))
            return 10, risks
    else:
        # Bare hostname, assume HTTPS
        try:
            parsed = urlparse(f'https://{target}')
        except Exception as e:
            risks.append(('Invalid Host', 10, f'Could not parse host: {str(e)[:30]}'))
            return 10, risks

    host = parsed.hostname
    scheme = parsed.scheme

    # Validate hostname exists
    if not host:
        risks.append(('Invalid Host', 10, 'Hostname missing for SSL check.'))
        score += 10
        return score, risks

    # Validate hostname format
    if not is_valid_hostname(host):
        risks.append(('Invalid Host Format', 10, f'Hostname format is invalid: {host}'))
        score += 10
        return score, risks

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

    # Additional validation after ensuring HTTPS
    if not host:
        risks.append(('Invalid Host', 10, 'Hostname missing for SSL check.'))
        score += 10
        return score, risks

    # Determine port based on scheme
    if parsed.port:
        port = parsed.port
    elif scheme == 'https':
        port = 443
    elif scheme == 'http':
        port = 80
    else:
        port = 443  # Default to 443 for other schemes

    # Ensure port is valid
    if not (1 <= port <= 65535):
        risks.append(('Invalid Port', 10, f'Port {port} is outside valid range (1-65535)'))
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

    # Continue with existing SSL validation logic
    port = parsed.port or 443
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
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
                elif protocol_version == 'TLSv1.2':
                    # TLS 1.2 is still secure but newer versions are preferred
                    weight = int(15 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Outdated TLS Version', weight, f'Uses older but still secure {protocol_version}.'))
                        score += weight

                # Enhanced certificate expiry validation with multiple format support
                expiry_str = cert.get('notAfter')
                if expiry_str:
                    try:
                        expiry = parse_certificate_date(expiry_str)
                        if expiry:
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
                            elif days_left < 14:
                                # Expiring in 2 weeks
                                weight = int(35 * sensitivity_multiplier)
                                if weight > 0 and not is_legit:
                                    risks.append(('SSL Expiring Soon (14d)', weight, f'Expires in {days_left} days.'))
                                    score += weight
                            elif days_left < 30 and not is_legit:
                                # Expiring soon, only flag for non-legitimate
                                weight = int(25 * sensitivity_multiplier)
                                if weight > 0:
                                    risks.append(('SSL Expiring Soon (30d)', weight, f'Expires in {days_left} days.'))
                                    score += weight
                    except Exception:
                        risks.append(('SSL Expiry Parse Error', 10, 'Could not parse expiry: ' + str(expiry_str)[:50]))
                        score += 10

                # Enhanced Subject/Domain mismatch - strong phishing indicator
                subject_alt = cert.get('subjectAltName', [])
                if subject_alt:
                    # Check if host matches any SAN entry with more precise matching
                    host_matches = is_domain_match(host, subject_alt)
                    if not host_matches:
                        risks.append(('SSL Domain Mismatch', 80, 'Certificate does not match domain.'))
                        score += 80

                # Enhanced Self-signed certificate detection
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
                
                # Additional certificate checks
                # Check certificate issuer
                issuer_cn = issuer.get('commonName', '')
                if not issuer_cn:
                    risks.append(('Missing Issuer Info', 20, 'Certificate has no issuer common name.'))
                    score += 20
                
                # Check for weak signature algorithms
                sig_alg = cert.get('signatureAlgorithm', '')
                if sig_alg:
                    weak_algs = ['md2', 'md5', 'sha1']
                    if any(alg in sig_alg.lower() for alg in weak_algs):
                        weight = int(45 * sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Weak Signature Algorithm', weight, f'Uses weak algorithm: {sig_alg}'))
                            score += weight
                
                # Check certificate key size (if available)
                # Note: This is a simplified check, in practice you'd need to parse the public key properly
                serial_number = cert.get('serialNumber', '')
                if serial_number and len(serial_number) < 8:
                    weight = int(25 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Weak Serial Number', weight, f'Serial number too short: {serial_number}'))
                        score += weight
                
                # Check for certificate validity period (too long or too short)
                not_before_str = cert.get('notBefore')
                if not_before_str:
                    try:
                        not_before = parse_certificate_date(not_before_str)
                        if not_before:
                            cert_age = (datetime.now() - not_before).days
                            
                            # Certificate too new (potential for fraud)
                            if cert_age < 7:
                                weight = int(30 * sensitivity_multiplier)
                                if weight > 0 and not is_trusted_subdomain:
                                    risks.append(('New Certificate', weight, f'Certificate issued {cert_age} days ago.'))
                                    score += weight
                            
                            # Calculate validity period
                            if expiry:
                                validity_period = (expiry - not_before).days
                                # Certificate valid for too long (security risk)
                                if validity_period > 825:  # More than 2.25 years
                                    weight = int(35 * sensitivity_multiplier)
                                    if weight > 0:
                                        risks.append(('Long Validity Period', weight, f'Certificate valid for {validity_period} days.'))
                                        score += weight
                    except Exception:
                        # If we can't parse notBefore, just continue
                        pass
    except Exception as e:
        # SSL handshake failures can indicate problems but also network issues
        error_msg = str(e).lower()
        
        # Distinguish between different error types
        if 'certificate verify failed' in error_msg or 'certificate has expired' in error_msg:
            risks.append(('SSL Verification Failed', 70, 'Certificate verification failed.'))
            score += 70
        elif 'hostname doesn\'t match' in error_msg or 'mismatch' in error_msg:
            # Hostname verification failed
            risks.append(('SSL Hostname Mismatch', 75, 'Hostname does not match certificate.'))
            score += 75
        elif 'timed out' in error_msg or 'connection refused' in error_msg:
            # Network issues, less suspicious
            weight = int(30 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('SSL Connection Failed', weight, f'Could not connect: {error_msg[:40]}'))
                score += weight
        elif 'wrong version number' in error_msg or 'record layer failure' in error_msg:
            # Protocol version issues
            weight = int(40 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('SSL Protocol Error', weight, f'Protocol version mismatch: {error_msg[:40]}'))
                score += weight
        else:
            weight = int(50 * sensitivity_multiplier)
            if weight > 0:
                risks.append(('SSL Handshake Failed', weight, f'TLS connection issue: {str(e)[:50]}'))
                score += weight

    # --- TITAN-TIER: Certificate Intelligence (Layer 2+) ---
    # 1. Certificate Transparency (CT) Log Check (Simulated for Phase 1/2)
    # Real implementation would query crt.sh or Google CT logs
    # Absence from CT logs is highly suspicious for public CAs
    # For now, we assume standard CAs are in CT. If we had the raw cert, we'd check SCTs.
    # Placeholder Logic:
    # if not cert.get('scts'): 
    #    risks.append(('CT Log Void', 90, 'Certificate not found in public Transparency Logs'))
    #    score += 90

    # 2. "Let's Encrypt" Abuse Pattern
    # Free certs are often used by phishers. High risk if:
    # - Issuer is Let's Encrypt (or other free CA)
    # - AND Cert is very new (< 24 hours)
    # - AND Domain contains high-value keywords (bank, login, secure)
    
    issuer_name = ''
    if 'issuer' in locals() and issuer:
         # Extract Organization/Common Name from issuer dict
         issuer_name = issuer.get('organizationName', '') or issuer.get('commonName', '')
    
    # List of free/automated CAs often abused
    free_cas = ['Let\'s Encrypt', 'cPanel', 'Cloudflare', 'ZeroSSL']
    
    if any(ca.lower() in issuer_name.lower() for ca in free_cas):
        # Check cert age
        if 'cert_age' in locals() and cert_age < 1: # Less than 24 hours old
             # Check for high-value targets in hostname
             high_value_keywords = ['bank', 'login', 'secure', 'account', 'update', 'verify', 'paypal', 'apple', 'microsoft']
             if any(kw in host.lower() for kw in high_value_keywords):
                 risks.append(('Let\'s Encrypt Abuse', 50, f'New free certificate (<24h) on high-value domain: {host}'))
                 score += 50

    return score, risks