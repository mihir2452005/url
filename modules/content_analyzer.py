import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import socket
import whois
from datetime import datetime
import hashlib
import json
import os
import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Global variable to store the last soup object for advanced analysis
_last_soup = None

def get_last_soup():
    """Return the last soup object for advanced analysis."""
    return _last_soup

def load_brand_favicons():
    """Load known brand favicon hashes."""
    try:
        data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'brand_favicons.json')
        if os.path.exists(data_path):
            with open(data_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading brand favicons: {e}")
    return {}

async def check_favicon(url, soup, session, domain):
    """
    Check if the site's favicon matches a known brand but domain doesn't match.
    Returns: (score_modifier, risk_entry_or_None)
    """
    try:
        # Find favicon URL
        icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if not icon_link:
            # Try default /favicon.ico
            favicon_url = urljoin(url, '/favicon.ico')
        else:
            favicon_url = urljoin(url, icon_link.get('href'))

        # Fetch favicon
        try:
            async with session.get(favicon_url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    # Compute hash (MD5 of content)
                    favicon_hash = hashlib.md5(content).hexdigest()[:8] # First 8 chars for brevity/demo
                    
                    brands_db = load_brand_favicons()
                    
                    # Check against DB
                    for brand, known_hash in brands_db.items():
                        if favicon_hash == known_hash:
                            # Match found! Check if domain matches brand
                            if brand not in domain.lower():
                                return 90, ('Favicon Impersonation', 90, f'Site uses {brand.capitalize()} favicon but domain is not {brand}')
        except:
            pass # Favicon fetch failed, ignore
            
    except Exception as e:
        pass
    
    return 0, None


async def content_risk(url):
    """Analyze URL content for malicious indicators with enhanced zero-day phishing detection."""
    global _last_soup
    risks = []
    score = 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, timeout=10, ssl=False) as response:
                    content_text = await response.text()
                    _last_soup = BeautifulSoup(content_text, 'html.parser')
                    soup = _last_soup
                    
                    # 0. Favicon Analysis (The "Flash" Check)
                    fav_score, fav_risk = await check_favicon(url, soup, session, domain)
                    if fav_risk:
                        risks.append(fav_risk)
                        score += fav_score
                        
            except Exception as e:
                # If we can't access the content, assign a moderate risk
                risks.append(('Content Access Error', 20, f'Could not access content: {str(e)[:50]}'))
                return 20, risks

        # 1. Enhanced brand impersonation detection
        title = soup.title.string if soup.title else ""
        body_text = soup.get_text().lower()
        
        # Extended list of brand names for impersonation detection
        brands = [
            'paypal', 'amazon', 'apple', 'microsoft', 'facebook', 'google', 'twitter', 'instagram', 
            'sbi', 'hdfc', 'icici', 'axis', 'citibank', 'netflix', 'spotify', 'adobe', 'office', 
            'microsoftonline', 'salesforce', 'zendesk', 'slack', 'dropbox', 'ebay', 'chase', 
            'wellsfargo', 'bankofamerica', 'santander', 'bofa', 'capitalone', 'usaa', 'ally', 
            'americanexpress', 'mastercard', 'visa', 'discover', 'tdbank', 'pnc', 'wells fargo',
            'yahoo', 'gmail', 'outlook', 'hotmail', 'aol', 'icloud', 'protonmail', 'tutanota'
        ]
        
        # Check for brand impersonation in title and body
        for brand in brands:
            if brand.lower() in title.lower() and brand.lower() not in domain.lower():
                # This is a potential brand impersonation
                brand_score = 75
                risks.append(('Brand Impersonation', brand_score, f'Brand name "{brand}" in title but not in domain: {domain}'))
                score += brand_score
            elif brand.lower() in body_text and brand.lower() not in domain.lower():
                # Check if brand is mentioned frequently in body (potential impersonation)
                brand_mentions = len(re.findall(r'\b' + brand.lower() + r'\b', body_text))
                if brand_mentions > 2:  # More than 2 mentions suggest impersonation
                    brand_score = min(70, brand_mentions * 20)
                    risks.append(('Potential Brand Impersonation', brand_score, f'Brand "{brand}" mentioned {brand_mentions} times in content but not in domain'))
                    score += brand_score
        
        # 2. Enhanced form analysis
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Check if form posts to external domain
            if action.startswith(('http://', 'https://')):
                action_parsed = urlparse(action)
                if action_parsed.netloc != domain:
                    external_form_score = 80
                    risks.append(('External Form Action', external_form_score, f'Form posts to external domain: {action_parsed.netloc}'))
                    score += external_form_score
            
            # Look for credential-related inputs
            inputs = form.find_all(['input', 'select', 'textarea'])
            password_fields = []
            username_fields = []
            
            for inp in inputs:
                inp_type = inp.get('type', 'text').lower()
                inp_name = inp.get('name', '').lower()
                inp_id = inp.get('id', '').lower()
                
                # Password fields
                if inp_type == 'password' or any(x in inp_name + inp_id for x in ['pass', 'pwd', 'password']):
                    password_fields.append(inp)
                
                # Username/email fields
                if inp_type in ['text', 'email'] and any(x in inp_name + inp_id for x in ['user', 'name', 'email', 'login', 'username']):
                    username_fields.append(inp)
                
                # Check for hidden credential fields
                if inp_type == 'hidden':
                    hidden_value = inp.get('value', '').lower()
                    if any(x in hidden_value for x in ['password', 'credential', 'account']):
                        hidden_cred_score = 65
                        risks.append(('Hidden Credential Field', hidden_cred_score, f'Hidden field contains credential-related text: {hidden_value[:50]}'))
                        score += hidden_cred_score
            
            # If form has both username and password fields, check for security features
            if password_fields and username_fields:
                # Check if form has CSRF token
                csrf_indicators = ['csrf', 'token', 'authenticity_token', '_token', 'xsrf']
                has_csrf = any(any(ind in inp.get('name', '').lower() for ind in csrf_indicators) 
                              for inp in inputs if inp.get('type', '') in ['hidden', 'text'])
                
                if not has_csrf:
                    no_csrf_score = 60
                    risks.append(('Missing CSRF Token', no_csrf_score, 'Form lacks CSRF protection - potential credential harvesting'))
                    score += no_csrf_score
                
                # Check if form is using HTTP instead of HTTPS
                if url.lower().startswith('http:') and method == 'post':
                    insecure_form_score = 70
                    risks.append(('Insecure Password Form', insecure_form_score, 'Password form submitted over unencrypted HTTP'))
                    score += insecure_form_score
        
        # 3. Enhanced phishing indicators in content
        phishing_indicators = [
            (r'urgent', 'Urgent Action Required'),
            (r'act now|limited time|expires?', 'Urgency Pressure'),
            (r'confirm account|verify account|update account', 'Account Verification Request'),
            (r'click here|download now|claim now', 'Clickbait Language'),
            (r'free money|win big|congratulations', 'Prize/Winning Scam'),
            (r'blocked|suspended|disabled', 'Account Status Threat'),
            (r'personal information|verify identity|confirm details', 'Information Request'),
            (r'banking|secure login|online banking', 'Banking Impersonation'),
            (r'payment|transaction|billing', 'Payment Related'),
            (r'document|pdf|attachment', 'Document Impersonation'),
        ]
        
        for pattern, desc in phishing_indicators:
            matches = re.findall(pattern, body_text, re.IGNORECASE)
            if len(matches) > 2:  # More than 2 occurrences
                phishing_score = min(65, len(matches) * 15)
                risks.append((desc, phishing_score, f'Found {len(matches)} instances of "{pattern}" in content'))
                score += phishing_score
        
        # 4. Suspicious links analysis
        links = soup.find_all('a', href=True)
        suspicious_links = []
        
        for link in links:
            href = link.get('href')
            link_text = link.get_text().strip().lower()
            
            # Check for suspicious link texts
            suspicious_texts = [
                'click here', 'download', 'update now', 'verify account', 
                'secure login', 'free gift', 'urgent action', 'act now'
            ]
            
            if any(text in link_text for text in suspicious_texts):
                # Check if the link goes to a different domain
                full_link = urljoin(url, href)
                link_domain = urlparse(full_link).netloc
                
                if link_domain != domain and link_domain:
                    suspicious_links.append((full_link, link_text))
        
        if suspicious_links:
            link_score = min(70, len(suspicious_links) * 25)
            risks.append(('Suspicious External Links', link_score, f'{len(suspicious_links)} potentially suspicious external links found'))
            score += link_score
        
        # 5. Enhanced script analysis
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string or ""
            if script_content:
                # Check for suspicious JavaScript patterns
                suspicious_js_patterns = [
                    (r'window\.location\s*[+]=|\s*=\s*["\'][^"\']*location', 'Dynamic URL Redirection'),
                    (r'document\.write|innerHTML|outerHTML', 'DOM Manipulation'),
                    (r'eval\(|setTimeout\([^,]+,', 'Code Evaluation'),
                    (r'atob\(|btoa\(|String\.fromCharCode', 'Encoding/Decoding'),
                    (r'\/[\w\W]{5,}\/[igm]*\s*\.[\w]+\(', 'Obfuscated Regex'),
                    (r'charCodeAt|fromCharCode', 'Character Manipulation'),
                ]
                
                for pattern, desc in suspicious_js_patterns:
                    matches = re.findall(pattern, script_content, re.IGNORECASE)
                    if matches:
                        js_score = min(60, len(matches) * 20)
                        risks.append((desc, js_score, f'Found {len(matches)} suspicious JS patterns: {desc}'))
                        score += js_score
        
        # 6. Meta tag analysis
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content = meta.get('content', '').lower()
            
            if name == 'robots' and 'noindex' in content:
                # Site doesn't want to be indexed - potentially suspicious
                noindex_score = 35
                risks.append(('No Index Tag', noindex_score, 'Site prevents search engine indexing'))
                score += noindex_score
        
        # 7. Image analysis for logo impersonation
        images = soup.find_all('img')
        suspicious_images = []
        
        for img in images:
            src = img.get('src', '')
            alt = img.get('alt', '').lower()
            title = img.get('title', '').lower()
            
            # Check if image filename or attributes contain brand names
            for brand in brands:
                if brand.lower() in src.lower() or brand.lower() in alt or brand.lower() in title:
                    if brand.lower() not in domain.lower():
                        suspicious_images.append((src, brand))
        
        if suspicious_images:
            img_score = min(50, len(suspicious_images) * 15)
            risks.append(('Suspicious Brand Images', img_score, f'{len(suspicious_images)} images with brand names but not in domain'))
            score += img_score
        
        # 8. Frame/iframe analysis
        frames = soup.find_all(['iframe', 'frame'])
        for frame in frames:
            src = frame.get('src', '')
            if src:
                frame_domain = urlparse(urljoin(url, src)).netloc
                if frame_domain and frame_domain != domain:
                    iframe_score = 65
                    risks.append(('External iFrame', iframe_score, f'Embedded content from external domain: {frame_domain}'))
                    score += iframe_score
        
        # 9. Social engineering lures
        social_lures = [
            (r'free [a-z ]+ now', 'Free Offer Lure'),
            (r'limited time|offer expires', 'Scarcity Lure'),
            (r'click here for|download [a-z ]+ now', 'Clickbait Lure'),
            (r'act now|before it\'s gone', 'Urgency Lure'),
            (r'your account will be|will be suspended', 'Threat Lure'),
        ]
        
        for pattern, desc in social_lures:
            matches = re.findall(pattern, body_text, re.IGNORECASE)
            if matches:
                lure_score = min(55, len(matches) * 20)
                risks.append((desc, lure_score, f'Social engineering lure found: {desc}'))
                score += lure_score
        
        # 10. Check for fake security indicators
        security_texts = [
            'secure connection', 'encrypted', 'protected', 'secure login', 'safe browsing'
        ]
        for text in security_texts:
            if text in body_text and url.lower().startswith('http:'):  # Not HTTPS
                fake_security_score = 50
                risks.append(('Fake Security Claim', fake_security_score, f'Claims "{text}" but uses HTTP, not HTTPS'))
                score += fake_security_score
    
    except Exception as e:
        risks.append(('Content Analysis Error', 10, f'Error analyzing content: {str(e)[:50]}'))
        score += 10
    
    # Cap the score at 100
    score = min(100, score)
    
    return score, risks
