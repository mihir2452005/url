"""
Advanced URL Threat Detection Features
Comprehensive multi-category analysis without external API dependencies
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote
import unicodedata
import hashlib
from datetime import datetime


class AdvancedLexicalAnalyzer:
    """
    Category 1: Advanced Lexical Features
    Sophisticated URL string analysis and pattern detection
    """
    
    @staticmethod
    def analyze(url):
        """Perform comprehensive lexical analysis"""
        risks = []
        score = 0
        
        parsed = urlparse(url)
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        fragment = parsed.fragment or ''
        
        # NEW: Check for educational institutions early
        from config import Config
        netloc_lower = netloc.lower()
        
        # Educational TLDs get special treatment
        educational_tlds = ['.edu', '.ac.', '.edu.']
        is_educational = any(tld in netloc_lower for tld in educational_tlds)
        
        # Also check for educational keywords
        has_edu_keyword = any(keyword in netloc_lower for keyword in Config.EDUCATIONAL_KEYWORDS)
        
        # NEW: Check for subdomains of known legitimate domains
        # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
        is_trusted_subdomain = False
        for trusted_domain in Config.TRUSTED_DOMAINS:
            if netloc_lower.endswith('.' + trusted_domain.lower()) or netloc_lower == trusted_domain.lower():
                is_trusted_subdomain = True
                break
        
        # If educational, apply very low sensitivity multiplier
        if is_educational or has_edu_keyword or is_trusted_subdomain:
            edu_multiplier = 0.1  # Very lenient for educational sites
        else:
            edu_multiplier = 1.0
        
        # 1. Character Frequency Analysis
        char_freq = Counter(url.lower())
        total_chars = len(url)
        
        # Detect unusual character distributions
        suspicious_chars = {'-': 0.15, '_': 0.10, '.': 0.10, '%': 0.05, '@': 0.01}
        for char, threshold in suspicious_chars.items():
            if char in char_freq and char_freq[char] / total_chars > threshold:
                weight = int(30 * (char_freq[char] / total_chars / threshold) * edu_multiplier)
                if weight > 0:
                    risks.append((f'High {char} Character Frequency', min(weight, 40), 
                                f'Unusual frequency of "{char}" character ({char_freq[char]} occurrences)'))
                    score += min(weight, 40)
        
        # 2. Shannon Entropy Calculation (advanced)
        domain_chars = [c for c in netloc if c.isalnum()]
        if len(domain_chars) > 5:
            entropy = -sum((domain_chars.count(c) / len(domain_chars)) * 
                          math.log2(domain_chars.count(c) / len(domain_chars)) 
                          for c in set(domain_chars))
            
            if entropy > 4.5:
                weight = int((entropy - 4.5) * 40)
                risks.append(('Very High Domain Entropy', min(weight, 50), 
                            f'Domain entropy: {entropy:.2f} (DGA indicator)'))
                score += min(weight, 50)
        
        # 3. Digit-to-Letter Ratio Analysis
        digits = sum(c.isdigit() for c in netloc)
        letters = sum(c.isalpha() for c in netloc)
        if letters > 0:
            digit_ratio = digits / letters
            if digit_ratio > 0.5:
                weight = int(digit_ratio * 40)
                risks.append(('High Digit Ratio', min(weight, 45), 
                            f'Unusual digit-to-letter ratio: {digit_ratio:.2f}'))
                score += min(weight, 45)
        
        # 4. Consecutive Character Patterns
        consecutive_digits = re.findall(r'\d{4,}', url)
        if consecutive_digits:
            weight = len(consecutive_digits) * 15
            risks.append(('Long Digit Sequences', min(weight, 35), 
                        f'{len(consecutive_digits)} sequences of 4+ consecutive digits'))
            score += min(weight, 35)
        
        # 5. Homograph Detection (Extended Unicode Analysis)
        confusable_scripts = []
        for char in netloc:
            try:
                char_name = unicodedata.name(char)
                if any(script in char_name for script in ['CYRILLIC', 'GREEK', 'ARABIC']):
                    confusable_scripts.append((char, char_name.split()[0]))
            except ValueError:
                pass
        
        if confusable_scripts and any(c.isalpha() and ord(c) < 128 for c in netloc):
            risks.append(('Advanced Homograph Attack', 70, 
                        f'Mixed scripts detected: {set(s[1] for s in confusable_scripts)}'))
            score += 70
        
        # 6. Encoding Scheme Analysis
        # Detect multiple encoding layers
        encoding_layers = 0
        test_string = url
        for _ in range(3):
            try:
                decoded = unquote(test_string)
                if decoded != test_string and '%' in test_string:
                    encoding_layers += 1
                    test_string = decoded
                else:
                    break
            except:
                break
        
        if encoding_layers > 1:
            weight = encoding_layers * 25
            risks.append(('Multiple Encoding Layers', min(weight, 55), 
                        f'{encoding_layers} layers of URL encoding (obfuscation)'))
            score += min(weight, 55)
        
        # 7. Vowel Consonant Ratio (linguistic analysis)
        vowels = sum(1 for c in netloc.lower() if c in 'aeiou')
        consonants = sum(1 for c in netloc.lower() if c.isalpha() and c not in 'aeiou')
        if consonants > 0:
            vc_ratio = vowels / consonants
            # Normal English: ~0.4-0.6, Random/DGA: often <0.3 or >0.7
            if vc_ratio < 0.2 or vc_ratio > 0.8:
                weight = 30
                risks.append(('Abnormal Linguistic Pattern', weight, 
                            f'Vowel/consonant ratio: {vc_ratio:.2f} (non-natural)'))
                score += weight
        
        return score, risks


class AdvancedStructuralAnalyzer:
    """
    Category 2: Advanced Structural Features
    Deep URL hierarchy and component analysis
    """
    
    @staticmethod
    def analyze(url):
        """Perform structural analysis"""
        risks = []
        score = 0
        
        parsed = urlparse(url)
        path = parsed.path or ''
        query = parsed.query or ''
        fragment = parsed.fragment or ''
        
        # 1. Path Depth Analysis
        path_segments = [s for s in path.split('/') if s]
        depth = len(path_segments)
        
        if depth > 7:
            weight = (depth - 7) * 8
            risks.append(('Excessive Path Depth', min(weight, 40), 
                        f'URL has {depth} path levels (typical: 2-5)'))
            score += min(weight, 40)
        
        # 2. Parameter Analysis
        params = parse_qs(query)
        param_count = len(params)
        
        if param_count > 10:
            weight = (param_count - 10) * 5
            risks.append(('Excessive Parameters', min(weight, 35), 
                        f'{param_count} query parameters (complexity)'))
            score += min(weight, 35)
        
        # 3. Suspicious Parameter Names
        suspicious_params = ['redirect', 'url', 'next', 'goto', 'return', 'continue',
                           'exec', 'cmd', 'execute', 'eval', 'run']
        found_suspicious = [p for p in params.keys() if any(sp in p.lower() for sp in suspicious_params)]
        
        if found_suspicious:
            weight = len(found_suspicious) * 20
            risks.append(('Suspicious Parameter Names', min(weight, 50), 
                        f'Parameters: {", ".join(found_suspicious)}'))
            score += min(weight, 50)
        
        # 4. Parameter Value Analysis
        for param, values in params.items():
            for value in values:
                # Check for encoded URLs in parameters
                if value.startswith('http') or '%3A%2F%2F' in value:
                    risks.append(('URL in Parameter', 35, 
                                f'Parameter "{param}" contains URL (open redirect risk)'))
                    score += 35
                    break
                
                # Check for script/code indicators
                if any(indicator in value.lower() for indicator in ['<script', 'javascript:', 'onerror=']):
                    risks.append(('Script in Parameter', 60, 
                                f'Parameter "{param}" contains script indicator'))
                    score += 60
                    break
        
        # 5. Fragment Analysis
        if fragment:
            if len(fragment) > 100:
                risks.append(('Large Fragment', 25, 
                            f'Fragment is {len(fragment)} chars (unusual)'))
                score += 25
            
            if any(indicator in fragment.lower() for indicator in ['javascript:', '<script', 'eval(']):
                risks.append(('Suspicious Fragment', 55, 
                            'Fragment contains script/code indicators'))
                score += 55
        
        # 6. Path Pattern Analysis
        # Detect file extension spoofing
        if path:
            double_extensions = re.findall(r'\.(\w+)\.(\w+)$', path)
            if double_extensions:
                ext1, ext2 = double_extensions[0]
                if ext1 in ['jpg', 'png', 'gif', 'pdf', 'doc'] and ext2 in ['exe', 'scr', 'bat']:
                    risks.append(('Extension Spoofing', 65, 
                                f'Suspicious double extension: .{ext1}.{ext2}'))
                    score += 65
        
        # 7. Directory Traversal Indicators
        traversal_patterns = ['../', '..\\', '%2e%2e/', '%252e%252e']
        for pattern in traversal_patterns:
            if pattern in url.lower():
                risks.append(('Directory Traversal Pattern', 70, 
                            f'Contains traversal sequence: {pattern}'))
                score += 70
                break
        
        # 8. NEW PARAMETER: SQL Injection Pattern Detection
        # Detects common SQL injection patterns in parameters
        sql_patterns = [
            r"('|\")(\s)*(or|and)(\s)*('|\")?(=|<|>)",  # ' or '=
            r"union(\s)+select",  # UNION SELECT
            r"(drop|delete|insert|update)(\s)+(table|from)",  # Dangerous SQL
            r"-{2,}",  # SQL comments
            r"(;|\|\||&&)(\s)*(drop|select|insert|update)",  # Command injection
        ]
        
        query_lower = query.lower()
        sql_matches = 0
        for pattern in sql_patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                sql_matches += 1
        
        if sql_matches >= 2:
            risks.append(('SQL Injection Pattern', 75, 
                        f'{sql_matches} SQL injection indicators detected'))
            score += 75
        elif sql_matches == 1:
            risks.append(('Potential SQL Pattern', 40, 
                        'Query contains SQL-like syntax'))
            score += 40
        
        # 9. NEW PARAMETER: Command Injection Detection
        # Detects shell command patterns in parameters
        cmd_patterns = [';', '|', '&&', '||', '`', '$(', '${', '\n', '\r']
        cmd_count = sum(1 for pattern in cmd_patterns if pattern in query)
        
        if cmd_count >= 3:
            risks.append(('Command Injection Pattern', 70, 
                        f'{cmd_count} command injection indicators'))
            score += 70
        elif cmd_count >= 2:
            risks.append(('Shell Metacharacters', 35, 
                        'Query contains shell command separators'))
            score += 35
        
        return score, risks


class AdvancedDomainAnalyzer:
    """
    Category 3: Advanced Domain/Host Features
    Comprehensive domain reputation and pattern analysis
    """
    
    @staticmethod
    def analyze(url, netloc):
        """Perform advanced domain analysis"""
        risks = []
        score = 0
        
        # 1. Subdomain Analysis
        labels = netloc.split('.')
        subdomain_count = len(labels) - 2  # Subtract domain and TLD
        
        if subdomain_count > 3:
            weight = (subdomain_count - 3) * 15
            risks.append(('Deep Subdomain Nesting', min(weight, 45), 
                        f'{subdomain_count} subdomain levels'))
            score += min(weight, 45)
        
        # 2. Subdomain Pattern Analysis
        if subdomain_count > 0:
            subdomains = labels[:-2]
            # Check for numeric subdomains
            numeric_subs = [s for s in subdomains if s.isdigit()]
            if numeric_subs:
                risks.append(('Numeric Subdomain', 30, 
                            f'Subdomain uses only digits: {".".join(numeric_subs)}'))
                score += 30
            
            # Check for very long subdomains
            long_subs = [s for s in subdomains if len(s) > 20]
            if long_subs:
                weight = len(long_subs) * 20
                risks.append(('Unusually Long Subdomain', min(weight, 40), 
                            f'Subdomain length: {max(len(s) for s in long_subs)} chars'))
                score += min(weight, 40)
        
        # 3. Domain Label Analysis
        if len(labels) >= 2:
            sld = labels[-2]  # Second-level domain
            
            # Check for hyphens in SLD
            if '-' in sld:
                hyphen_count = sld.count('-')
                if hyphen_count > 2:
                    weight = hyphen_count * 15
                    risks.append(('Multiple Hyphens in Domain', min(weight, 40), 
                                f'{hyphen_count} hyphens (typosquatting indicator)'))
                    score += min(weight, 40)
            
            # Check for digit sequences in SLD
            if re.search(r'\d{3,}', sld):
                risks.append(('Digit Sequence in Domain', 35, 
                            'Domain contains 3+ consecutive digits'))
                score += 35
        
        # 4. TLD Analysis
        if len(labels) >= 1:
            tld = labels[-1].lower()
            
            # Country-code TLDs often abused
            high_abuse_cctlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc']
            if tld in high_abuse_cctlds:
                risks.append(('High-Abuse ccTLD', 45, 
                            f'.{tld} TLD has very high abuse rates'))
                score += 45
            
            # New gTLDs with elevated risk
            risky_gtlds = ['click', 'download', 'loan', 'win', 'work', 'bid']
            if tld in risky_gtlds:
                risks.append(('Risky gTLD', 30, 
                            f'.{tld} TLD associated with malicious campaigns'))
                score += 30
        
        # 5. Domain Registration Pattern Analysis
        # Check for suspicious patterns in domain name
        patterns = {
            r'(secure|verify|account|login|update)\d+': 'Security keyword with digit',
            r'\d{4,}': 'Long numeric sequence',
            r'(.)\1{3,}': 'Repeated characters (4+)',
            r'[A-Za-z]{20,}': 'Very long word (20+ chars)'
        }
        
        for pattern, description in patterns.items():
            if re.search(pattern, netloc):
                risks.append(('Suspicious Domain Pattern', 25, description))
                score += 25
                break
        
        return score, risks


class AdvancedContentAnalyzer:
    """
    Category 5: Advanced Content/HTML Features
    Sophisticated HTML structure and content analysis
    """
    
    @staticmethod
    def analyze(soup, domain):
        """Perform advanced content analysis on BeautifulSoup object"""
        risks = []
        score = 0
        
        if not soup:
            return score, risks
        
        # 1. DOM Depth Analysis
        max_depth = AdvancedContentAnalyzer._calculate_dom_depth(soup)
        if max_depth > 15:
            weight = (max_depth - 15) * 3
            risks.append(('Deep DOM Structure', min(weight, 30), 
                        f'DOM depth: {max_depth} levels (complexity)'))
            score += min(weight, 30)
        
        # 2. Meta Tag Analysis
        meta_tags = soup.find_all('meta')
        
        # Check for suspicious meta refresh
        for meta in meta_tags:
            if meta.get('http-equiv', '').lower() == 'refresh':
                content = meta.get('content', '')
                if content and 'url=' in content.lower():
                    refresh_url = content.lower().split('url=')[1]
                    if domain not in refresh_url:
                        risks.append(('External Meta Refresh', 45, 
                                    'Meta refresh redirects to different domain'))
                        score += 45
        
        # Check for missing essential meta tags
        essential_metas = ['description', 'viewport']
        found_metas = [m.get('name', '').lower() for m in meta_tags]
        missing_metas = [m for m in essential_metas if m not in found_metas]
        if len(missing_metas) == len(essential_metas):
            risks.append(('Missing Essential Meta Tags', 20, 
                        'No description or viewport meta tags'))
            score += 20
        
        # 3. Form Analysis (advanced)
        forms = soup.find_all('form')
        for form in forms:
            # Check form method
            method = form.get('method', 'get').lower()
            action = form.get('action', '')
            
            # POST to external domain
            if method == 'post' and action:
                if action.startswith('http') and domain not in action:
                    risks.append(('External POST Form', 60, 
                                'Form POSTs credentials to external domain'))
                    score += 60
            
            # Check for hidden fields with suspicious names
            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            suspicious_hidden = [inp for inp in hidden_inputs 
                               if any(name in inp.get('name', '').lower() 
                                     for name in ['password', 'token', 'session'])]
            if suspicious_hidden:
                risks.append(('Suspicious Hidden Fields', 35, 
                            f'{len(suspicious_hidden)} hidden fields with sensitive names'))
                score += 35
        
        # 4. External Resource Analysis
        external_resources = 0
        total_resources = 0
        
        for tag in soup.find_all(['script', 'link', 'img']):
            src = tag.get('src') or tag.get('href')
            if src:
                total_resources += 1
                if src.startswith('http') and domain not in src:
                    external_resources += 1
        
        if total_resources > 5:
            external_ratio = external_resources / total_resources
            if external_ratio > 0.8:
                weight = int((external_ratio - 0.8) * 100)
                risks.append(('High External Resource Ratio', min(weight, 40), 
                            f'{int(external_ratio * 100)}% resources from external domains'))
                score += min(weight, 40)
        
        # 5. Title and Heading Analysis
        title = soup.find('title')
        if not title or not title.string or len(title.string.strip()) < 3:
            risks.append(('Missing/Empty Title', 25, 
                        'Page has no meaningful title'))
            score += 25
        
        # Check for misleading titles
        if title and title.string:
            title_text = title.string.lower()
            misleading_keywords = ['verify', 'suspended', 'locked', 'urgent', 'immediate action']
            if any(kw in title_text for kw in misleading_keywords):
                risks.append(('Misleading Page Title', 30, 
                            'Title contains urgency/threat keywords'))
                score += 30
        
        return score, risks
    
    @staticmethod
    def _calculate_dom_depth(element, depth=0):
        """Calculate maximum DOM tree depth"""
        if not element.contents:
            return depth
        return max(AdvancedContentAnalyzer._calculate_dom_depth(child, depth + 1) 
                  for child in element.contents if hasattr(child, 'contents'))


class AdvancedJavaScriptAnalyzer:
    """
    Category 6: Advanced JavaScript Features
    Sophisticated JavaScript code analysis
    """
    
    @staticmethod
    def analyze(soup):
        """Perform advanced JavaScript analysis"""
        risks = []
        score = 0
        
        if not soup:
            return score, risks
        
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_text = script.string or ''
            if not script_text:
                continue
            
            # 1. Obfuscation Detection (advanced)
            # Check for eval chains
            eval_chain = len(re.findall(r'eval\s*\(', script_text))
            if eval_chain >= 2:
                weight = eval_chain * 25
                risks.append(('Eval Chain Detected', min(weight, 60), 
                            f'{eval_chain} chained eval() calls (heavy obfuscation)'))
                score += min(weight, 60)
            
            # 2. String Concatenation Obfuscation
            concat_patterns = len(re.findall(r'[\'"]\s*\+\s*[\'"]', script_text))
            if concat_patterns > 20:
                weight = int(concat_patterns / 5)
                risks.append(('String Concatenation Obfuscation', min(weight, 45), 
                            f'{concat_patterns} string concatenations'))
                score += min(weight, 45)
            
            # 3. Suspicious Function Calls
            dangerous_functions = {
                'eval(': 40,
                'Function(': 35,
                'setTimeout(': 15,
                'setInterval(': 15,
                'document.write(': 30,
                'innerHTML': 20,
                'outerHTML': 25,
                'fromCharCode': 30
            }
            
            for func, weight in dangerous_functions.items():
                if func in script_text:
                    count = script_text.count(func)
                    if count >= 2:
                        risks.append((f'Multiple {func} Calls', min(weight * count, 55), 
                                    f'{count} occurrences of {func}'))
                        score += min(weight * count, 55)
                        break
            
            # 4. Hex/Unicode Escape Analysis
            hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', script_text))
            unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', script_text))
            
            total_escapes = hex_escapes + unicode_escapes
            if total_escapes > 10:
                weight = int(total_escapes / 3)
                risks.append(('Escape Sequence Obfuscation', min(weight, 50), 
                            f'{total_escapes} hex/unicode escapes'))
                score += min(weight, 50)
            
            # 5. Base64 Detection
            base64_pattern = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', script_text)
            if base64_pattern:
                risks.append(('Base64 Encoded Data', 35, 
                            f'{len(base64_pattern)} base64 strings (possible payload)'))
                score += 35
            
            # 6. Redirect Pattern Detection
            redirect_patterns = [
                r'window\.location\s*=',
                r'location\.href\s*=',
                r'location\.replace\s*\(',
                r'document\.location\s*='
            ]
            
            redirect_count = sum(len(re.findall(pattern, script_text)) 
                               for pattern in redirect_patterns)
            if redirect_count >= 2:
                weight = redirect_count * 20
                risks.append(('Multiple Redirect Mechanisms', min(weight, 50), 
                            f'{redirect_count} different redirect methods'))
                score += min(weight, 50)
            
            # 7. Credential Harvesting Indicators
            credential_patterns = [
                r'password\s*[=:]',
                r'username\s*[=:]',
                r'token\s*[=:]',
                r'session\s*[=:]',
                r'cookie\s*[=:]'
            ]
            
            credential_matches = sum(len(re.findall(pattern, script_text.lower())) 
                                   for pattern in credential_patterns)
            if credential_matches >= 2:
                weight = credential_matches * 20
                risks.append(('Credential Handling in Script', min(weight, 55), 
                            f'{credential_matches} credential-related operations'))
                score += min(weight, 55)
        
        return score, risks


class AdvancedHeuristicAnalyzer:
    """
    Category 9: Advanced Heuristic/NLP Features
    Natural language processing and semantic analysis
    """
    
    @staticmethod
    def analyze(soup, url):
        """Perform heuristic and NLP analysis"""
        risks = []
        score = 0
        
        if not soup:
            return score, risks
        
        # 1. Brand Name Detection (extended list)
        major_brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
            'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
            'yahoo', 'ebay', 'walmart', 'target', 'chase', 'bankofamerica',
            'wellsfargo', 'citibank', 'americanexpress', 'visa', 'mastercard',
            'dhl', 'fedex', 'ups', 'usps', 'irs', 'ssa', 'usbank'
        ]
        
        page_text = soup.get_text().lower()
        url_lower = url.lower()
        
        # Check if brand mentioned in content but not in official domain
        mentioned_brands = [brand for brand in major_brands if brand in page_text]
        
        for brand in mentioned_brands:
            # Check if it's the official domain
            if brand not in url_lower or not url_lower.endswith(f'{brand}.com'):
                risks.append(('Brand Impersonation', 55, 
                            f'Page mentions "{brand}" but domain is not official'))
                score += 55
                break
        
        # 2. Suspicious Keyword Analysis
        urgency_keywords = {
            'verify your account': 45,
            'suspended account': 50,
            'unusual activity': 40,
            'confirm your identity': 45,
            'update payment': 45,
            'account locked': 50,
            'immediate action': 40,
            'click here to secure': 45,
            'limited time': 30,
            'act now': 30,
            'expire today': 35,
            'claim your': 30
        }
        
        keyword_count = 0
        for keyword, weight in urgency_keywords.items():
            if keyword in page_text:
                keyword_count += 1
                if keyword_count >= 3:
                    risks.append(('Multiple Urgency Keywords', 50, 
                                f'{keyword_count} urgency/threat phrases detected'))
                    score += 50
                    break
        
        # 3. Language Consistency Analysis
        # Check for mixed language content (common in phishing)
        scripts_used = set()
        for char in page_text:
            try:
                char_script = unicodedata.name(char).split()[0]
                if char_script in ['LATIN', 'CYRILLIC', 'ARABIC', 'CHINESE', 'JAPANESE']:
                    scripts_used.add(char_script)
            except:
                pass
        
        if len(scripts_used) > 2:
            risks.append(('Mixed Language Scripts', 35, 
                        f'Page uses {len(scripts_used)} different writing systems'))
            score += 35
        
        # 4. Spelling and Grammar Analysis (basic)
        # Check for common phishing spelling errors
        common_errors = ['varification', 'confrim', 'acount', 'secrity', 'notifcation']
        found_errors = [error for error in common_errors if error in page_text]
        
        if found_errors:
            weight = len(found_errors) * 20
            risks.append(('Spelling Errors', min(weight, 40), 
                        f'Common phishing misspellings: {", ".join(found_errors)}'))
            score += min(weight, 40)
        
        # 5. Semantic Inconsistency Detection
        title = soup.find('title')
        if title and title.string:
            title_brands = [b for b in major_brands if b in title.string.lower()]
            content_brands = [b for b in major_brands if b in page_text]
            
            # Title mentions different brand than content
            if title_brands and content_brands and set(title_brands) != set(content_brands):
                risks.append(('Brand Inconsistency', 40, 
                            'Title and content reference different brands'))
                score += 40
        
        return score, risks


class AdvancedBehavioralAnalyzer:
    """
    Category 10: Advanced Behavioral Features
    Pattern recognition and anomaly detection
    """
    
    @staticmethod
    def analyze(url, all_risks):
        """Perform behavioral and correlation analysis"""
        risks = []
        score = 0
        
        # 1. Multi-Factor Correlation Analysis
        # Count how many different risk categories have been triggered
        risk_categories = set()
        for category_risks in all_risks.values():
            if isinstance(category_risks, tuple) and category_risks[1]:
                risk_categories.add(category_risks)
        
        category_count = len([r for r in all_risks.values() if isinstance(r, tuple) and r[0] > 0])
        
        # High correlation of risks across categories is very suspicious
        if category_count >= 4:
            weight = (category_count - 3) * 20
            risks.append(('Multi-Category Risk Correlation', min(weight, 60), 
                        f'Risks detected in {category_count} different categories'))
            score += min(weight, 60)
        
        # 2. Anomaly Score Calculation
        # Calculate total accumulated risk
        total_accumulated_risk = sum(r[0] for r in all_risks.values() if isinstance(r, tuple))
        
        # If accumulated risk is very high (>100), it's a strong anomaly
        if total_accumulated_risk > 100:
            weight = int((total_accumulated_risk - 100) / 5)
            risks.append(('High Anomaly Score', min(weight, 50), 
                        f'Accumulated risk: {total_accumulated_risk} points'))
            score += min(weight, 50)
        
        # 3. Pattern Clustering
        # Check for clustering of related risks
        obfuscation_indicators = 0
        phishing_indicators = 0
        malware_indicators = 0
        
        for category_risks in all_risks.values():
            if isinstance(category_risks, tuple):
                for risk_item in category_risks[1]:
                    risk_name = risk_item[0].lower()
                    if any(keyword in risk_name for keyword in ['obfuscat', 'encod', 'hex', 'base64']):
                        obfuscation_indicators += 1
                    if any(keyword in risk_name for keyword in ['brand', 'phish', 'spoof', 'mimic']):
                        phishing_indicators += 1
                    if any(keyword in risk_name for keyword in ['exec', 'payload', 'malicious']):
                        malware_indicators += 1
        
        if obfuscation_indicators >= 3:
            risks.append(('Obfuscation Pattern Cluster', 45, 
                        f'{obfuscation_indicators} obfuscation techniques detected'))
            score += 45
        
        if phishing_indicators >= 3:
            risks.append(('Phishing Pattern Cluster', 50, 
                        f'{phishing_indicators} phishing indicators detected'))
            score += 50
        
        # 4. Confidence Scoring
        # Higher confidence when multiple independent checks agree
        if category_count >= 3 and total_accumulated_risk > 80:
            risks.append(('High Confidence Threat', 40, 
                        'Multiple independent checks confirm threat'))
            score += 40
        
        return score, risks


class AdvancedCertificateAnalyzer:
    """
    NEW CATEGORY: Certificate Transparency and Advanced SSL Analysis
    Detects suspicious certificate patterns without external CT log lookups
    """
    
    @staticmethod
    def analyze(url, existing_ssl_info=None):
        """Perform advanced certificate analysis"""
        risks = []
        score = 0
        
        import ssl
        import socket
        from urllib.parse import urlparse
        from datetime import datetime
        
        parsed = urlparse(url)
        hostname = parsed.netloc
        port = parsed.port or 443
        
        if not parsed.scheme or parsed.scheme != 'https':
            return score, risks
        
        # NEW: Check for subdomains of known legitimate domains
        # This helps with domains like web.whatsapp.com, m.facebook.com, etc.
        from config import Config
        is_trusted_subdomain = False
        for trusted_domain in Config.TRUSTED_DOMAINS:
            if hostname.lower().endswith('.' + trusted_domain.lower()) or hostname.lower() == trusted_domain.lower():
                is_trusted_subdomain = True
                break
        
        # If trusted subdomain, reduce sensitivity
        if is_trusted_subdomain:
            # Apply reduced sensitivity to all certificate checks
            cert_sensitivity_multiplier = 0.3
        else:
            cert_sensitivity_multiplier = 1.0
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # 1. NEW PARAMETER: Certificate Issuer Analysis
                    # Check if issued by known CA or self-signed
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    issuer_cn = issuer.get('commonName', '')
                    subject_cn = subject.get('commonName', '')
                    
                    # Self-signed certificate (issuer == subject)
                    if issuer_cn == subject_cn and issuer_cn:
                        weight = int(60 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Self-Signed Certificate', weight, 
                                        'Certificate is self-signed (not from trusted CA)'))
                            score += weight
                    
                    # 2. NEW PARAMETER: Certificate Age Analysis
                    # Very new certificates (<7 days) on unknown sites are suspicious
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    cert_age_days = (datetime.now() - not_before).days
                    
                    if cert_age_days < 7:
                        weight = int(50 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Very New Certificate', weight, 
                                        f'Certificate issued {cert_age_days} days ago (suspicious)'))
                            score += weight
                    elif cert_age_days < 30:
                        weight = int(25 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('New Certificate', weight, 
                                        f'Certificate issued {cert_age_days} days ago'))
                            score += weight
                    
                    # 3. NEW PARAMETER: Certificate Validity Period
                    # Certificates with very long validity (>2 years) are suspicious
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    validity_days = (not_after - not_before).days
                    
                    if validity_days > 825:  # >2.25 years (CA/B Forum limit is 825 days)
                        weight = int(55 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Excessive Validity Period', weight, 
                                        f'Certificate valid for {validity_days} days (exceeds standards)'))
                        score += weight
                    elif validity_days > 730:
                        weight = int(30 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Long Validity Period', weight, 
                                        f'Certificate valid for {validity_days} days'))
                        score += weight
                    
                    # 4. NEW PARAMETER: Subject Alternative Names (SAN) Analysis
                    # Too many SANs or wildcard patterns can be suspicious
                    san_list = []
                    for san_type, san_value in cert.get('subjectAltName', []):
                        if san_type == 'DNS':
                            san_list.append(san_value)
                    
                    if len(san_list) > 100:
                        weight = int(40 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Excessive SANs', weight, 
                                        f'Certificate has {len(san_list)} domains (shared hosting or suspicious)'))
                            score += weight
                    
                    # Check for suspicious wildcard usage
                    wildcard_count = sum(1 for san in san_list if san.startswith('*.'))
                    if wildcard_count > 5:
                        weight = int(35 * cert_sensitivity_multiplier)
                        if weight > 0:
                            risks.append(('Multiple Wildcards', weight, 
                                        f'{wildcard_count} wildcard certificates'))
                            score += weight
                    
                    # 5. NEW PARAMETER: Certificate Key Size
                    # Small key sizes (<2048 bits) are insecure
                    # Note: This requires pyOpenSSL, simplified check here
                    # In production, you'd parse the public key properly
                    
                    # 6. NEW PARAMETER: Certificate Chain Depth
                    # Self-signed or short chains are suspicious
                    # This would require more advanced parsing
                    
        except ssl.SSLError as e:
            # SSL errors already handled by ssl_checker.py
            pass
        except socket.timeout:
            risks.append(('Certificate Fetch Timeout', 20, 
                        'Could not retrieve certificate (timeout)'))
            score += 20
        except Exception as e:
            # Connection failed - might already be flagged
            pass
        
        return score, risks


def perform_advanced_analysis(url, soup=None, existing_risks=None):
    """
    Main function to perform all advanced analysis
    Returns aggregated results from all feature categories
    """
    results = {}
    
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or ''
        
        # Category 1: Lexical Analysis
        lexical_score, lexical_risks = AdvancedLexicalAnalyzer.analyze(url)
        results['advanced_lexical'] = (lexical_score, lexical_risks)
        
        # Category 2: Structural Analysis
        structural_score, structural_risks = AdvancedStructuralAnalyzer.analyze(url)
        results['advanced_structural'] = (structural_score, structural_risks)
        
        # Category 3: Domain Analysis
        domain_score, domain_risks = AdvancedDomainAnalyzer.analyze(url, netloc)
        results['advanced_domain'] = (domain_score, domain_risks)
        
        # NEW CATEGORY: Advanced Certificate Analysis
        cert_score, cert_risks = AdvancedCertificateAnalyzer.analyze(url)
        results['advanced_certificate'] = (cert_score, cert_risks)
        
        # Categories requiring soup object
        if soup:
            # Category 5: Content Analysis
            content_score, content_risks = AdvancedContentAnalyzer.analyze(soup, netloc)
            results['advanced_content'] = (content_score, content_risks)
            
            # Category 6: JavaScript Analysis
            js_score, js_risks = AdvancedJavaScriptAnalyzer.analyze(soup)
            results['advanced_javascript'] = (js_score, js_risks)
            
            # Category 9: Heuristic/NLP Analysis
            heuristic_score, heuristic_risks = AdvancedHeuristicAnalyzer.analyze(soup, url)
            results['advanced_heuristic'] = (heuristic_score, heuristic_risks)
        
        # Category 10: Behavioral Analysis (requires all previous results)
        if existing_risks:
            all_risks = {**existing_risks, **results}
            behavioral_score, behavioral_risks = AdvancedBehavioralAnalyzer.analyze(url, all_risks)
            results['advanced_behavioral'] = (behavioral_score, behavioral_risks)
        
        # Phase 2++: OCR Analysis integration
        # Note: In production, we'd pass the screenshot path, but for now we look for it in the static folder
        # based on the URL hash as defined in snapshot.py
        import os
        url_hash = abs(hash(url))
        screenshot_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'screenshots', f'{url_hash}.png')
        
        if os.path.exists(screenshot_path):
            try:
                from modules.ocr_analyzer import ocr_engine
                if ocr_engine.enabled:
                    text = ocr_engine.extract_text(screenshot_path)
                    ocr_score, ocr_risks = ocr_engine.analyze_text(text)
                    if ocr_risks:
                         results['ocr_analysis'] = (ocr_score, ocr_risks)
            except Exception:
                pass

        
    except Exception as e:
        results['advanced_error'] = (5, [('Advanced Analysis Error', 5, f'Error: {str(e)[:50]}')])
    
    return results
