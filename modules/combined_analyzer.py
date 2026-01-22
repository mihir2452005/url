"""
Combined Analyzer Module for URL Detection
Combines rule-based analysis with machine learning models for enhanced detection.
"""
from modules.lexical import lexical_risk
from modules.domain import domain_risk
from modules.ssl_checker import ssl_risk
from modules.content_analyzer import content_risk
from modules.ml_model import ml_risk, MLUrlDetector
from modules.malicious_file_detector import malicious_file_risk
import threading
from modules.advanced_features import perform_advanced_analysis
from modules.layered_analysis import LayeredUrlAnalyzer
from urllib.parse import urlparse
from config import Config
import asyncio


class CombinedUrlAnalyzer:
    """
    Combines rule-based and ML-based URL analysis for enhanced detection.
    """
    
    def __init__(self):
        self.layered_analyzer = LayeredUrlAnalyzer()
    
    async def analyze_url_combined(self, url):
        """
        Perform combined analysis using both rule-based and ML approaches.
        """
        # First check if URL is valid
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {'error': 'Invalid URL'}, 400
        
        # CRITICAL: Early exit for trusted domains to prevent false positives
        domain = parsed.netloc.lower()
        if domain in [d.lower() for d in Config.TRUSTED_DOMAINS]:
            result = {
                'score': 0,
                'classification': 'Safe',
                'verdict': 'Safe',
                'confidence': 100.0,
                'breakdown': {
                    'trusted_domain': {
                        'score': 0,
                        'details': [('Trusted Domain', 0, 'Domain is in verified whitelist of legitimate sites')],
                        'weighted': 0
                    }
                },
                'risks': {
                    'trusted_domain': (0, [('Trusted Domain', 0, 'Domain is in verified whitelist of legitimate sites')])
                },
                'ml_analysis': {
                    'score': 0,
                    'prediction': 'Benign',
                    'confidence': 1.0,
                    'details': 'Trusted domain - no ML analysis needed'
                }
            }
            return result
        
        # Perform rule-based analysis
        rule_based_result = await self._perform_rule_based_analysis(url)
        
        # Perform ML-based analysis
        ml_result = await self._perform_ml_analysis(url)
        
        # Combine results
        combined_result = self._combine_results(rule_based_result, ml_result)
        
        return combined_result
    
    async def _perform_rule_based_analysis(self, url):
        """
        Perform traditional rule-based analysis.
        """
        from modules.scorer import compute_score
        
        risks = {}
        
        # Perform all rule-based analyses
        risks['lexical'] = lexical_risk(url)
        parsed = urlparse(url)
        risks['domain'] = domain_risk(parsed.netloc)
        risks['ssl'] = ssl_risk(url)
        
        # Content analysis
        content_result = await content_risk(url)
        risks['content'] = content_result
        
        # Advanced analysis
        try:
            advanced_results = await asyncio.to_thread(perform_advanced_analysis, url, None, risks)
            risks.update(advanced_results)
        except Exception as e:
            risks['advanced_error'] = (0, [('Advanced Analysis Skipped', 0, str(e)[:50])])
        
        # Malicious file detection
        try:
            risks['malicious_file'] = malicious_file_risk(url)
        except Exception as e:
            risks['malicious_file_error'] = (0, [('Malicious File Detection Error', 0, str(e)[:50])])
        
        # Compute rule-based score
        score, classification, breakdown = compute_score(risks)
        
        return {
            'score': score,
            'classification': classification,
            'breakdown': breakdown,
            'risks': risks
        }
    
    async def _perform_ml_analysis(self, url):
        """
        Perform ML-based analysis.
        """
        ml_score, ml_details = ml_risk(url)
        
        # Determine prediction based on score
        if ml_score < 30:
            prediction = 'Benign'
        elif ml_score < 70:
            prediction = 'Suspicious'
        else:
            prediction = 'Malicious'
        
        # Extract confidence from ML details if available
        confidence = 0.5  # Default confidence
        for detail in ml_details:
            if 'ML Confidence:' in detail[2]:
                try:
                    confidence_str = detail[2].split('ML Confidence: ')[1].split(',')[0]
                    confidence = float(confidence_str)
                    break
                except:
                    pass
        
        return {
            'score': ml_score,
            'prediction': prediction,
            'confidence': confidence,
            'details': ml_details
        }
    
    def _combine_results(self, rule_based_result, ml_result):
        """
        Combine rule-based and ML-based results.
        """
        # Weighted combination of scores
        # Give more weight to ML for accuracy (similar to VirusTotal), while keeping rule-based for interpretability
        rule_weight = 0.4  # Reduced weight for rule-based
        ml_weight = 0.6  # Increased weight for ML-based
        
        combined_score = (rule_based_result['score'] * rule_weight) + (ml_result['score'] * ml_weight)
        
        # Determine initial classification based on combined score
        if combined_score < Config.THRESHOLDS['safe']:
            classification = 'Safe'
        elif combined_score < Config.THRESHOLDS['suspicious']:
            classification = 'Suspicious'
        else:
            classification = 'Malicious'
        
        # CRITICAL: Override for high-confidence threats like EICAR test files
        # If malicious file detection identifies known threats, override the score/classification
        malicious_file_result = rule_based_result['risks'].get('malicious_file')
        if malicious_file_result and isinstance(malicious_file_result, tuple) and len(malicious_file_result) == 2:
            mf_score, mf_details = malicious_file_result
            if mf_score >= 90:  # Very high risk detected
                # Check for specific high-risk indicators
                high_risk_indicators = ['EICAR Test File']
                has_high_risk = any(any(indicator in detail[0] for indicator in high_risk_indicators) 
                                 for detail in mf_details if isinstance(detail, tuple) and len(detail) >= 1)
                
                if has_high_risk:
                    combined_score = 95  # Set to very high score
                    classification = 'Malicious'  # Override classification
                    # Ensure ML analysis reflects this
                    ml_result['prediction'] = 'Malicious'
                    ml_result['confidence'] = 1.0
        
        # CRITICAL: Override classification based on ML prediction with high confidence
        # This ensures alignment with ML results similar to VirusTotal
        if ml_result['confidence'] > 0.85:  # Very high confidence threshold
            if ml_result['prediction'] == 'Malicious':
                classification = 'Malicious'
            elif ml_result['prediction'] == 'Benign':
                classification = 'Safe'
        elif ml_result['confidence'] > 0.7:  # High confidence threshold
            if ml_result['prediction'] == 'Malicious' and classification != 'Malicious':
                classification = 'Suspicious'  # At least mark as suspicious
            elif ml_result['prediction'] == 'Benign' and classification != 'Safe':
                classification = 'Safe'  # Override to safe if ML is confident
        
        # Calculate combined confidence
        rule_confidence = self._derive_rule_confidence(rule_based_result)
        combined_confidence = (rule_confidence * rule_weight) + (ml_result['confidence'] * ml_weight)
        
        # Store ML override indicator
        ml_override = (ml_result['confidence'] > 0.7 and 
                       ((ml_result['prediction'] == 'Malicious' and classification == 'Malicious') or 
                        (ml_result['prediction'] == 'Benign' and classification == 'Safe')))
        
        # Derive verdict
        verdict = self._derive_verdict(combined_score, classification, rule_based_result['risks'])
        
        result = {
            'score': round(combined_score, 2),
            'classification': classification,
            'verdict': verdict,
            'confidence': round(combined_confidence * 100, 2),
            'breakdown': rule_based_result['breakdown'],
            'risks': rule_based_result['risks'],
            'ml_analysis': ml_result,
            'analysis_method': 'combined',
            'ml_override': ml_override  # Indicator if ML analysis influenced the final result
        }
        
        return result
    
    def _derive_rule_confidence(self, rule_result):
        """
        Derive confidence from rule-based analysis.
        """
        score = rule_result['score']
        classification = rule_result['classification']
        
        # Higher score typically means higher confidence in maliciousness
        if classification == 'Safe':
            # Lower risk + fewer engines -> higher confidence in safety
            base_confidence = max(0.0, min(1.0, (100.0 - score) / 100.0))
        elif classification == 'Suspicious':
            # Suspicious is inherently uncertain
            base_confidence = 0.6
        else:  # Malicious
            # Higher score indicates higher confidence in maliciousness
            base_confidence = max(0.5, min(1.0, score / 100.0))
        
        return base_confidence
    
    def _derive_verdict(self, score, classification, risks):
        """
        Derive a VirusTotal-like verdict (Safe, Suspicious, Phishing, Malicious).
        """
        phishing_names = {
            'Brand Mimicry',
            'Typosquatting',
            'Typosquatting (Fuzzy)',
            'Leetspeak Typosquatting',
            'Homograph Attack',
            'Punycode/IDN',
            'Social Engineering Lure',
            'External Form Action',
            'Insecure Password Field',
            'Hidden Password Field',
            'AI Pattern Match',
            'URL Shortener',
            'Excessive Subdomains',
            'High Hex Encoding',
            'IP Address URL',
            # Advanced feature phishing indicators
            'Advanced Homograph Attack',
            'Brand Impersonation',
            'Multiple Urgency Keywords',
            'Credential Handling in Script',
            'Suspicious Hidden Fields',
            'Phishing Pattern Cluster',
            'External POST Form',
            'Misleading Page Title'
        }

        phishing_flag = False
        for cat in ('lexical', 'content', 'ai_analysis', 'domain', 
                    'advanced_lexical', 'advanced_content', 'advanced_javascript', 
                    'advanced_heuristic', 'advanced_behavioral'):
            cat_result = risks.get(cat)
            if not cat_result:
                continue
            _, details = cat_result
            for name, _, _ in details:
                if name in phishing_names:
                    phishing_flag = True
                    break
            if phishing_flag:
                break

        if classification == 'Safe':
            return 'Safe'
        if classification == 'Suspicious':
            return 'Suspicious'
        # classification == 'Malicious'
        if phishing_flag:
            return 'Phishing'
        return 'Malicious'


# Global instance for use in the app
combined_analyzer = CombinedUrlAnalyzer()


async def analyze_url_combined(url):
    """
    Wrapper function for combined analysis.
    """
    return await combined_analyzer.analyze_url_combined(url)