from flask import Flask, render_template, request, jsonify, redirect, url_for
from urllib.parse import urlparse
import threading
import time
import os
from modules.lexical import lexical_risk
from modules.domain import domain_risk
from modules.ssl_checker import ssl_risk
from modules.content_analyzer import content_risk
from modules.scorer import compute_score
from modules.local_detection import LocalUrlDetector
from modules.history_storage import AnalysisHistoryStorage
from modules.advanced_features import perform_advanced_analysis
from modules.layered_analysis import LayeredUrlAnalyzer
from modules.combined_analyzer import CombinedUrlAnalyzer, analyze_url_combined
from modules.ml_model import initialize_ml_detector
from modules.malicious_file_detector import malicious_file_risk
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for browser extension
from flask_cors import CORS
CORS(app, resources={r"/analyze": {"origins": "*"}})

# Initialize Local AI Detector (loads models once)
ai_detector = LocalUrlDetector()

# Initialize Layered URL Analyzer
layered_analyzer = LayeredUrlAnalyzer()

# Initialize persistent history storage
history_storage = AnalysisHistoryStorage()


def derive_verdict(score, classification, risks, ml_analysis_result=None):
    """Derive a VirusTotal-like verdict (Safe, Suspicious, Phishing, Malicious)."""
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
        'Misleading Page Title',
        # Malicious file indicators
        'EICAR Test File',
        'Suspicious File Extension',
        'Malicious Pattern Match',
        'Suspicious Keyword'
    }

    # Check if ML analysis should influence the verdict
    ml_influence = False
    if ml_analysis_result and ml_analysis_result.get('prediction'):
        ml_prediction = ml_analysis_result['prediction']
        ml_confidence = ml_analysis_result.get('confidence', 0)
        
        # If ML is highly confident, prioritize its verdict
        if ml_confidence > 0.85:
            if ml_prediction == 'Malicious':
                # Check for phishing indicators to determine between 'Phishing' and 'Malicious'
                phishing_flag = False
                for cat in ('lexical', 'content', 'ai_analysis', 'domain', 
                            'advanced_lexical', 'advanced_content', 'advanced_javascript', 
                            'advanced_heuristic', 'advanced_behavioral', 'malicious_file'):
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
                return 'Phishing' if phishing_flag else 'Malicious'
            elif ml_prediction == 'Benign':
                return 'Safe'
        elif ml_confidence > 0.7:
            # Moderate confidence, but still consider ML input
            if ml_prediction == 'Malicious':
                # Check for phishing indicators
                phishing_flag = False
                for cat in ('lexical', 'content', 'ai_analysis', 'domain', 
                            'advanced_lexical', 'advanced_content', 'advanced_javascript', 
                            'advanced_heuristic', 'advanced_behavioral', 'malicious_file'):
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
                return 'Phishing' if phishing_flag else 'Malicious'
            elif ml_prediction == 'Benign':
                return 'Safe'

    # Fallback to traditional logic if ML influence is not applied
    phishing_flag = False
    for cat in ('lexical', 'content', 'ai_analysis', 'domain', 
                'advanced_lexical', 'advanced_content', 'advanced_javascript', 
                'advanced_heuristic', 'advanced_behavioral', 'malicious_file'):
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


def derive_confidence(score, classification, risks):
    """Confidence heuristic based on score, base classification, and number of detectors that fired."""
    engines_triggered = sum(1 for v in risks.values() if isinstance(v, tuple) and v[0] > 0)

    if classification == 'Safe':
        # Lower risk + fewer engines -> higher confidence in safety
        base = max(0.0, min(100.0, 100.0 - score))
        penalty = 5.0 * max(0, engines_triggered - 1)
        return max(0.0, base - penalty)

    if classification == 'Suspicious':
        # Suspicious is inherently uncertain but multiple engines raise confidence somewhat
        return float(min(90.0, 40.0 + 10.0 * engines_triggered))

    # Malicious / Phishing: higher score + more agreeing engines => higher confidence
    return float(min(100.0, max(score, 50.0) + 5.0 * max(0, engines_triggered - 1)))

def run_analysis(url, include_layered_analysis=False, use_combined_analysis=False):
    # If combined analysis is requested, use the new combined approach
    if use_combined_analysis:
        result = analyze_url_combined(url)
        if isinstance(result, tuple):
            return result  # Return error tuple if invalid URL
        
        # Include layered analysis if also requested
        if include_layered_analysis and 'layered_analysis' not in result:
            layered_result = layered_analyzer.analyze_url(url)
            result['layered_analysis'] = layered_result
        
        return result
    
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
            }
        }
        
        # Include layered analysis if requested
        if include_layered_analysis:
            layered_result = layered_analyzer.analyze_url(url)
            result['layered_analysis'] = layered_result
        
        return result
    
    risks = {}
    threads = []
    soup_object = None
    
    def thread_lexical():
        risks['lexical'] = lexical_risk(url)
    
    def thread_domain():
        risks['domain'] = domain_risk(parsed.netloc)
    
    def thread_ssl():
        risks['ssl'] = ssl_risk(url)
    
    def thread_content():
        # Capture soup object for advanced analysis
        nonlocal soup_object
        result = content_risk(url)
        risks['content'] = result
        # Try to get soup object from content_analyzer if available
        try:
            from modules.content_analyzer import get_last_soup
            soup_object = get_last_soup()
        except:
            pass
    
    def thread_ai():
        risks['ai_analysis'] = ai_detector.analyze(url)
    
    for func in [thread_lexical, thread_domain, thread_ssl, thread_content, thread_ai]:
        t = threading.Thread(target=func)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join(timeout=app.config['ANALYSIS_TIMEOUT'])
    
    # Run advanced feature analysis
    try:
        advanced_results = perform_advanced_analysis(url, soup_object, risks)
        # Merge advanced results into main risks
        risks.update(advanced_results)
    except Exception as e:
        # If advanced analysis fails, continue with basic analysis
        risks['advanced_error'] = (0, [('Advanced Analysis Skipped', 0, str(e)[:50])])
    
    # Run malicious file detection
    try:
        risks['malicious_file'] = malicious_file_risk(url)
    except Exception as e:
        # If malicious file detection fails, continue with analysis
        risks['malicious_file_error'] = (0, [('Malicious File Detection Error', 0, str(e)[:50])])
    
    score, classification, breakdown = compute_score(risks)
    
    # CRITICAL: Override for high-confidence threats like EICAR test files
    # If malicious file detection identifies known threats, override the score/classification
    malicious_file_result = risks.get('malicious_file')
    if malicious_file_result and isinstance(malicious_file_result, tuple) and len(malicious_file_result) == 2:
        mf_score, mf_details = malicious_file_result
        if mf_score >= 90:  # Very high risk detected
            # Check for specific high-risk indicators
            high_risk_indicators = ['EICAR Test File']
            has_high_risk = any(any(indicator in detail[0] for indicator in high_risk_indicators) 
                             for detail in mf_details if isinstance(detail, tuple) and len(detail) >= 1)
            
            if has_high_risk:
                score = 95  # Set to very high score
                classification = 'Malicious'  # Override classification
    
    # Also run ML analysis for comparison and potential override
    try:
        from modules.ml_model import ml_risk
        ml_score, ml_details = ml_risk(url)
        # Extract ML prediction and confidence if available
        ml_prediction = 'Benign'
        ml_confidence = 0.5
        for detail in ml_details:
            if 'ML Confidence:' in detail[2]:
                try:
                    confidence_str = detail[2].split('ML Confidence: ')[1].split(',')[0]
                    ml_confidence = float(confidence_str)
                    pred_part = detail[2].split('Prediction: ')[1]
                    ml_prediction = pred_part
                    break
                except:
                    pass
        
        # Pass ML analysis to verdict derivation
        verdict = derive_verdict(score, classification, risks, {'prediction': ml_prediction, 'confidence': ml_confidence})
    except:
        # If ML analysis fails, use traditional approach
        verdict = derive_verdict(score, classification, risks)
    
    confidence = derive_confidence(score, classification, risks)
    
    result = {
        'score': score,
        'classification': classification,
        'verdict': verdict,
        'confidence': confidence,
        'breakdown': breakdown,
        'risks': risks
    }
    
    # Include layered analysis if requested
    if include_layered_analysis:
        layered_result = layered_analyzer.analyze_url(url)
        result['layered_analysis'] = layered_result
    
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    chart_data = []
    if request.method == 'POST':
        url = request.form['url']
        include_layered = 'include_layered_analysis' in request.form
        use_combined = 'use_combined_analysis' in request.form
        
        result = run_analysis(url, include_layered_analysis=include_layered, use_combined_analysis=use_combined)
        if isinstance(result, tuple):
            result = result[0]  # Handle error tuple ({'error':...}, 400)
        else:
            # Save to history
            history_storage.add_analysis(url, result)
            chart_data = [item['weighted'] for item in result['breakdown'].values()]
        return render_template('index.html', 
                               result=result, 
                               url=url, 
                               chart_data=chart_data, 
                               include_layered_analysis=include_layered,
                               use_combined_analysis=use_combined)
    return render_template('index.html', chart_data=chart_data)

@app.route('/analyze', methods=['POST'])
def api_analyze():
    url = request.json['url']
    include_layered = request.json.get('include_layered_analysis', False)
    use_combined = request.json.get('use_combined_analysis', False)
    
    result = run_analysis(url, include_layered_analysis=include_layered, use_combined_analysis=use_combined)
    if not isinstance(result, tuple):  # Not an error
        history_storage.add_analysis(url, result)
    return jsonify(result)

@app.route('/healthz')
def health_check():
    """Health check endpoint for deployment."""
    return jsonify({'status': 'healthy', 'components': {'ai': ai_detector.rag_enabled}}), 200

@app.route('/history')
def history():
    """Display analysis history page."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    all_history = history_storage.get_all_history()
    total = len(all_history)
    total_pages = (total + per_page - 1) // per_page
    
    start = (page - 1) * per_page
    end = start + per_page
    page_history = all_history[start:end]
    
    stats = history_storage.get_statistics()
    
    return render_template('history.html', 
                          history=page_history, 
                          stats=stats,
                          page=page,
                          total_pages=total_pages,
                          total=total)

@app.route('/history/<entry_id>')
def history_detail(entry_id):
    """Display detailed view of a specific analysis."""
    entry = history_storage.get_by_id(entry_id)
    if not entry:
        return render_template('error.html', message='Analysis not found'), 404
    
    # Prepare chart data
    chart_data = []
    if 'breakdown' in entry:
        chart_data = [item.get('weighted', 0) for item in entry['breakdown'].values()]
    
    return render_template('history_detail.html', entry=entry, chart_data=chart_data)

@app.route('/history/search')
def history_search():
    """Search history with filters."""
    query = request.args.get('q', '')
    verdict = request.args.get('verdict', None)
    min_score = request.args.get('min_score', type=float)
    max_score = request.args.get('max_score', type=float)
    
    results = history_storage.search_history(
        query=query if query else None,
        verdict=verdict if verdict else None,
        min_score=min_score,
        max_score=max_score
    )
    
    stats = history_storage.get_statistics()
    
    return render_template('history.html', 
                          history=results, 
                          stats=stats,
                          search_query=query,
                          search_verdict=verdict,
                          page=1,
                          total_pages=1,
                          total=len(results))

@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear all analysis history."""
    history_storage.clear_history()
    return redirect(url_for('history'))

@app.route('/history/delete/<entry_id>', methods=['POST'])
def delete_history_entry(entry_id):
    """Delete a specific history entry."""
    history_storage.delete_entry(entry_id)
    return redirect(url_for('history'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # debug=False for production
    app.run(host='0.0.0.0', port=port, debug=False)