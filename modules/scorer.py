from config import Config

def compute_score(risks_dict):
    """
    Aggregates risks with weights.
    Enhanced logic to prevent false positives on legitimate sites.
    Classification: Safe (0-40), Suspicious (41-70), Malicious (71+).
    """
    total = 0
    breakdown = {}
    cat_scores = {}
    
    for cat, (score, details) in risks_dict.items():
        if cat in Config.RISK_WEIGHTS:
            weighted = score * Config.RISK_WEIGHTS[cat]
            total += weighted
            cat_scores[cat] = {'score': score, 'details': details, 'weighted': weighted}
    
    # CRITICAL FIX: Cap the final score at 100 without aggressive multiplication
    # The previous "total * 10" was causing legitimate sites to hit 100%
    # New approach: scale more conservatively
    total = min(total, 100)  # Direct cap without multiplication
    
    if total < Config.THRESHOLDS['safe']:
        classification = 'Safe'
    elif total < Config.THRESHOLDS['suspicious']:
        classification = 'Suspicious'
    else:
        classification = 'Malicious'
    
    breakdown = cat_scores
    return total, classification, breakdown