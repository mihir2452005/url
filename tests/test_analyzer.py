import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from modules.lexical import lexical_risk
from modules.scorer import compute_score

def test_lexical():
    score, risks = lexical_risk('http://paypa1-login-secure.com')
    assert score > 0
    assert any('Typosquatting' in r[0] for r in risks)

def test_scorer():
    risks = {'lexical': (10, []), 'domain': (5, [])}
    score, _, _ = compute_score(risks)
    assert 0 <= score <= 100

if __name__ == "__main__":
    pytest.main([__file__])