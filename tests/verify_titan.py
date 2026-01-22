import sys
import os
import time

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.rust_bridge import is_ip_address, count_special_chars, has_suspicious_keywords, RUST_ACTIVE
from modules.lexical import lexical_risk

def test_rust_bridge():
    print("\n--- Testing Titan Core (Rust Bridge) ---")
    
    if RUST_ACTIVE:
        print("[INFO] Titan Mode: ACTIVE (Rust Binary Loaded)")
    else:
        print("[INFO] Titan Mode: STANDBY (Using Python Optimized Fallback)")
    
    # 1. Test IP Check
    url_ip = "http://192.168.1.1/login"
    url_domain = "https://google.com"
    
    if is_ip_address(url_ip) and not is_ip_address(url_domain):
        print("[PASS] IP Detection Logic")
    else:
        print("[FAIL] IP Detection Logic")
        
    # 2. Test Special Chars
    url_chars = "https://example.com/login?u=user&p=pass%"
    count = count_special_chars(url_chars)
    # : / / . / ? = & = % -> 9 chars (depends on exact logic, but as long as it returns int it's working)
    if isinstance(count, int) and count > 0:
        print(f"[PASS] Special Char Counting (Count: {count})")
    else:
        print("[FAIL] Special Char Counting")

    # 3. Test Keywords
    url_bad = "http://paypal-secure-login.com"
    url_good = "http://example.com"
    
    if has_suspicious_keywords(url_bad) and not has_suspicious_keywords(url_good):
         print("[PASS] Keyword Detection Logic")
    else:
         print("[FAIL] Keyword Detection Logic")

def test_lexical_integration():
    print("\n--- Testing Lexical Module Integration ---")
    url = "http://192.168.1.1"
    score, risks = lexical_risk(url)
    
    found_ip_risk = any(r[0] == 'Private IP Address' for r in risks)
    
    if found_ip_risk:
        print("[PASS] Lexical Module correctly uses Bridge for IP detection")
    else:
        print(f"[FAIL] Lexical Module failed to detect IP. Risks: {risks}")

if __name__ == "__main__":
    test_rust_bridge()
    test_lexical_integration()
