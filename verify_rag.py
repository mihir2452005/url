
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

try:
    from modules.local_detection import LocalUrlDetector
    print("Successfully imported LocalUrlDetector")
except ImportError as e:
    print(f"Failed to import LocalUrlDetector: {e}")
    sys.exit(1)

def test_rag():
    print("\nInitializing LocalUrlDetector...")
    detector = LocalUrlDetector()
    
    print(f"\nRAG Enabled: {detector.rag_enabled}")
    
    if detector.rag_enabled:
        print("RAG models loaded successfully.")
    else:
        print("RAG models failed to load.")
        return

    # Test with a known signature to trigger RAG
    test_url = "http://example.com/secure-login-verify-account" 
    # This matches "secure-login-verify-account" signature
    
    print(f"\nAnalyzing URL: {test_url}")
    score, risks = detector.analyze(test_url)
    
    print(f"Score: {score}")
    print("Risks found:")
    rag_triggered = False
    for r in risks:
        print(f" - {r}")
        if "AI Pattern Match" in r[0]:
            rag_triggered = True
            
    if rag_triggered:
        print("\nSUCCESS: RAG mechanism triggered correctly!")
    else:
        print("\nFAILURE: RAG mechanism did NOT trigger on matching URL.")

if __name__ == "__main__":
    test_rag()
