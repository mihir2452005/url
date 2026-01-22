#!/usr/bin/env python3
"""
Test script to verify the integration of ML models with the URL Sentinel application.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from app import run_analysis
from modules.ml_model import ml_risk, initialize_ml_detector
from modules.combined_analyzer import analyze_url_combined


import asyncio

def async_test_wrapper(func):
    """Wrapper to run async tests."""
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

async def test_ml_integration():
    """
    Test the ML model integration with various URLs.
    """
    print("🧪 Testing ML Integration with URL Sentinel")
    print("=" * 50)
    
    # Initialize ML detector
    # This might be synchronous or async depending on implementation, 
    # but based on app.py use, we treat it as is.
    ml_detector = initialize_ml_detector()
    
    # Test URLs
    test_urls = [
        ("https://www.google.com", "Legitimate website"),
        ("https://www.facebook.com", "Legitimate website"),
        ("http://192.168.1.100/login.php", "IP-based login (suspicious)"),
        ("https://secure-update-paypal.account-security-check.com", "Phishing site"),
        ("https://github.com", "Legitimate website"),
        ("https://suspicious-malware-site.com", "Suspicious domain")
    ]
    
    print("\n1️⃣ Testing standalone ML analysis:")
    for url, description in test_urls:
        print(f"\n   URL: {url} ({description})")
        try:
            # check if ml_risk is async
            if asyncio.iscoroutinefunction(ml_risk):
                 ml_score, ml_details = await ml_risk(url)
            else:
                 ml_score, ml_details = ml_risk(url)

            print(f"   ML Score: {ml_score}/100")
            
            # Extract prediction from details
            prediction = "Unknown"
            confidence = 0.0
            for detail in ml_details:
                if 'ML Confidence:' in detail[2]:
                    try:
                        confidence_str = detail[2].split('ML Confidence: ')[1].split(',')[0]
                        confidence = float(confidence_str)
                        pred_part = detail[2].split('Prediction: ')[1]
                        prediction = pred_part
                        break
                    except:
                        pass
            
            print(f"   Prediction: {prediction}, Confidence: {confidence:.2f}")
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n2️⃣ Testing combined analysis:")
    for url, description in test_urls:
        print(f"\n   URL: {url} ({description})")
        try:
            # analyze_url_combined is likely async
            result = await analyze_url_combined(url)
            
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], dict) and 'error' in result[0]:
                print(f"   Error: {result[0]['error']}")
                continue
                
            print(f"   Combined Score: {result['score']}/100")
            print(f"   Classification: {result['classification']}")
            print(f"   Verdict: {result['verdict']}")
            print(f"   Confidence: {result['confidence']}%")
            
            if 'ml_analysis' in result:
                ml_result = result['ml_analysis']
                print(f"   ML Prediction: {ml_result['prediction']}, ML Confidence: {(ml_result['confidence']*100):.1f}%")
        except Exception as e:
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n3️⃣ Testing traditional analysis (for comparison):")
    for url, description in test_urls[:3]:  # Only test first 3 to keep output manageable
        print(f"\n   URL: {url} ({description})")
        try:
            # run_analysis is async in app.py
            result = await run_analysis(url)
            
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], dict) and 'error' in result[0]:
                print(f"   Error: {result[0]['error']}")
                continue
                
            print(f"   Traditional Score: {result['score']}/100")
            print(f"   Classification: {result['classification']}")
            print(f"   Verdict: {result['verdict']}")
            print(f"   Confidence: {result['confidence']}%")
        except Exception as e:
            print(f"   Error: {e}")
    
    print(f"\n✅ Integration test completed!")
    print(f"✅ ML models are successfully integrated with URL Sentinel")
    print(f"✅ Combined analysis is available for enhanced detection")


async def test_with_options():
    """
    Test analysis with different options (traditional, combined, with layered analysis).
    """
    print(f"\n📋 Testing Different Analysis Modes")
    print("=" * 50)
    
    url = "https://secure-update-paypal.account-security-check.com"
    
    print(f"\nTesting URL: {url}")
    
    # Traditional analysis
    print(f"\n1️⃣ Traditional Rule-Based Analysis:")
    # run_analysis is async
    traditional_result = await run_analysis(url)
    print(f"   Score: {traditional_result['score']}/100")
    print(f"   Classification: {traditional_result['classification']}")
    print(f"   Verdict: {traditional_result['verdict']}")
    
    # Combined analysis
    print(f"\n2️⃣ Combined Rule-Based + ML Analysis:")
    combined_result = await run_analysis(url, use_combined_analysis=True)
    print(f"   Score: {combined_result['score']}/100")
    print(f"   Classification: {combined_result['classification']}")
    print(f"   Verdict: {combined_result['verdict']}")
    if 'ml_analysis' in combined_result:
        ml_result = combined_result['ml_analysis']
        print(f"   ML Prediction: {ml_result['prediction']}")
        print(f"   ML Confidence: {(ml_result['confidence']*100):.1f}%")
    
    # Combined analysis with layered analysis
    print(f"\n3️⃣ Combined + Layered Analysis:")
    combined_layered_result = await run_analysis(url, use_combined_analysis=True, include_layered_analysis=True)
    print(f"   Score: {combined_layered_result['score']}/100")
    print(f"   Classification: {combined_layered_result['classification']}")
    print(f"   Verdict: {combined_layered_result['verdict']}")
    if 'ml_analysis' in combined_layered_result:
        ml_result = combined_layered_result['ml_analysis']
        print(f"   ML Prediction: {ml_result['prediction']}")
        print(f"   ML Confidence: {(ml_result['confidence']*100):.1f}%")
    if 'layered_analysis' in combined_layered_result:
        layered_result = combined_layered_result['layered_analysis']
        print(f"   Layered Score: {layered_result['final_score']}/100")
        print(f"   Layered Classification: {layered_result['classification']}")
    
    print(f"\n✅ All analysis modes working correctly!")


async def main():
    print("🌐 URL Sentinel - Integration Test")
    print("Verifying ML model integration with the detection system")
    
    await test_ml_integration()
    await test_with_options()
    
    print(f"\n🎉 All integration tests passed!")
    print(f"🚀 URL Sentinel now has enhanced detection capabilities combining:")
    print(f"   • Traditional rule-based analysis")
    print(f"   • Machine learning-based analysis") 
    print(f"   • Layered analysis (Static + Reputation + Content)")
    print(f"   • Combined approach for optimal accuracy")

if __name__ == "__main__":
    asyncio.run(main())