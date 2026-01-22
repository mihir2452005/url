import asyncio
import sys
import os
import aiohttp
from bs4 import BeautifulSoup

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.content_analyzer import check_favicon
from modules.visual_model import visual_detector

async def test_favicon_forensics():
    print("\n--- Testing Favicon Forensics ---")
    url = "https://www.google.com"
    domain = "google.com"
    
    # Mocking a session and soup for the test
    # In a real test we would fetch real content or mock the response
    # Here we test the logic flows
    
    # 1. Test Load DB
    from modules.content_analyzer import load_brand_favicons
    db = load_brand_favicons()
    print(f"Database Loaded: {len(db)} brands found.")
    
    if len(db) > 0:
        print("[PASS] DB Load Passed")
    else:
        print("[FAIL] DB Load Failed")

async def test_visual_model():
    print("\n--- Testing Visual Siamese Model ---")
    # Test initialization
    if visual_detector:
        print("[PASS] Visual Detector Initialized")
    else:
        print("[FAIL] Visual Detector Failed")
        
    # Test embedding (simulated)
    emb = await visual_detector.compute_embedding("fake_image_data")
    if emb.shape == (1, 128):
         print("[PASS] Embedding Generation Passed (Shape: 1x128)")
    else:
         print(f"[FAIL] Embedding Generation Failed (Shape: {emb.shape})")

async def run_tests():
    await test_favicon_forensics()
    await test_visual_model()

if __name__ == "__main__":
    asyncio.run(run_tests())
