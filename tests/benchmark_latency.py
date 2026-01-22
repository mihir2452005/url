import asyncio
import time
import sys
import os
import json
from quart import Quart

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

async def run_benchmark():
    print("Starting Latency Benchmark...")
    
    # Create test client
    client = app.test_client()
    
    # Test URL (safe)
    url = "https://www.google.com"
    
    start_time = time.time()
    response = await client.post('/analyze', json={'url': url})
    end_time = time.time()
    
    data = await response.get_json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Verdict: {data.get('verdict')}")
    print(f"Total Latency: {(end_time - start_time) * 1000:.2f} ms")
    
    if response.status_code == 200:
        print("✅ Benchmark Passed: Analysis completed successfully.")
    else:
        print("❌ Benchmark Failed: Non-200 response.")

if __name__ == "__main__":
    asyncio.run(run_benchmark())
