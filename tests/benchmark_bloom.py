import time
import sys
import os
import random
import string

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.fast_filter import BloomFilter

def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def run_benchmark():
    print("Starting Bloom Filter Benchmark...")
    
    capacity = 1000000
    bf = BloomFilter(capacity=capacity, error_rate=0.001)
    
    # 1. Add benchmarks
    print(f"Adding 10,000 items...")
    start_time = time.time()
    for _ in range(10000):
        bf.add(random_string())
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"Time to add 10,000 items: {elapsed:.4f}s")
    print(f"Avg addition time: {(elapsed/10000)*1000000:.2f} microseconds")
    
    # 2. Check benchmarks
    print(f"Checking 10,000 items...")
    start_time = time.time()
    for _ in range(10000):
        bf.check(random_string())
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"Time to check 10,000 items: {elapsed:.4f}s")
    print(f"Avg check time: {(elapsed/10000)*1000000:.2f} microseconds")
    
    target_micros = 100 # 0.1ms is 100 microseconds
    current_micros = (elapsed/10000)*1000000
    
    if current_micros < target_micros:
        print(f"[PASS] Lookup speed ({current_micros:.2f} us) is faster than target ({target_micros} us)")
    else:
        print(f"[FAIL] Lookup speed ({current_micros:.2f} us) is slower than target ({target_micros} us)")

if __name__ == "__main__":
    run_benchmark()
