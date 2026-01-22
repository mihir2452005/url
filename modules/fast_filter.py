import math
import hashlib
import os
import pickle

class BloomFilter:
    """
    A high-performance Bloom Filter implementation using standard libraries.
    Designed for zero-dependency, low-latency lookups (< 0.01ms).
    """
    def __init__(self, capacity=1000000, error_rate=0.001, filepath=None):
        """
        Initialize the Bloom Filter.
        
        Args:
            capacity (int): Expected number of elements to store.
            error_rate (float): Acceptable false positive rate (e.g., 0.001 = 0.1%).
            filepath (str, optional): Path to save/load the filter persistence.
        """
        self.capacity = capacity
        self.error_rate = error_rate
        self.filepath = filepath
        
        # Calculate optimal size (m) and hash functions (k)
        # m = -(n * ln(p)) / (ln(2)^2)
        self.size = int(-(capacity * math.log(error_rate)) / (math.log(2)**2))
        
        # k = (m/n) * ln(2)
        self.hash_count = int((self.size / capacity) * math.log(2))
        
        # Initialize bit array (using bytearray for memory efficiency in pure Python)
        # We need self.size bits, so self.size/8 bytes
        self.byte_size = (self.size + 7) // 8
        self.bit_array = bytearray(self.byte_size)
        
        # Load from disk if exists
        if filepath and os.path.exists(filepath):
            self.load()

    def _get_hash_indices(self, item):
        """
        Generate k hash indices for a given item using double hashing.
        Uses md5 and sha1 for speed and distribution in standard lib.
        """
        item_str = str(item).encode('utf-8')
        
        # Calculate two base hashes
        h1 = int(hashlib.sha1(item_str).hexdigest(), 16)
        h2 = int(hashlib.md5(item_str).hexdigest(), 16)
        
        indices = []
        for i in range(self.hash_count):
            # Double hashing: (h1 + i * h2) % m
            idx = (h1 + i * h2) % self.size
            indices.append(idx)
        return indices

    def add(self, item):
        """Add an item to the filter."""
        for idx in self._get_hash_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
    
    def check(self, item):
        """
        Check if an item exists in the filter.
        Returns:
            True: Item MIGHT exist (False Positive possible).
            False: Item DEFINITELY does not exist.
        """
        for idx in self._get_hash_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def save(self):
        """Save the filter to disk."""
        if not self.filepath:
            return
        
        with open(self.filepath, 'wb') as f:
            # We save metadata and the raw bytes
            pickle.dump({
                'capacity': self.capacity,
                'error_rate': self.error_rate,
                'hash_count': self.hash_count,
                'size': self.size,
                'bit_array': self.bit_array
            }, f)

    def load(self):
        """Load the filter from disk."""
        if not self.filepath or not os.path.exists(self.filepath):
            return
            
        try:
            with open(self.filepath, 'rb') as f:
                data = pickle.load(f)
                self.capacity = data['capacity']
                self.error_rate = data['error_rate']
                self.hash_count = data['hash_count']
                self.size = data['size']
                self.bit_array = data['bit_array']
        except Exception as e:
            print(f"Error loading BloomFilter: {e}")

# Global instance for easy import
# Initialize with 1 million capacity, 0.1% error rate
# This will consume approx 1.7 MB of RAM
url_filter = BloomFilter(capacity=1000000, error_rate=0.001, filepath='data/url_filter.bloom')
