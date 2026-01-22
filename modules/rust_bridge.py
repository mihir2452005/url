import re
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("rust_bridge")

# Global flag to check if Rust is active
RUST_ACTIVE = False

try:
    # Attempt to import the compiled Rust extension
    import rust_core
    # Verify functions exist (to distinguish from source folder)
    if hasattr(rust_core, 'rust_is_ip_address'):
        RUST_ACTIVE = True
        logger.info("[TITAN] Rust acceleration module loaded successfully!")
    else:
        raise ImportError("Module found but functions missing (likely source folder)")
except ImportError:
    logger.info("[TITAN] Rust accelerator not linked. Using optimized Python engine (Standard Mode).")
    RUST_ACTIVE = False

# -------------------------------------------------------------------------
# BRIDGE FUNCTIONS
# These functions expose the Rust logic (or Python fallback) with a unified API.
# -------------------------------------------------------------------------

def is_ip_address(url):
    """
    Check if the URL hostname is an IP address.
    """
    if RUST_ACTIVE:
        return rust_core.rust_is_ip_address(url)
    else:
        # Python Fallback (Regex)
        # Matches IP patterns like 192.168.1.1
        ip_pattern = r"(?i)^(http://|https://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        return bool(re.match(ip_pattern, url))

def count_special_chars(url):
    """
    Count number of special characters in the URL.
    """
    if RUST_ACTIVE:
        return rust_core.rust_count_special_chars(url)
    else:
        # Python Fallback
        return sum(1 for c in url if not c.isalnum())

def has_suspicious_keywords(url):
    """
    Check for suspicious keywords (login, verify, etc.)
    """
    if RUST_ACTIVE:
        return rust_core.rust_has_suspicious_keywords(url)
    else:
        # Python Fallback
        keywords = ["login", "verify", "update", "bank", "paypal"]
        url_lower = url.lower()
        return any(k in url_lower for k in keywords)

# -------------------------------------------------------------------------
# BENCHMARK UTILITY
# -------------------------------------------------------------------------
def benchmark_interface():
    """
    Simple benchmark to show which core is running.
    """
    test_url = "https://www.paypal-secure-login.com/verify?token=123"
    
    start = time.perf_counter()
    for _ in range(10000):
        is_ip_address(test_url)
        count_special_chars(test_url)
        has_suspicious_keywords(test_url)
    end = time.perf_counter()
    
    ms_per_op = ((end - start) / 10000) * 1000
    return {
        "active_core": "RUST" if RUST_ACTIVE else "PYTHON",
        "latency_10k_ops": f"{(end - start):.4f}s",
        "us_per_op": f"{ms_per_op * 1000:.2f}µs"
    }
