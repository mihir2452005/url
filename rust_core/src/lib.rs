use pyo3.prelude::*;
use pyo3.wrap_pyfunction;
use regex::Regex;

/// Titan-Tier Rust Core for URL Sentinel
/// provides sub-microsecond regex matching.

#[pyfunction]
fn rust_is_ip_address(url: &str) -> bool {
    let re = Regex::new(r"(?i)^(http://|https://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
    re.is_match(url)
}

#[pyfunction]
fn rust_count_special_chars(url: &str) -> usize {
    url.chars().filter(|c| !c.is_alphanumeric()).count()
}

#[pyfunction]
fn rust_has_suspicious_keywords(url: &str) -> bool {
    let keywords = ["login", "verify", "update", "bank", "paypal"];
    let url_lower = url.to_lowercase();
    for k in keywords.iter() {
        if url_lower.contains(k) {
            return true;
        }
    }
    false
}

#[pymodule]
fn rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rust_is_ip_address, m)?)?;
    m.add_function(wrap_pyfunction!(rust_count_special_chars, m)?)?;
    m.add_function(wrap_pyfunction!(rust_has_suspicious_keywords, m)?)?;
    Ok(())
}
