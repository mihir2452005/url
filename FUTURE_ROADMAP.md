# Future Roadmap: URL Sentinel (Offline-First / Zero-Dependency)

This document outlines the upgrade path to make URL Sentinel a completely autonomous, self-hosted security platform that relies on **ZERO external APIs** while prioritizing **Explainable AI (XAI)**.

## 1. Local Intelligence Core ("The Vault")
*Goal: Replace external reputation APIs with high-performance local databases.*
- [ ] **Local Threat Database**: Module to sync/import raw CSV community blocklists (URLhaus, PhishTank) into a local PostgreSQL/SQLite instance.
- [ ] **Bloom Filter Lookup**: Implement probabilistic data structures (Rust-based) to check URLs against millions of known bad signatures in microseconds.
- [ ] **Passive DNS Collector**: Build a local history of domain resolutions to detect "Fast-Flux" and IP rotation anomalies without querying external history services.

## 2. Self-Hosted AI & RAG ("The On-Prem Brain")
*Goal: Content analysis using purely local models.*
- [ ] **Local LLM Inference**: Integrate `Ollama` or `llama.cpp` to run quantized models (Mistral, Llama-3) locally for semantic analysis.
- [ ] **Offline Vector DB**: Use `FAISS` with local persistence to match brand profiles (e.g., "This text looks 99% like Chase Bank") without cloud calls.
- [ ] **Local Computer Vision**: Implement on-device logo detection using `ONNX Runtime` and MobileNetV3.

## 3. Explainable AI (XAI) - "The Glass Box"
*Goal: Demystify AI decisions so humans trust the verdict (Zero API).*
- [ ] **Local Feature Importance (SHAP/LIME)**: Integrate Python libraries `shap` or `lime` to generate charts showing exactly *which* words or HTML tags triggered the alert.
- [ ] **Visual Saliency Maps**: Overlay "heatmaps" on screenshots to show where the local vision model detected a spoofed logo or login button.
- [ ] **"Judge's Verdict" Generator**: Use the local LLM to write a plain-English narrative (e.g., *"I flagged this because the domain uses a Cyrillic 'a' (homograph) AND the page contains a hidden password field."*).
- [ ] **Interactive Decision Trees**: A UI component that visualizes the exact "If-Then" logic path taken by the Random Forest model to reach the conclusion.
- [ ] **"What-If" Simulator**: Allow analysts to tweak URL parameters locally (e.g., "Add HTTPS") to see how the risk score evolves in real-time.

## 4. Infrastructure Independence ("The Sovereign Stack")
*Goal: Eliminate reliance on 3rd party scanners and resolvers.*
- [ ] **Self-Hosted Sandbox**: Deploy local `Puppeteer` to safely render pages and capture evidence screenshots.
- [ ] **Direct Recursive Resolver**: Custom Rust-based DNS resolver to query authoritative nameservers directly for true forensic data (TTL, CNAME chains).
- [ ] **JARM Fingerprinting**: Local implementation of active TLS server fingerprinting to map malicious server infrastructure.

## 5. Client-Side Edge Computing ("Zero Latency")
*Goal: Move explainability and detection to the browser.*
- [ ] **WASM Core**: Compile detection logic to `WebAssembly` to run 100% inside the user's browser.
- [ ] **In-Browser Explanation**: Show the "Why" tooltip directly in the browser extension icon, computed locally on the client machine.

## 6. Privacy & Specialized Networks
- [ ] **Tor/.onion Scanning**: Native support for scanning Dark Web links using a bundled Tor proxy.
- [ ] **Air-Gapped Operation**: Full system functionality without *any* outbound internet access using offline update packs.
