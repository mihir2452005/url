import difflib
from urllib.parse import urlparse

class LocalUrlDetector:
    def __init__(self):
        self.embedding_model = None
        self.known_embeddings = None
        self.rag_enabled = False
        
        # Common targets for phishing
        self.target_brands = [
            'paypal', 'google', 'microsoft', 'apple', 'facebook', 
            'netflix', 'amazon', 'dropbox', 'linkedin', 'yahoo', 
            'instagram', 'whatsapp', 'bankofamerica', 'chase',
            'wellsfargo', 'citi', 'capitalone', 'americanexpress',
            'adobe', 'dhl', 'fedex', 'ups', 'usps', 'irs', 'gov',
            'roblox', 'fortnite', 'steam', 'binance', 'coinbase',
            'blockchain', 'metamask', 'trustwallet', 'ledger', 'trezor',
            # NEW BRANDS: Add more emerging targets
            'tiktok', 'discord', 'telegram', 'signal', 'zoom',
            'docusign', 'quickbooks', 'payoneer', 'wise', 'revolut',
            'robinhood', 'etoro', 'kraken', 'gemini', 'opensea',
            'uniswap', 'pancakeswap', 'phantom', 'exodus', 'electrum'
        ]
        
        # Whitelist to prevent false positives on official domains
        self.whitelist = {
            'paypal.com', 'www.paypal.com', 'google.com', 'www.google.com',
            'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
            'facebook.com', 'www.facebook.com', 'amazon.com', 'www.amazon.com',
            'netflix.com', 'www.netflix.com', 'dropbox.com', 'www.dropbox.com',
            'linkedin.com', 'www.linkedin.com', 'chase.com', 'www.chase.com',
            'whatsapp.com', 'web.whatsapp.com', 'm.whatsapp.com'
        }
        
        # Signatures for RAG (Semantic Matching)
        self.known_signatures = [
            "secure-login-verify-account",
            "update-payment-details-immediate",
            "microsoft-office-365-shared-document",
            "apple-id-locked-unlock-now",
            "suspicious-sign-in-attempt-alert",
            "wallet-connect-dapp-sync",
            "metamask-restore-phrase",
            "irs-tax-refund-claim"
        ]
        self._load_rag_models()

    def _load_rag_models(self):
        """Loads local ML models if available and persists embeddings."""
        try:
            from sentence_transformers import SentenceTransformer
            import pickle
            import os
            
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Persistence logic
            data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
            rag_file = os.path.join(data_dir, 'rag_embeddings.pkl')
            
            if os.path.exists(rag_file):
                try:
                    with open(rag_file, 'rb') as f:
                        data = pickle.load(f)
                        self.known_signatures = data['signatures']
                        self.known_embeddings = data['embeddings']
                        # print(f"Loaded RAG data from {rag_file}")
                except Exception as e:
                    print(f"Error loading RAG data: {e}. Recomputing...")
                    self._compute_and_save(rag_file)
            else:
                self._compute_and_save(rag_file)
                
            self.rag_enabled = True
        except ImportError:
            print("Local AI: sentence-transformers not found. Running in heuristic mode only.")

    def _compute_and_save(self, filepath):
        """Computes embeddings and saves them to disk."""
        import pickle
        import os
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        self.known_embeddings = self.embedding_model.encode(self.known_signatures)
        
        data = {
            'signatures': self.known_signatures,
            'embeddings': self.known_embeddings
        }
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
            print(f"Saved RAG data to {filepath}")
        except Exception as e:
            print(f"Failed to save RAG data: {e}")

    def analyze(self, url):
        risks = []
        score = 0
        
        parsed = urlparse(url)
        domain = (parsed.netloc or '').lower()
        path = (parsed.path or '').lower()
        query = (parsed.query or '').lower()

        # Check against comprehensive whitelist
        if domain in self.whitelist:
            return 0, []
        
        # Check against trusted domains from config
        from config import Config
        if domain in [d.lower() for d in Config.TRUSTED_DOMAINS]:
            return 0, []
        
        # NEW: Enhanced check for educational institutions
        educational_tlds = ['.edu', '.ac.', '.edu.']
        is_educational = any(tld in domain for tld in educational_tlds)
        
        has_edu_keyword = any(keyword in domain for keyword in Config.EDUCATIONAL_KEYWORDS)
        
        # Educational institutions get special treatment
        if is_educational or has_edu_keyword:
            # Very likely legitimate, skip most checks
            sensitivity_multiplier = 0.05  # Extremely lenient
            is_legit = True
        else:
            # Check if domain matches known legitimate patterns
            is_legit = any(pattern in domain for pattern in Config.KNOWN_LEGITIMATE_PATTERNS)
            sensitivity_multiplier = 0.3 if is_legit else 1.0
        
        # 1. Brand Mimicry - refined fuzzy matching
        for brand in self.target_brands:
            brand_lower = brand.lower()
            official_domains = {f"{brand_lower}.com", f"www.{brand_lower}.com", f"{brand_lower}.org", f"www.{brand_lower}.org"}

            if domain in official_domains:
                continue

            # Exact brand substring in domain labels (very suspicious)
            domain_labels = domain.split('.')
            if any(brand_lower == label for label in domain_labels):
                # Exact brand name as a subdomain or part of domain (not official)
                weight = int(70 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Brand Mimicry', weight, f'Domain contains exact brand "{brand_lower}" but is not official.'))
                    score += weight
                    break

            # Brand present in path/query - less suspicious, context matters
            if brand_lower in path or brand_lower in query:
                # Only flag if combined with suspicious URL characteristics
                if len(path) < 50:  # Short path with brand name is more suspicious
                    weight = int(30 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('Brand in URL Path', weight, f'Path references "{brand_lower}" on non-official domain.'))
                        score += weight
                        break

            # Fuzzy typosquatting - improved algorithm
            labels = [l for l in domain.split('.') if l]
            if not labels:
                continue
            
            # Check second-level domain (most important)
            sld = labels[-2] if len(labels) >= 2 else labels[0]
            ratio = difflib.SequenceMatcher(None, sld, brand_lower).ratio()
            
            # Very high similarity (0.85-0.99) is suspicious typosquatting
            if 0.85 <= ratio < 1.0:
                weight = int(65 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Typosquatting (Fuzzy)', weight, f'Domain "{sld}" closely resembles "{brand_lower}" ({int(ratio*100)}% similar).'))
                    score += weight
                    break
            # Moderate similarity (0.75-0.84) - less certain
            elif 0.75 <= ratio < 0.85 and not is_legit:
                weight = int(40 * sensitivity_multiplier)
                if weight > 0:
                    risks.append(('Possible Typosquatting', weight, f'Domain "{sld}" somewhat resembles "{brand_lower}" ({int(ratio*100)}% similar).'))
                    score += weight
                    break

        # 2. Local RAG / Semantic Similarity - refined thresholds
        if self.rag_enabled:
            try:
                from sklearn.metrics.pairwise import cosine_similarity
                input_embedding = self.embedding_model.encode([url])
                similarities = cosine_similarity(input_embedding, self.known_embeddings)
                max_similarity = similarities.max()
                
                # Higher threshold to reduce false positives
                if max_similarity > 0.75:
                    # Very high similarity to known phishing patterns
                    weight = int(75 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('AI Pattern Match (High)', weight, f'Very similar to known phishing patterns ({int(max_similarity*100)}%).'))
                        score += weight
                elif max_similarity > 0.65 and not is_legit:
                    # Moderate similarity, only flag for non-legitimate
                    weight = int(50 * sensitivity_multiplier)
                    if weight > 0:
                        risks.append(('AI Pattern Match', weight, f'Similar to known phishing patterns ({int(max_similarity*100)}%).'))
                        score += weight
            except Exception:
                pass  # Gracefully handle any ML errors

        return score, risks