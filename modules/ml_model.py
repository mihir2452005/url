"""
Machine Learning Model Module for URL Detection
Integrates the organized dataset with ML models to enhance detection capabilities.
"""
import os
import pickle
import re
from urllib.parse import urlparse, urlsplit
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
import joblib
from modules.ssl_checker import is_valid_hostname
from config import Config


class URLFeatureExtractor:
    """
    Extracts features from URLs for ML model training and prediction.
    """
    
    def __init__(self):
        # Precompile regex patterns for efficiency
        self.ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
        self.url_scheme_pattern = re.compile(r'^https?://')
        self.double_ext_pattern = re.compile(r'\.(\w+)\.(\w+)(?:\?|#|$)')
        self.special_char_pattern = re.compile(r'[^a-zA-Z0-9.-]')
        
    def extract_features(self, url):
        """
        Extract features from a single URL.
        """
        features = {}
        
        # Parse the URL
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Basic length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname) if hostname else 0
        features['path_length'] = len(path) if path else 0
        features['query_length'] = len(query) if query else 0
        
        # Character count features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_exclamations'] = url.count('!')
        features['num_hash_signs'] = url.count('#')
        features['num_percent_signs'] = url.count('%')
        features['num_tilde_signs'] = url.count('~')
        
        # Special character ratio
        special_chars = len(self.special_char_pattern.findall(url))
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        # Protocol features
        features['has_https'] = 1 if url.lower().startswith('https://') else 0
        features['has_http'] = 1 if url.lower().startswith('http://') and not url.lower().startswith('https://') else 0
        
        # Hostname features
        if hostname:
            features['hostname_has_ip'] = 1 if self.ip_pattern.match(hostname) else 0
            features['num_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 1 else 0
            features['avg_subdomain_len'] = np.mean([len(sub) for sub in hostname.split('.')[:-1]]) if hostname.count('.') > 1 else 0
            
            # Entropy of hostname
            features['hostname_entropy'] = self.calculate_entropy(hostname)
        else:
            features['hostname_has_ip'] = 0
            features['num_subdomains'] = 0
            features['avg_subdomain_len'] = 0
            features['hostname_entropy'] = 0
        
        # Path features
        if path:
            # Check for double extensions
            double_ext_matches = self.double_ext_pattern.findall(path.lower())
            features['has_double_ext'] = 1 if double_ext_matches else 0
            features['num_double_ext'] = len(double_ext_matches)
            
            # Check for suspicious file extensions
            suspicious_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.jar']
            features['has_suspicious_ext'] = 1 if any(ext in path.lower() for ext in suspicious_extensions) else 0
            
            # Depth of path
            features['path_depth'] = path.count('/') if path else 0
        else:
            features['has_double_ext'] = 0
            features['num_double_ext'] = 0
            features['has_suspicious_ext'] = 0
            features['path_depth'] = 0
        
        # Query features
        if query:
            features['num_params'] = query.count('&') + 1
            features['query_has_sensitive'] = 1 if any(param in query.lower() for param in ['password', 'pwd', 'pass', 'login', 'username', 'user']) else 0
        else:
            features['num_params'] = 0
            features['query_has_sensitive'] = 0
        
        # Keyword stuffing detection
        suspicious_keywords = [
            'secure', 'login', 'update', 'password', 'account', 'verify',
            'confirm', 'bank', 'paypal', 'amazon', 'apple', 'microsoft',
            'facebook', 'google', 'urgent', 'limited', 'time', 'offer',
            'free', 'win', 'prize', 'cash', 'money', 'credit', 'loan'
        ]
        
        url_lower = url.lower()
        matched_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        features['keyword_count'] = len(matched_keywords)
        features['keyword_density'] = len(matched_keywords) / len(url_lower.split()) if len(url_lower.split()) > 0 else 0
        
        # Character repetition
        features['has_char_repetition'] = 1 if re.search(r'(.)\1{3,}', url_lower) else 0
        
        # Check for homograph attacks
        features['has_homograph'] = self.detect_homograph_risks(url_lower)
        
        return features
    
    def calculate_entropy(self, s):
        """
        Calculate the Shannon entropy of a string.
        """
        if not s:
            return 0
        
        # Calculate character frequencies
        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_length = len(s)
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def detect_homograph_risks(self, hostname):
        """
        Detect potential homograph attacks using confusable characters.
        """
        # Common confusable character mappings
        confusables = {
            'а': 'a',  # Cyrillic 'a' vs Latin 'a'
            'о': 'o',  # Cyrillic 'o' vs Latin 'o'
            'е': 'e',  # Cyrillic 'e' vs Latin 'e'
            'р': 'p',  # Cyrillic 'p' vs Latin 'p'
            'с': 'c',  # Cyrillic 'c' vs Latin 'c'
            'х': 'x',  # Cyrillic 'x' vs Latin 'x'
            'ν': 'v',  # Greek 'nu' vs Latin 'v'
            'ω': 'w',  # Greek 'omega' vs 'w'
        }
        
        # Check for confusable characters
        for char in hostname:
            if char in confusables:
                return 1
        return 0
    
    def extract_features_batch(self, urls):
        """
        Extract features from a batch of URLs.
        """
        features_list = []
        for url in urls:
            features = self.extract_features(url)
            features_list.append(features)
        
        return pd.DataFrame(features_list)


class MLUrlDetector:
    """
    Machine Learning-based URL detector that uses the organized dataset.
    """
    
    def __init__(self, model_path=None, feature_extractor=None):
        self.model_path = model_path
        self.feature_extractor = feature_extractor or URLFeatureExtractor()
        self.model = None
        self.is_trained = False
        self.feature_names = None
        
        # Try to load pre-trained model if available
        if model_path and os.path.exists(model_path):
            try:
                self.load_model()
            except Exception as e:
                print(f"Warning: Could not load model from {model_path}: {e}")
    
    def load_model(self):
        """
        Load a pre-trained model from disk.
        """
        if self.model_path and os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            print(f"Model loaded from {self.model_path}")
        else:
            print(f"Model file not found: {self.model_path}")
    
    def save_model(self, model_path=None):
        """
        Save the trained model to disk.
        """
        save_path = model_path or self.model_path
        if save_path and self.model:
            joblib.dump(self.model, save_path)
            print(f"Model saved to {save_path}")
    
    def prepare_dataset(self, dataset_path=None):
        """
        Prepare dataset from the organized URL detection dataset.
        """
        # Try to load from organized dataset if available
        if dataset_path is None:
            # Look for organized dataset
            possible_paths = [
                "../../../organized_url_dataset/training_data/mixed_training_urls.csv",
                "../../organized_url_dataset/training_data/mixed_training_urls.csv",
                "../organized_url_dataset/training_data/mixed_training_urls.csv",
                "./organized_url_dataset/training_data/mixed_training_urls.csv",
                "organized_url_dataset/training_data/mixed_training_urls.csv"
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    dataset_path = path
                    break
        
        if dataset_path is None or not os.path.exists(dataset_path):
            # Create a synthetic dataset for demonstration
            print("Dataset not found, creating synthetic dataset for demonstration...")
            return self.create_synthetic_dataset()
        
        try:
            print(f"Loading dataset from {dataset_path}")
            df = pd.read_csv(dataset_path, nrows=10000)  # Limit for demo purposes
            
            # Assume the dataset has 'url' and 'label' columns
            if 'url' not in df.columns or 'label' not in df.columns:
                # If column names are different, try common variations
                if 'URL' in df.columns and 'LABEL' in df.columns:
                    df.rename(columns={'URL': 'url', 'LABEL': 'label'}, inplace=True)
                elif 'Url' in df.columns and 'Label' in df.columns:
                    df.rename(columns={'Url': 'url', 'Label': 'label'}, inplace=True)
                else:
                    # Create synthetic dataset if column names don't match
                    return self.create_synthetic_dataset()
            
            # Convert labels to binary (0 for benign, 1 for malicious)
            df['label_binary'] = df['label'].apply(lambda x: 1 if str(x).lower() in ['malicious', 'phishing', 'bad', '1', 'suspicious', 'spam', 'malware'] else 0)
            
            # Extract features
            print("Extracting features...")
            features_df = self.feature_extractor.extract_features_batch(df['url'].tolist())
            
            # Combine features with labels
            X = features_df
            y = df['label_binary']
            
            # Check if we have both classes represented
            unique_labels = y.unique()
            if len(unique_labels) == 1:
                print(f"⚠️  Warning: Only one class found in dataset: {unique_labels[0]}")
                print("   This may be due to the dataset having only benign or only malicious URLs.")
                print("   Adding synthetic samples to balance dataset for training...")
                
                # Add synthetic samples of the missing class
                synthetic_samples_needed = 100  # Add 100 samples of the opposite class
                opposite_class = 1 - unique_labels[0]  # If all are 0, add 1s; if all are 1, add 0s
                
                if opposite_class == 0:
                    # Add some known benign URLs
                    synthetic_urls = [
                        "https://www.google.com",
                        "https://www.facebook.com",
                        "https://www.youtube.com",
                        "https://www.amazon.com",
                        "https://www.wikipedia.org"
                    ] * 20  # Repeat to get 100 samples
                else:
                    # Add some known malicious URLs
                    synthetic_urls = [
                        "http://192.168.1.100/login.php",
                        "https://secure-update-paypal.account-security-check.com",
                        "https://facebook-login-update-password.now.sh",
                        "https://suspicious-malware-site.com",
                        "https://phishing-bank-fake-login.com"
                    ] * 20  # Repeat to get 100 samples
                
                # Extract features for synthetic samples
                synthetic_features = self.feature_extractor.extract_features_batch(synthetic_urls)
                synthetic_y = [opposite_class] * len(synthetic_urls)
                
                # Concatenate with original data
                X = pd.concat([X, synthetic_features], ignore_index=True)
                y = pd.Series(list(y) + synthetic_y)
            
            print(f"Dataset prepared: {X.shape[0]} samples, {X.shape[1]} features")
            print(f"Label distribution: {y.value_counts().to_dict()}")
            return X, y
            
        except Exception as e:
            print(f"Error preparing dataset: {e}")
            return self.create_synthetic_dataset()
    
    def create_synthetic_dataset(self):
        """
        Create a synthetic dataset for demonstration purposes.
        """
        print("Creating synthetic dataset...")
        
        # Create some example URLs with labels
        benign_urls = [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.youtube.com",
            "https://www.twitter.com",
            "https://www.linkedin.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.wikipedia.org",
            "https://www.reddit.com",
            "https://www.amazon.com",
            "https://www.ebay.com",
            "https://www.netflix.com",
            "https://www.spotify.com",
            "https://www.office.com",
            "https://www.dropbox.com"
        ] * 100  # Multiply to create more samples
        
        malicious_urls = [
            "http://192.168.1.100/login.php",
            "https://secure-update-paypal.account-security-check.com",
            "https://facebook-login-update-password.now.sh",
            "https://google-docs-viewer-urgent-action-required.com",
            "https://amazon-prime-free-gift-card-offer.org",
            "https://paypal-security-account-verification.net",
            "https://microsoft-office-365-security-update.info",
            "https://bank-of-america-online-banking-secure-login.com",
            "https://apple-id-security-check-verify-now.org",
            "https://instagram-verification-required-security.com",
            "https://twitter-account-suspended-appeal-form.com",
            "https://netflix-premium-upgrade-offer-deal.com",
            "https://github-enterprise-license-renewal-urgent.com",
            "https://linkedin-job-offer-congratulations-you-won.com",
            "https://whatsapp-web-security-authentication-check.com"
        ] * 100  # Multiply to create more samples
        
        # Combine and create labels
        all_urls = benign_urls + malicious_urls
        labels = [0] * len(benign_urls) + [1] * len(malicious_urls)  # 0 for benign, 1 for malicious
        
        # Create DataFrame
        df = pd.DataFrame({
            'url': all_urls,
            'label_binary': labels
        })
        
        # Extract features
        print("Extracting features from synthetic dataset...")
        features_df = self.feature_extractor.extract_features_batch(df['url'].tolist())
        
        X = features_df
        y = df['label_binary']
        
        print(f"Synthetic dataset created: {X.shape[0]} samples, {X.shape[1]} features")
        return X, y
    
    def train(self, X=None, y=None, dataset_path=None, model_type='random_forest'):
        """
        Train the ML model on the provided dataset.
        """
        if X is None or y is None:
            X, y = self.prepare_dataset(dataset_path)
        
        # Store feature names for later use
        self.feature_names = X.columns.tolist()
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Select and train model
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        elif model_type == 'logistic_regression':
            self.model = LogisticRegression(random_state=42, max_iter=1000)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        print("Training model...")
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained successfully!")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"\nLabel distribution in test set: {pd.Series(y_test).value_counts().to_dict()}")
        
        # Only print classification report if we have both classes in test set
        unique_test_labels = set(y_test)
        if len(unique_test_labels) > 1:
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
        else:
            print(f"\n⚠️  Warning: Test set only contains one class: {list(unique_test_labels)[0]}")
            print("   Classification report skipped due to single-class test set.")
        
        self.is_trained = True
        
        # Feature importance (for tree-based models)
        if hasattr(self.model, 'feature_importances_'):
            feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(feature_importance.head(10))
    
    def predict_single(self, url):
        """
        Predict if a single URL is malicious or benign.
        Returns (prediction, confidence, risk_factors).
        """
        if not self.is_trained or self.model is None:
            return 0, 0.5, [("Model not trained", 0, "ML model has not been trained yet")]
        
        # Extract features
        features_df = self.feature_extractor.extract_features_batch([url])
        
        # Make prediction
        prediction = self.model.predict(features_df)[0]
        probabilities = self.model.predict_proba(features_df)[0]
        
        # Get confidence as the max probability
        confidence = max(probabilities)
        
        # Identify risk factors based on feature values
        risk_factors = self.identify_risk_factors(url, features_df.iloc[0], prediction)
        
        return int(prediction), float(confidence), risk_factors
    
    def identify_risk_factors(self, url, features, prediction):
        """
        Identify which features contributed most to the prediction.
        """
        risk_factors = []
        
        # Check for high-risk indicators
        if features['hostname_has_ip'] == 1:
            risk_factors.append(("IP Address in URL", 80, f"URL uses IP address instead of domain: {urlparse(url).hostname}"))
        
        if features['has_double_ext'] == 1:
            risk_factors.append(("Double Extension", 85, "URL has suspicious double file extension"))
        
        if features['has_suspicious_ext'] == 1:
            risk_factors.append(("Suspicious Extension", 75, "URL has executable file extension"))
        
        if features['keyword_count'] > 3:
            risk_factors.append(("Keyword Stuffing", 50, f"URL contains {features['keyword_count']} suspicious keywords"))
        
        if features['has_char_repetition'] == 1:
            risk_factors.append(("Character Repetition", 45, "URL contains excessive character repetition"))
        
        if features['special_char_ratio'] > 0.3:
            risk_factors.append(("High Special Char Ratio", 60, f"URL has {features['special_char_ratio']:.2f} special character ratio"))
        
        if features['hostname_entropy'] > 4.0:
            risk_factors.append(("High Hostname Entropy", 65, f"Hostname has high entropy: {features['hostname_entropy']:.2f}"))
        
        if features['num_subdomains'] > 3:
            risk_factors.append(("Excessive Subdomains", 55, f"URL has {features['num_subdomains']} subdomains"))
        
        # If no specific risk factors were identified but the model predicted malicious
        if prediction == 1 and len(risk_factors) == 0:
            risk_factors.append(("ML Model Prediction", 40, "Machine learning model classified this as potentially malicious"))
        
        return risk_factors
    
    def analyze(self, url):
        """
        Analyze a URL using the ML model.
        Returns a tuple: (score, details) similar to other risk functions.
        """
        if not self.is_trained:
            # Return minimal risk if model is not trained
            return (0, [("ML Analysis Skipped", 0, "Model not trained or unavailable")])
        
        try:
            prediction, confidence, risk_factors = self.predict_single(url)
            
            # Convert prediction to a risk score (0-100)
            # If prediction is 1 (malicious), use confidence to determine score
            if prediction == 1:
                score = min(100, int(confidence * 100))
            else:
                score = max(0, 100 - int(confidence * 100))
            
            # Add ML-specific details to risk factors
            ml_details = f"ML Confidence: {confidence:.2f}, Prediction: {'Malicious' if prediction == 1 else 'Benign'}"
            risk_factors.append(("ML Analysis Result", 0, ml_details))
            
            return (score, risk_factors)
        
        except Exception as e:
            # If ML analysis fails, return minimal risk
            return (0, [("ML Analysis Error", 0, f"Error in ML analysis: {str(e)[:50]}")])


# Global instance for use in the app
ml_detector = None


def initialize_ml_detector():
    """
    Initialize the ML detector with pre-trained model if available.
    """
    global ml_detector
    model_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'ml_url_model.pkl')
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    ml_detector = MLUrlDetector(model_path=model_path)
    
    # Try to load model, if not available, train on dataset
    if not ml_detector.is_trained:
        try:
            print("Training ML model...")
            ml_detector.train()
            ml_detector.save_model()
        except Exception as e:
            print(f"Could not train model: {e}")
    
    return ml_detector


def ml_risk(url):
    """
    Wrapper function for ML-based risk analysis that matches the interface of other risk functions.
    """
    global ml_detector
    
    if ml_detector is None:
        ml_detector = initialize_ml_detector()
    
    return ml_detector.analyze(url)

def extract_features(url):
    """Extract comprehensive features from URL for ML model with enhanced reputation analysis."""
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. Domain length
    features.append(len(domain))
    
    # 3. Path length
    features.append(len(path))
    
    # 4. Query length
    features.append(len(query))
    
    # 5. Number of dots in domain
    features.append(domain.count('.'))
    
    # 6. Number of subdomains
    subdomains = len(domain.split('.')) - 2 if domain.count('.') >= 2 else 0
    features.append(max(0, subdomains))
    
    # 7. Number of query parameters
    features.append(len(query.split('&')) if query else 0)
    
    # 8. Number of special characters
    special_chars = sum(1 for c in url if c in '-_~.%@!#$%^&*()_+=[]{}|;:,.<>?')
    features.append(special_chars)
    
    # 9. Contains IP address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features.append(1 if re.search(ip_pattern, domain) else 0)
    
    # 10. URL scheme (binary: 1 for https, 0 for http)
    features.append(1 if parsed.scheme == 'https' else 0)
    
    # 11. Number of digits in URL
    features.append(sum(1 for c in url if c.isdigit()))
    
    # 12. Number of letters in URL
    features.append(sum(1 for c in url if c.isalpha()))
    
    # 13. Ratio of digits to total characters
    features.append(sum(1 for c in url if c.isdigit()) / len(url) if len(url) > 0 else 0)
    
    # 14. Number of encoded characters (e.g., %20)
    encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
    features.append(encoded_count)
    
    # 15. Contains suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.click', '.stream', '.download', '.cricket', '.date', '.faith', '.review', '.science', '.site', '.space', '.tech', '.win', '.country', '.kim', '.men', '.loan', '.racing', '.review', '.vip', '.xin']
    features.append(1 if any(domain.lower().endswith(tld) for tld in suspicious_tlds) else 0)
    
    # 16. Number of hyphens in domain
    features.append(domain.count('-'))
    
    # 17. Number of underscores in URL
    features.append(url.count('_'))
    
    # 18. Average word length in path
    path_words = [word for word in re.split(r'[^a-zA-Z0-9]', path) if word]
    avg_word_len = sum(len(word) for word in path_words) / len(path_words) if path_words else 0
    features.append(avg_word_len)
    
    # 19. Number of slashes in URL
    features.append(url.count('/'))
    
    # 20. Number of equal signs in query
    features.append(query.count('='))
    
    # 21. Number of ampersands in query
    features.append(query.count('&'))
    
    # 22. Entropy of the domain
    domain_chars = [c for c in domain if c.isalnum()]
    if domain_chars:
        freq = Counter(domain_chars)
        total = len(domain_chars)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values() if count > 0)
    else:
        entropy = 0
    features.append(entropy)
    
    # 23. Number of uppercase letters in domain
    features.append(sum(1 for c in domain if c.isupper()))
    
    # 24. Number of lowercase letters in domain
    features.append(sum(1 for c in domain if c.islower()))
    
    # 25. Contains suspicious keywords
    suspicious_keywords = ['secure', 'account', 'login', 'confirm', 'update', 'bank', 'signin', 'password', 'verification', 
                          'paypal', 'amazon', 'apple', 'microsoft', 'facebook', 'google', 'twitter', 'instagram', 
                          'sbi', 'hdfc', 'icici', 'axis', 'citibank', 'netflix', 'spotify', 'adobe', 'office', 
                          'microsoftonline', 'salesforce', 'zendesk', 'slack', 'dropbox', 'onedrive', 'sharepoint', 
                          'admin', 'webmail', 'owa', 'portal', 'ebay', 'paypal', 'amazon', 'apple', 'microsoft']
    keyword_count = sum(1 for keyword in suspicious_keywords if keyword.lower() in url.lower())
    features.append(keyword_count)
    
    # 26. Port number (default 80/443 = 0, else 1)
    features.append(0 if parsed.port in [None, 80, 443] else 1)
    
    # 27. Number of special characters in domain
    special_domain_chars = sum(1 for c in domain if c in '-_~.%@!#$%^&*()_+=[]{}|;:,.<>?')
    features.append(special_domain_chars)
    
    # 28. Domain starts with number
    features.append(1 if domain and domain[0].isdigit() else 0)
    
    # 29. Number of consecutive identical characters
    consecutive_count = 0
    for i in range(len(url) - 1):
        if url[i] == url[i+1]:
            consecutive_count += 1
    features.append(consecutive_count)
    
    # 30. Number of '@' symbols (should be 0 in legitimate URLs)
    features.append(url.count('@'))
    
    # 31. Number of '#' symbols
    features.append(url.count('#'))
    
    # 32. Number of '?' symbols
    features.append(url.count('?'))
    
    # 33. Contains punycode (for internationalized domains)
    features.append(1 if 'xn--' in domain.lower() else 0)
    
    # 34. Enhanced homograph detection
    homograph_chars = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'к': 'k', 'в': 'b', 'м': 'm',
        'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'χ': 'x',
        'і': 'i', 'ӏ': 'l', 'ј': 'j', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ԁ': 'd', 'ѕ': 's', 'ѓ': 'g',
    }
    homograph_count = sum(1 for c in url if c in homograph_chars)
    features.append(homograph_count)
    
    # 35. Double extension detection
    dangerous_exts = ['exe', 'scr', 'bat', 'com', 'pif', 'cmd', 'vbs', 'js', 'jse', 'ws', 'wsf', 'msi', 'mht', 'mhtml', 'lnk', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'jar', 'swf']
    double_ext_pattern = r'\.({})\.({})'.format('|'.join(dangerous_exts), '|'.join(dangerous_exts))
    double_ext_match = bool(re.search(double_ext_pattern, path.lower()))
    features.append(1 if double_ext_match else 0)
    
    # 36. Sequential digits in domain
    seq_digit_match = re.search(r'[0-9]{4,}', domain)
    features.append(1 if seq_digit_match else 0)
    
    # 37. Number of uppercase letters in path
    features.append(sum(1 for c in path if c.isupper()))
    
    # 38. Ratio of special characters to total length
    features.append(special_chars / len(url) if len(url) > 0 else 0)
    
    # 39. Number of dots in path
    features.append(path.count('.'))
    
    # 40. URL contains common malicious file patterns
    malicious_patterns = [r'\b(password|credential|login|account|security|bank|paypal|amazon|apple|microsoft)\b',
                         r'\b(urgent|important|verify|confirm|update|suspended|locked|compromised)\b',
                         r'\b(account|session|cookie|token|auth|sign-in|log-in)\b']
    malicious_pattern_count = sum(1 for pattern in malicious_patterns if re.search(pattern, url.lower()))
    features.append(malicious_pattern_count)
    
    # 41. Number of percent-encoded characters in path
    encoded_in_path = len(re.findall(r'%[0-9A-Fa-f]{2}', path))
    features.append(encoded_in_path)
    
    # 42. Domain contains brand impersonation keywords
    brand_keywords = ['paypal', 'amazon', 'apple', 'microsoft', 'facebook', 'google', 'twitter', 'instagram', 
                     'sbi', 'hdfc', 'icici', 'axis', 'citibank', 'netflix', 'spotify', 'adobe', 'office', 
                     'microsoftonline', 'salesforce', 'zendesk', 'slack', 'dropbox', 'ebay', 'chase', 'wellsfargo']
    brand_imp_count = sum(1 for keyword in brand_keywords if keyword.lower() in domain.lower() and keyword.lower() != domain.lower().split('.')[0])
    features.append(brand_imp_count)
    
    # 43. Path depth (number of directories)
    path_depth = path.count('/') if path else 0
    features.append(path_depth)
    
    # 44. Query complexity (number of parameters * average parameter length)
    if query:
        params = query.split('&')
        param_lengths = [len(param.split('=')[1]) if '=' in param else len(param) for param in params]
        avg_param_length = sum(param_lengths) / len(param_lengths) if param_lengths else 0
        query_complexity = len(params) * avg_param_length
    else:
        query_complexity = 0
    features.append(query_complexity)
    
    # 45. Number of non-ASCII characters
    ascii_count = sum(1 for c in url if ord(c) < 128)
    non_ascii_count = len(url) - ascii_count
    features.append(non_ascii_count)
    
    return features
