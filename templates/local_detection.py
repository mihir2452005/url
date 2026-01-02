import math
import re
from collections import Counter

# Dependencies: pip install sentence-transformers numpy scikit-learn
# For LLM: pip install llama-cpp-python

class LocalUrlDetector:
    def __init__(self):
        self.embedding_model = None
        self.known_phishing_embeddings = []
        self.known_phishing_labels = []

    def calculate_entropy(self, text):
        """
        Calculates Shannon Entropy. High entropy (>4.5) in a domain 
        often indicates Algorithmic Generation (DGA) used by malware.
        """
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def load_rag_models(self):
        """
        Loads a local embedding model for RAG (Retrieval Augmented Generation).
        This runs entirely offline.
        """
        try:
            from sentence_transformers import SentenceTransformer
            # 'all-MiniLM-L6-v2' is small, fast, and runs locally
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # SIMULATION: In a real app, load these from a local FAISS index or ChromaDB
            # These represent "concepts" of phishing we want to match against
            known_signatures = [
                "secure-login-paypal-update",
                "verify-bank-account-alert",
                "microsoft-office-365-login",
                "apple-id-support-unlock"
            ]
            self.known_phishing_embeddings = self.embedding_model.encode(known_signatures)
            self.known_phishing_labels = known_signatures
        except ImportError:
            print("SentenceTransformers not installed. RAG features disabled.")

    def check_rag_similarity(self, url_string):
        """
        RAG Logic: Embeds the input URL and finds semantic similarity 
        to known phishing patterns in our local vector store.
        """
        if not self.embedding_model:
            return 0.0, "RAG inactive"

        from sklearn.metrics.pairwise import cosine_similarity
        
        # Embed the input URL (focusing on path/query usually helps)
        input_embedding = self.embedding_model.encode([url_string])
        
        # Calculate similarity against known bad signatures
        similarities = cosine_similarity(input_embedding, self.known_phishing_embeddings)
        
        # Get the highest match
        max_score = similarities.max()
        
        # If similarity is high (> 0.7), it's likely trying to mimic that signature
        return max_score, "High similarity to known phishing pattern" if max_score > 0.7 else "Low similarity"

    def analyze_with_local_llm(self, url):
        """
        Uses a Local LLM (e.g., Llama-3 via llama.cpp) to analyze the URL.
        No API keys required.
        """
        # Pseudo-code for integrating a local GGUF model
        # from llama_cpp import Llama
        # llm = Llama(model_path="./models/mistral-7b-quantized.gguf", n_ctx=2048)
        
        prompt = f"""
        You are a security expert. Analyze this URL: '{url}'
        1. Is it trying to mimic a popular brand?
        2. Does it use suspicious keywords (login, verify, secure)?
        3. Return a risk score from 0 to 100.
        Answer in JSON format.
        """
        
        # output = llm(prompt, max_tokens=128)
        # return output['choices'][0]['text']
        
        return {
            "note": "Local LLM integration requires a .gguf model file and llama-cpp-python installed."
        }