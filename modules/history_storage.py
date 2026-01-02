import json
import os
from datetime import datetime
from pathlib import Path

class AnalysisHistoryStorage:
    """
    Persistent storage for URL analysis history.
    Stores results locally without external dependencies.
    """
    
    def __init__(self, storage_path='data/analysis_history.json'):
        """Initialize storage with specified path."""
        self.storage_path = storage_path
        self._ensure_storage_directory()
        self._load_history()
    
    def _ensure_storage_directory(self):
        """Create storage directory if it doesn't exist."""
        storage_dir = os.path.dirname(self.storage_path)
        if storage_dir:
            Path(storage_dir).mkdir(parents=True, exist_ok=True)
    
    def _load_history(self):
        """Load existing history from file."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    self.history = json.load(f)
                    if not isinstance(self.history, list):
                        self.history = []
            except (json.JSONDecodeError, IOError):
                self.history = []
        else:
            self.history = []
    
    def _save_history(self):
        """Persist history to file."""
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error saving history: {e}")
    
    def add_analysis(self, url, result):
        """
        Add a new analysis result to history.
        
        Args:
            url: The analyzed URL
            result: Analysis result dictionary containing score, verdict, etc.
        """
        # Prepare simplified risk details for storage
        risk_summary = {}
        if 'risks' in result:
            for category, (score, details) in result.get('risks', {}).items():
                risk_summary[category] = {
                    'score': score,
                    'details': [
                        {'name': name, 'weight': weight, 'explanation': expl}
                        for name, weight, expl in details
                    ]
                }
        
        # Create history entry
        entry = {
            'id': self._generate_id(),
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'score': result.get('score', 0),
            'classification': result.get('classification', 'Unknown'),
            'verdict': result.get('verdict', 'Unknown'),
            'confidence': result.get('confidence', 0),
            'risk_summary': risk_summary,
            'breakdown': result.get('breakdown', {})
        }
        
        # Add to history (newest first)
        self.history.insert(0, entry)
        
        # Limit history size (keep last 100 entries)
        if len(self.history) > 100:
            self.history = self.history[:100]
        
        self._save_history()
        return entry['id']
    
    def _generate_id(self):
        """Generate unique ID for analysis entry."""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        return f"analysis_{timestamp}"
    
    def get_all_history(self):
        """Retrieve all history entries."""
        return self.history
    
    def get_recent_history(self, limit=10):
        """Get most recent N entries."""
        return self.history[:limit]
    
    def get_by_id(self, entry_id):
        """Retrieve specific entry by ID."""
        for entry in self.history:
            if entry.get('id') == entry_id:
                return entry
        return None
    
    def search_history(self, query=None, verdict=None, min_score=None, max_score=None):
        """
        Search history with filters.
        
        Args:
            query: URL substring to search for
            verdict: Filter by verdict (Safe/Suspicious/Phishing/Malicious)
            min_score: Minimum risk score
            max_score: Maximum risk score
        """
        results = self.history
        
        if query:
            query_lower = query.lower()
            results = [e for e in results if query_lower in e.get('url', '').lower()]
        
        if verdict:
            results = [e for e in results if e.get('verdict') == verdict]
        
        if min_score is not None:
            results = [e for e in results if e.get('score', 0) >= min_score]
        
        if max_score is not None:
            results = [e for e in results if e.get('score', 0) <= max_score]
        
        return results
    
    def clear_history(self):
        """Clear all history entries."""
        self.history = []
        self._save_history()
    
    def delete_entry(self, entry_id):
        """Delete a specific entry by ID."""
        self.history = [e for e in self.history if e.get('id') != entry_id]
        self._save_history()
    
    def get_statistics(self):
        """Calculate statistics from history."""
        if not self.history:
            return {
                'total_analyses': 0,
                'safe_count': 0,
                'suspicious_count': 0,
                'phishing_count': 0,
                'malicious_count': 0,
                'average_score': 0,
                'average_confidence': 0
            }
        
        verdicts = [e.get('verdict', 'Unknown') for e in self.history]
        scores = [e.get('score', 0) for e in self.history]
        confidences = [e.get('confidence', 0) for e in self.history]
        
        return {
            'total_analyses': len(self.history),
            'safe_count': verdicts.count('Safe'),
            'suspicious_count': verdicts.count('Suspicious'),
            'phishing_count': verdicts.count('Phishing'),
            'malicious_count': verdicts.count('Malicious'),
            'average_score': sum(scores) / len(scores) if scores else 0,
            'average_confidence': sum(confidences) / len(confidences) if confidences else 0
        }
