
try:
    import pytesseract
    from PIL import Image
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

import os
import re

class OCRAnalyzer:
    """
    Titan-Tier Optical Character Recognition for Screenshots.
    """
    def __init__(self, tesseract_cmd=None):
        self.enabled = PYTESSERACT_AVAILABLE
        
        # If user provides a specific path or we need to find it
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        
        # Verify binary presence
        try:
            if self.enabled:
                pytesseract.get_tesseract_version()
        except:
            print("Warning: Tesseract binary not found. OCR Disabled.")
            self.enabled = False

    def extract_text(self, image_path):
        """
        Extract text from an image file.
        """
        if not self.enabled or not os.path.exists(image_path):
            return ""
        
        try:
            text = pytesseract.image_to_string(Image.open(image_path))
            return text
        except Exception as e:
            print(f"OCR Extraction Failed: {e}")
            return ""

    def analyze_text(self, text):
        """
        Analyze extracted text for phishing keywords using NLP logic.
        """
        risks = []
        score = 0
        text_lower = text.lower()
        
        # 1. Critical Inputs
        if 'password' in text_lower or 'ssn' in text_lower or 'credit card' in text_lower:
            # High risk if found on a non-trusted domain (caller logic handles domain check)
            risks.append(('Sensitive Input Field', 0, 'Found password/financial fields in screenshot'))
            score += 0 # This is a sensor, the decision logic is in the orchestrator
            
        # 2. Urgency
        urgency_keywords = ['immediate action', 'account suspended', 'verify now', '24 hours']
        if any(k in text_lower for k in urgency_keywords):
            risks.append(('Visual Urgency', 0, 'Screenshot contains urgent threatening language'))
            
        return score, risks

# Global
ocr_engine = OCRAnalyzer()
