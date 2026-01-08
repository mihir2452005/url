"""
Malicious File Detection Module for URL Sentinel
Detects known malicious files, test files (like EICAR), and suspicious file types.
"""
import re
import requests
from urllib.parse import urlparse
import hashlib
from typing import Tuple, List, Dict


class MaliciousFileDetector:
    """
    Detects malicious files, known test files (EICAR), and suspicious file types in URLs.
    """
    
    def __init__(self):
        # Known malicious/test file signatures and patterns
        self.malicious_signatures = {
            # EICAR test file signature (in various encodings)
            'eicar': [
                'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
                'eicar.com',
                'eicar.com.txt',
                'eicar_test',
                'eicar-standard-antivirus-test-file'
            ],
            # Common malicious file extensions
            'malicious_extensions': {
                '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.vbe', '.js', '.jse',
                '.wsf', '.wsh', '.msc', '.msp', '.hta', '.cpl', '.dll', '.sys', '.bin',
                '.cmd', '.ps1', '.reg', '.inf', '.msi', '.msp', '.tmp', '.dat'
            },
            # Suspicious keywords in filenames
            'suspicious_keywords': [
                'password', 'login', 'security', 'update', 'account', 'verify',
                'urgent', 'critical', 'important', 'suspicious', 'malicious',
                'trojan', 'virus', 'malware', 'ransomware', 'keygen', 'crack',
                'hack', 'exploit', 'rootkit', 'backdoor', 'worm', 'spyware',
                'adware', 'botnet', 'phishing', 'scam', 'fraud'
            ],
            # Known malicious file patterns
            'malicious_patterns': [
                r'eicar.*\.com',  # EICAR test files
                r'.*\.(exe|scr|bat|com|pif|vbs|js|ps1)$',  # Executable files
                r'.*password.*\.(txt|doc|pdf|zip)$',  # Password-related suspicious files
                r'.*login.*\.(txt|doc|pdf|zip)$',  # Login-related suspicious files
                r'.*credentials?$',  # Credential files
            ]
        }
    
    def detect_malicious_file_indicators(self, url: str) -> Tuple[int, List[Tuple[str, int, str]]]:
        """
        Detect malicious file indicators in a URL.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Tuple of (total_score, list_of_risks)
        """
        risks = []
        total_score = 0
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        filename = path.split('/')[-1] if '/' in path else path
        
        # Check for EICAR test file specifically
        if self._is_eicar_file(url, path, filename):
            risks.append(('EICAR Test File', 95, 'URL points to EICAR antivirus test file, which is designed to trigger antivirus alerts'))
            total_score += 95
        
        # Check for malicious file extensions
        ext_risks = self._check_file_extensions(filename)
        for risk in ext_risks:
            risks.append(risk)
            total_score += risk[1]
        
        # Check for suspicious keywords in filename
        keyword_risks = self._check_suspicious_keywords(filename)
        for risk in keyword_risks:
            risks.append(risk)
            total_score += risk[1]
        
        # Check for malicious patterns
        pattern_risks = self._check_malicious_patterns(url, filename)
        for risk in pattern_risks:
            risks.append(risk)
            total_score += risk[1]
        
        # Check for suspicious download paths
        if self._is_suspicious_download_path(path):
            risk = ('Suspicious Download Path', 40, f'URL contains suspicious download path: {path}')
            risks.append(risk)
            total_score += 40
        
        return min(total_score, 100), risks
    
    def _is_eicar_file(self, url: str, path: str, filename: str) -> bool:
        """
        Check if the URL points to an EICAR test file.
        """
        url_lower = url.lower()
        path_lower = path.lower()
        filename_lower = filename.lower()
        
        # Check various EICAR patterns
        eicar_patterns = [
            'eicar.com',
            'eicar.com.txt',
            'eicar-test',
            'standard-antivirus-test',
            'antivirus-test-file'
        ]
        
        for pattern in eicar_patterns:
            if pattern in url_lower or pattern in path_lower or pattern in filename_lower:
                return True
        
        return False
    
    def _check_file_extensions(self, filename: str) -> List[Tuple[str, int, str]]:
        """
        Check for malicious file extensions.
        """
        risks = []
        
        # Find file extension
        if '.' in filename:
            ext = '.' + filename.split('.')[-1].lower()
            full_ext = '.' + '.'.join(filename.split('.')[1:]).lower()  # In case of double extensions
            
            if ext in self.malicious_signatures['malicious_extensions']:
                risks.append((
                    f'Suspicious File Extension: {ext}',
                    70 if ext in ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js'] else 50,
                    f'File has potentially executable extension: {ext}'
                ))
            
            if full_ext != ext and full_ext in self.malicious_signatures['malicious_extensions']:
                risks.append((
                    f'Double Extension: {full_ext}',
                    85,
                    f'File has double extension suggesting executable disguise: {full_ext}'
                ))
        
        return risks
    
    def _check_suspicious_keywords(self, filename: str) -> List[Tuple[str, int, str]]:
        """
        Check for suspicious keywords in filename.
        """
        risks = []
        filename_lower = filename.lower()
        
        for keyword in self.malicious_signatures['suspicious_keywords']:
            if keyword in filename_lower:
                severity = 45 if keyword in ['password', 'login', 'account', 'verify', 'credentials'] else 35
                risks.append((
                    f'Suspicious Keyword: {keyword}',
                    severity,
                    f'Filename contains suspicious keyword: {keyword}'
                ))
        
        return risks
    
    def _check_malicious_patterns(self, url: str, filename: str) -> List[Tuple[str, int, str]]:
        """
        Check for malicious patterns in URL and filename.
        """
        risks = []
        
        for pattern in self.malicious_signatures['malicious_patterns']:
            if re.search(pattern, url, re.IGNORECASE) or re.search(pattern, filename, re.IGNORECASE):
                risks.append((
                    'Malicious Pattern Match',
                    80,
                    f'URL matches malicious pattern: {pattern}'
                ))
        
        return risks
    
    def _is_suspicious_download_path(self, path: str) -> bool:
        """
        Check if the path suggests a suspicious download location.
        """
        suspicious_paths = [
            '/download/',
            '/dl/',
            '/get/',
            '/install/',
            '/setup/',
            '/update/'
        ]
        
        path_lower = path.lower()
        for spath in suspicious_paths:
            if spath in path_lower and any(ext in path_lower for ext in ['.exe', '.scr', '.bat', '.com']):
                return True
        
        return False


# Global instance
detector = MaliciousFileDetector()


def malicious_file_risk(url: str) -> Tuple[int, List[Tuple[str, int, str]]]:
    """
    Wrapper function that matches the interface of other risk functions.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Tuple of (score, list_of_details) where each detail is (name, weight, explanation)
    """
    return detector.detect_malicious_file_indicators(url)