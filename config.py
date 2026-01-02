import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-prod'
    ANALYSIS_TIMEOUT = 10  # Seconds for fetches
    
    # Adjusted weights to reduce false positives - domain/SSL more trusted for legitimate sites
    RISK_WEIGHTS = {
        'lexical': 0.20,      # Further reduced: lexical can over-trigger on legitimate complex URLs
        'domain': 0.30,       # Increased: domain age/reputation is strong signal
        'ssl': 0.25,          # Increased: valid SSL is strong legitimacy indicator
        'content': 0.15,      # Reduced: content analysis can false positive
        'ai_analysis': 0.10,  # Reduced: AI patterns can have false positives
        # Advanced feature weights (lower to complement existing analysis)
        'advanced_lexical': 0.08,
        'advanced_structural': 0.07,
        'advanced_domain': 0.06,
        'advanced_content': 0.05,
        'advanced_javascript': 0.10,
        'advanced_heuristic': 0.08,
        'advanced_behavioral': 0.12,
        'advanced_certificate': 0.09  # NEW: Advanced certificate analysis
    }
    
    # More conservative thresholds to reduce false positives
    THRESHOLDS = {
        'safe': 40,           # More forgiving threshold
        'suspicious': 70      # Higher bar for declaring malicious
    }
    
    # Comprehensive whitelist of major legitimate domains
    TRUSTED_DOMAINS = [
        # Google services
        'google.com', 'www.google.com', 'gmail.com', 'youtube.com',
        'google.co.uk', 'google.ca', 'google.de', 'google.fr',
        'accounts.google.com', 'mail.google.com', 'drive.google.com',
        'docs.google.com', 'maps.google.com', 'play.google.com',
        
        # Microsoft services
        'microsoft.com', 'www.microsoft.com', 'live.com', 'outlook.com',
        'hotmail.com', 'office.com', 'windows.com', 'xbox.com',
        'azure.com', 'bing.com', 'msn.com',
        
        # Apple services
        'apple.com', 'www.apple.com', 'icloud.com', 'me.com',
        'mac.com', 'itunes.com', 'appstore.com',
        
        # Social media
        'facebook.com', 'www.facebook.com', 'instagram.com', 'twitter.com',
        'x.com', 'linkedin.com', 'pinterest.com', 'snapchat.com',
        'tiktok.com', 'whatsapp.com', 'web.whatsapp.com', 'm.whatsapp.com', 'telegram.org',
        
        # E-commerce
        'amazon.com', 'www.amazon.com', 'ebay.com', 'walmart.com',
        'target.com', 'etsy.com', 'shopify.com',
        
        # Financial
        'paypal.com', 'www.paypal.com', 'stripe.com', 'square.com',
        'visa.com', 'mastercard.com',
        
        # Tech/Development
        'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
        'npmjs.com', 'python.org', 'nodejs.org',
        
        # News/Media
        'cnn.com', 'bbc.com', 'bbc.co.uk', 'nytimes.com', 'theguardian.com',
        'reuters.com', 'bloomberg.com', 'wsj.com',
        
        # Education
        'wikipedia.org', 'wikimedia.org', 'coursera.org', 'udemy.com',
        'khanacademy.org', 'edx.org',
        
        # Other major services
        'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
        'adobe.com', 'salesforce.com', 'oracle.com', 'ibm.com',
        'reddit.com', 'wordpress.com', 'medium.com'
    ]
    
    # Legitimate domain patterns (case-insensitive matching)
    KNOWN_LEGITIMATE_PATTERNS = [
        # CDNs and cloud services
        'cloudflare', 'akamai', 'amazonaws', 'azureedge', 'googleusercontent',
        'cloudfront', 'fastly', 'cdn77', 'jsdelivr', 'unpkg', 'gstatic',
        # Major platforms
        'github', 'gitlab', 'bitbucket', 'stackoverflow', 'reddit',
        'wikipedia', 'medium', 'wordpress', 'blogger', 'tumblr',
        # Enterprise/business
        'sharepoint', 'office365', 'salesforce', 'zendesk', 'atlassian',
        # Analytics/tracking (often trigger false positives)
        'doubleclick', 'google-analytics', 'googletagmanager', 'hotjar',
        # Social media platforms (including subdomains)
        'facebook', 'instagram', 'twitter', 'x', 'linkedin', 'pinterest', 'snapchat',
        'tiktok', 'whatsapp', 'telegram', 'discord', 'twitch',
        # Educational TLDs (US and International)
        '.edu',        # US higher education
        '.ac.uk',      # UK academic
        '.ac.in',      # India academic
        '.ac.jp',      # Japan academic
        '.ac.au',      # Australia academic
        '.ac.nz',      # New Zealand academic
        '.ac.za',      # South Africa academic
        '.ac.kr',      # South Korea academic
        '.ac.cn',      # China academic
        '.edu.au',     # Australia education
        '.edu.cn',     # China education
        '.edu.sg',     # Singapore education
        '.edu.my',     # Malaysia education
        '.edu.pk',     # Pakistan education
        '.edu.bd',     # Bangladesh education
        # Government TLDs
        '.gov', '.gov.uk', '.gov.au', '.gov.in', '.gov.sg',
        # Military and International Organizations
        '.mil', '.int',
        # Non-profit and trusted TLDs
        '.org', '.net'
    ]
    
    # Educational institution keywords (for additional validation)
    EDUCATIONAL_KEYWORDS = [
        'university', 'college', 'school', 'institute', 'academy',
        'education', 'learning', 'campus', 'student', 'faculty'
    ]