import re
import pandas as pd

class PhishFeatureExtractor:
    def __init__(self):
        # Words that indicate high urgency or risk
        self.risk_words = {
            "password", "verify", "account", "login", "update", "confirm", 
            "bank", "invoice", "suspended", "limited", "secure", "detect", 
            "urgent", "immediate", "action", "required", "wire", "transfer"
        }

    def extract_features(self, text):
        if not isinstance(text, str): return {}
        
        features = {}
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        if features['text_length'] == 0: features['text_length'] = 1
        
        # 1. Caps Ratio (Urgency)
        uppercase_count = sum(1 for c in text if c.isupper())
        features['caps_ratio'] = uppercase_count / features['text_length']

        # 2. Symbol Ratio (Obfuscation)
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        features['symbol_ratio'] = special_chars / features['text_length']

        # 3. URL Count
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        features['url_count'] = len(urls)
        features['has_ip_link'] = 1 if any(re.search(r'http.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls) else 0
        
        # 4. Forensic Signals
        features['invisible_char_count'] = sum(1 for c in text if not c.isprintable())
        features['hex_escape_count'] = len(re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', text))
        
        # 5. Risk Word Density
        clean_text = text.lower()
        features['risk_word_count'] = sum(1 for w in self.risk_words if w in clean_text)
        
        return features

    def transform(self, text_list):
        rows = [self.extract_features(t) for t in text_list]
        return pd.DataFrame(rows)