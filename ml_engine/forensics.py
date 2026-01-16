import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

class ForensicFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts 'Deception Signals' from text.
    Must be present for Phish_Model_Advanced.pkl to load.
    """
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for text in X:
            row = []
            text_str = str(text).lower()
            
            # 1. Homoglyph Ratio (Visual Deception)
            mixed_count = len(re.findall(r'[a-z][0-9][a-z]', text_str))
            visual_swaps = text_str.count('rn') + text_str.count('vv') + text_str.count('l')
            row.append((mixed_count + visual_swaps) / (len(text_str) + 1))

            # 2. Obfuscation Score (Spaced words)
            split_words = len(re.findall(r'\b[a-z] [a-z] [a-z]\b', text_str))
            row.append(split_words)

            # 3. Panic Score (Urgency)
            panic = text_str.count('!') + text_str.count('?')
            caps_ratio = sum(1 for c in str(text) if c.isupper()) / (len(text_str) + 1)
            row.append(panic + (caps_ratio * 10))

            # 4. Technical Traps (IPs)
            ip_links = len(re.findall(r'http.*?\d{1,3}\.\d{1,3}', text_str))
            bad_tlds = len(re.findall(r'\.(xyz|top|ru|cn|tk)\b', text_str))
            row.append(ip_links * 5)
            row.append(bad_tlds)

            features.append(row)
            
        return np.array(features)