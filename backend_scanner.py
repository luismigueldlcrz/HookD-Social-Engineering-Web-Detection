import joblib
import re
import math
import html
import json
import os
import pandas as pd
import numpy as np
import warnings
import sys
from urllib.parse import urlparse

# --- 1. SETUP & IMPORTS ---
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# Import custome feature engines
try:
    from feature_engine_advanced import PhishFeatureExtractor
    from forensics import ForensicFeatureExtractor
except ImportError:
    print("CRITICAL: Custom feature extractors not found. Model will fail to load.")

# --- 2. PICKLE COMPATIBILITY HACK ---
# This ensures the model finds 'get_numeric_features' in __main__
def get_numeric_features(text_series):
    extractor = PhishFeatureExtractor()
    return extractor.transform(text_series)

import __main__
setattr(__main__, "get_numeric_features", get_numeric_features)

# --- 3. CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Adjust paths to match your Flask structure
MODEL_FILE = os.path.join(BASE_DIR, 'models', 'Phish_Model_Advanced.pkl') 
WHITELIST_FILE = os.path.join(BASE_DIR, 'whitelist.json')
THRESHOLD = 0.90 

# --- 4. LISTS & CONSTANTS (Kept from your original file) ---
PROTECTED_BRANDS = [
    "bdo", "bpi", "metrobank", "landbank", "rcbc", "eastwest", "pnb", "unionbank", "securitybank",
    "globe", "smart", "pldt", "dito", "sky", "converge", "meralco", "maynilad", "manilawater",
    "gcash", "maya", "grab", "shopee", "lazada", "foodpanda", "lalamove", "angkas",
    "paypal", "netflix", "spotify", "microsoft", "apple", "google", "facebook", "instagram", "tiktok",
    "bsp", "bir", "sss", "pagibig", "philhealth", "lto", "nbi"
]

RISK_WORDS = {
    "password", "verify", "account", "login", "update", "confirm", "bank", "invoice", 
    "suspended", "limited", "secure", "detect", "unusual", "wallet", "signin", "auth", 
    "credential", "transfer", "payment", "reset", "access", "compliance", "policy", "admin"
}

INTENT_TRIGGERS = {
    "Account Security Lure": ["account suspended", "unauthorized login", "action required", "access limited"],
    "Financial/Payroll": ["wire transfer", "unpaid invoice", "payment update", "process a payment"],
    "Job/Task Scam": ["job offer", "part-time", "earn daily", "earn money", "work from home"],
    "Credential Theft": ["password expire", "reset link", "change password", "validate credentials"],
    "Prize/Lottery Scam": ["won", "winner", "prize", "congratulations", "claim your"]
}

SCAM_WORDS = ["widow", "cancer", "sick bed", "late husband", "fund", "charity", "barrister", "inheritance", "beneficiary"]

# --- 5. INITIALIZATION ---

def load_resources():
    # Load Whitelist
    whitelist = {"trusted_senders": [], "trusted_domains": []}
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                whitelist = json.load(f)
        except Exception: pass
    
    # Load Model
    model = None
    try:
        model = joblib.load(MODEL_FILE)
    except Exception as e:
        print(f"Model Load Error: {e}")
        
    return model, whitelist

# Initialize once when module is imported
MODEL, WHITELIST = load_resources()

# --- 6. HELPER FUNCTIONS ---

def normalize_text(text):
    # Text normalization
    return text.lower().strip()

def get_root_domain(address_or_url):
    try:
        if not address_or_url: return None
        if re.sub(r'[\s\-+()]', '', address_or_url).isdigit(): return None # Phone number
        
        clean = address_or_url.split('@')[-1] if '@' in address_or_url else urlparse(address_or_url).netloc
        if not clean and "://" not in address_or_url: clean = address_or_url.split('/')[0]
        
        # Simple domain extraction
        parts = clean.split('.')
        if len(parts) >= 2: return ".".join(parts[-2:])
        return clean
    except: return None

def check_harvesting_intent(text):
    text = text.lower()
    found_intents = []
    for label, keywords in INTENT_TRIGGERS.items():
        if any(k in text for k in keywords): found_intents.append(label)
    return found_intents

# --- 7. MAIN LOGIC (Refactored for Flask) ---

def scan_logic(body, sender=None):
    """
    Main entry point for the Flask App.
    Returns a dictionary result instead of printing to console.
    """
    if not sender: sender = "Unknown"
    
    warnings_list = []
    safe_indicators = []
    
    # 1. Whitelist Check
    sender_domain = get_root_domain(sender)
    is_whitelisted = False
    if sender_domain and sender_domain in [d.lower() for d in WHITELIST.get("trusted_domains", [])]:
        is_whitelisted = True
    
    if is_whitelisted:
        return {
            "label": "Safe",
            "confidence": 0,
            "css": "success",
            "message": "Sender is in your Whitelist.",
            "details": ["Verified Trusted Sender"]
        }

    # 2. AI Model Prediction
    full_text = f"Sender: {sender} Body: {body}"
    probability = 0.0
    
    if MODEL:
        try:
            # We use a DataFrame because the custom transformer expects it
            input_df = pd.DataFrame([full_text], columns=['text'])
            probability = MODEL.predict_proba(input_df)[0][1]
        except Exception as e:
            warnings_list.append(f"AI Analysis Failed: {str(e)}")
            probability = 0.5 # Fallback

    # 3. Rule-Based Overrides
    
    # A. Check bad extensions
    bad_extensions = re.findall(r'\.(exe|scr|vbs|bat|apk|jar|js)\b', body.lower())
    if bad_extensions:
        warnings_list.append(f"MALWARE: Dangerous file extension found (.{bad_extensions[0]}).")
        probability = max(probability, 0.95)

    # B. Brand Impersonation
    for brand in PROTECTED_BRANDS:
        if brand in sender.lower() or brand in body.lower():
            # If the brand is mentioned but domain is NOT official
            if sender_domain and sender_domain not in WHITELIST.get("trusted_domains", []) and brand not in sender_domain:
                 # Weak check for demo purposes
                 pass 

    # C. Intent Detection
    intents = check_harvesting_intent(body)
    if intents:
        warnings_list.append(f"Context: {', '.join(intents)} detected.")
        probability += (len(intents) * 0.10)

    # 4. Final Verdict Logic
    risk_score = int(min(probability * 100, 100))
    is_phishing = probability >= 0.75  # Slightly lower threshold for web safety

    label = "Phishing" if is_phishing else ("Suspicious" if risk_score > 50 else "Safe")
    css_class = "danger" if is_phishing else ("warning" if risk_score > 50 else "success")

    # Clean up warnings for UI
    if not warnings_list and is_phishing:
        warnings_list.append("AI Model detected high-risk linguistic patterns.")
    if not warnings_list and not is_phishing:
        warnings_list.append("No immediate threats detected.")

    return {
        "label": label,
        "confidence": risk_score,
        "css": css_class,
        "message": f"Risk Score: {risk_score}%",
        "details": warnings_list
    }