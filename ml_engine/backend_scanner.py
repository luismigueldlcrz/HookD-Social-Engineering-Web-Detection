import joblib
import re
import json
import os
import math
import html
import pandas as pd
import warnings
from urllib.parse import urlparse

# --- 1. SETUP & IMPORTS ---
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# Handle imports whether running as a package or standalone
try:
    from .feature_engine_advanced import PhishFeatureExtractor
except ImportError:
    try:
        from feature_engine_advanced import PhishFeatureExtractor
    except ImportError:
        print("CRITICAL: feature_engine_advanced.py not found. AI Model will fail.")

# --- 2. PICKLE COMPATIBILITY HACK ---
def get_numeric_features(text_series):
    extractor = PhishFeatureExtractor()
    return extractor.transform(text_series)

import __main__
setattr(__main__, "get_numeric_features", get_numeric_features)

# --- 3. CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, 'models', 'Phish_Model_Advanced.pkl') 
WHITELIST_FILE = os.path.join(os.path.dirname(BASE_DIR), 'whitelist.json')

# --- 4. LISTS & CONSTANTS ---
PROTECTED_BRANDS = [
    "bdo", "bpi", "metrobank", "landbank", "rcbc", "eastwest", "pnb", "unionbank", "securitybank",
    "globe", "smart", "pldt", "dito", "sky", "converge", "meralco", "maynilad", "manilawater",
    "gcash", "maya", "grab", "shopee", "lazada", "foodpanda", "lalamove", "angkas",
    "j&t", "jtexpress", "ninja", "ninjavan", "lbc",
    "paypal", "xendit", "paymongo",
    "philippineairlines", "cebupacific", "airasia",
    "netflix", "spotify", "disney", "primevideo", "hulu", "discord", "steam", "riot", "epic", 
    "roblox", "playstation", "xbox", "mojang", "ubisoft", "battle.net",
    "microsoft", "apple", "icloud", "google", "yahoo", "facebook", "instagram", "tiktok",
    "bsp", "bir", "sss", "pagibig", "philhealth", "lto", "psa", "nbi", 
    "mcafee", "norton", "kaspersky", "avast", "coursera", "udemy", "linkedin"
]

RISK_WORDS = {
    "password", "verify", "account", "login", "update", "confirm", "bank", "invoice", 
    "suspended", "limited", "secure", "detect", "unusual", "wallet", "signin", "auth", 
    "credential", "transfer", "payment", "reset", "access", "compliance", "policy", "admin"
}

INTENT_TRIGGERS = {
    "Account Security Lure": ["resume access", "account suspended", "account locked", "unauthorized login", "action required", "account restricted", "access limited", "account limited", "subscription is on hold", "payment declined", "prevent account closure", "under investigation", "scan the qr", "scan qr", "re-authenticate", "2fa expired", "access will be lost", "new device", "secure your account"],
    "Identity Verification": ["confirm identity", "verify activity", "security check", "verify your account", "upload id", "proof of address", "submit otp", "send full name", "otp is", "verification code"],
    "Financial/Payroll": ["direct deposit", "billing details", "payroll", "unpaid invoice", "payment update", "wire transfer", "process a payment", "outstanding payment", "swift copy", "fund dispatch", "acquisition", "settle your bill", "salary", "bonus structure", "annual review", "profit", "trading platform", "investment", "investing", "crypto", "mining farm", "returns", "wallet"],
    "Job/Task Scam": ["job offer", "part-time", "earn daily", "earn money", "per day", "liking posts", "no experience", "hiring", "work from home", "telegram", "whatsapp", "hr manager", "reserve your slot"],
    "Delivery/Parcel": ["missed delivery", "delivery preference", "claim your parcel", "claim your package", "return to sender", "schedule delivery", "shipping fee", "pending delivery", "incomplete address", "customs fee", "package is on hold", "courier", "attempted to deliver", "re-schedule", "no one was available"],
    "Credential Theft": ["password expire", "reset link", "change password", "update login", "resume uploads", "validate credentials", "reply with your password", "current password", "workstation password"],
    "Beneficiary/Legal Scam": ["barrister", "solicitor", "compensation", "inheritance", "next of kin", "funds release", "abandoned fund"],
    "Device Security/Tech Support": ["virus detected", "infected with", "malware", "spyware", "trojan", "call microsoft", "call support", "toll free", "windows security alert", "computer is infected", "hard drive", "data loss", "drivers expired"],
    "Prize/Lottery Scam": ["won", "winner", "prize", "grand draw", "congratulations", "claim your", "raffle", "dti permit", "lottery", "selected to win", "cash prize", "iphone 15", "voucher", "you have earned"]
}

# --- 5. INITIALIZATION ---
def load_resources():
    whitelist = {"trusted_senders": [], "trusted_domains": []}
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                whitelist = json.load(f)
        except Exception: pass
    
    model = None
    try:
        model = joblib.load(MODEL_FILE)
    except Exception as e:
        print(f"Model Load Error: {e}")
        
    return model, whitelist

MODEL, WHITELIST = load_resources()

# --- 6. HELPER FUNCTIONS ---
def get_clean_domain(url):
    """
    Extracts the root domain (e.g., 'www.paypal.com' -> 'paypal.com')
    Handles cleaning of protocols and paths.
    """
    try:
        if not url: return None
        # Remove whitespace
        url = url.strip()
        # Remove protocol
        if "://" in url:
            url = url.split("://")[1]
        # Remove paths/queries
        url = url.split('/')[0].split('?')[0]
        # Remove trailing punctuation often caught by regex
        url = url.rstrip('.,;:)')
        
        # Lowercase
        clean = url.lower()
        
        # Check if valid domain structure (at least one dot)
        if '.' not in clean: return None
        
        return clean
    except: return None

def is_domain_trusted(domain, trusted_list):
    """
    Checks if 'domain' is in 'trusted_list' OR is a subdomain of a trusted domain.
    Ex: 'support.paypal.com' matches 'paypal.com'
    """
    if not domain: return False
    if domain in trusted_list: return True
    
    for trusted in trusted_list:
        # Check for subdomain (e.g. "www.paypal.com" ends with ".paypal.com")
        if domain.endswith("." + trusted) or domain == "www." + trusted:
            return True
    return False

def normalize_and_log(text):
    logs = []
    if "\\u" in text or "\\x" in text:
        try:
            def decode_match(match): return chr(int(match.group(1), 16))
            text = re.sub(r'\\u([0-9a-fA-F]{4})', decode_match, text)
            text = re.sub(r'\\x([0-9a-fA-F]{2})', decode_match, text)
            logs.append("Unicode/Hex Escapes Decoded")
        except: pass 
    if "&" in text and ";" in text:
        decoded = html.unescape(text)
        if decoded != text:
            logs.append("HTML Entities Decoded")
            text = decoded

    norm_map = {
        '€': 'e', '3': 'e', '0': 'o', '1': 'i', '4': 'a', '@': 'a', '5': 's', '$': 's', '!': 'i', 'I': 'l', '|': 'l',
        'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 
        'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 
        'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ñ': 'n', 'ç': 'c'
    }

    normalized = text.lower()
    for char, replacement in norm_map.items(): normalized = normalized.replace(char, replacement)
    
    # Obfuscation Check
    text_nospace = text.replace(" ", "").lower()
    for char, replacement in norm_map.items(): text_nospace = text_nospace.replace(char, replacement)
    
    for word in RISK_WORDS:
        if word in text_nospace and word not in normalized:
             if word == "signin" and "sign in" in normalized: continue
             if word == "login" and "log in" in normalized: continue
             logs.append(f"Obfuscation Detected: Hidden '{word}'")

    return normalized, logs

def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def check_context(text):
    context_score, flags = 0, []
    text_lower = text.lower()
    dev_keywords_regex = r'\b(const|function|git|debug|module|string|int|bool|class|void)\b'
    
    if re.search(r'\b(var|let|const)\s+[a-zA-Z_]', text_lower) or re.search(dev_keywords_regex, text_lower):
        flags.append("Developer/Code Context")
        context_score -= 30

    legal_keywords = ["confidentiality notice", "privileged", "received in error", "delete this message"]
    if any(k in text_lower for k in legal_keywords):
        context_score -= 20
        flags.append("Legal Disclaimer")
    return context_score, list(set(flags))

# --- 7. MAIN LOGIC (REGEX & WHITELIST FIX) ---
def scan_logic(body, sender=None):
    if not sender or sender.strip() == "": sender = "Unknown_Sender"
    if not body: body = ""
    
    is_ocr = sender == "Image_OCR" or sender == "Unknown" or sender == "Unknown_Sender"
    
    warnings_list = []
    safe_indicators = []
    final_veto = False # Hard Fail Flag
    
    trusted_senders = [s.lower() for s in WHITELIST.get("trusted_senders", [])]
    trusted_domains = [d.lower() for d in WHITELIST.get("trusted_domains", [])]
    
    # --- 1. ROBUST LINK EXTRACTION (FIXED) ---
    # New regex avoids splitting URLs. Captures https://... or www.... or domain.com
    # Non-capturing groups (?:) ensure re.findall returns full strings, not tuples.
    raw_links = re.findall(r'(?:https?://|www\.)\S+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.\S+', body)
    
    links = []
    for l in raw_links:
        clean_l = get_clean_domain(l)
        if clean_l and len(clean_l) > 3: # Basic filter
            links.append(clean_l)

    # --- 2. WHITELIST CHECK & CONTENT ALIBI ---
    sender_clean = sender.lower().strip()
    sender_domain = get_clean_domain(sender)
    is_whitelisted = False
    
    # Check A: Sender is Trusted
    if sender_clean in trusted_senders: is_whitelisted = True
    elif sender_domain and is_domain_trusted(sender_domain, trusted_domains): is_whitelisted = True
    
    # Check B: "Content Alibi" (Critical Fix for PayPal Screenshot)
    # If the sender is unknown/OCR, BUT all found links are trusted, we consider it SAFE.
    if not is_whitelisted and links and is_ocr:
        all_links_safe = True
        for link in links:
            if not is_domain_trusted(link, trusted_domains):
                all_links_safe = False
                break 
        
        if all_links_safe:
            is_whitelisted = True
            safe_indicators.append("Verified Official URL in text.")

    if is_whitelisted:
        return {"label": "Safe", "confidence": 0, "css": "success", "message": "Verified Trusted Source", "details": ["Source/Domain matches Whitelist."]}

    # --- 3. AI MODEL ANALYSIS ---
    text_norm, sanitization_logs = normalize_and_log(body)
    context_score, context_flags = check_context(body)
    safe_indicators.extend(context_flags)
    
    probability = 0.0
    if MODEL:
        try:
            full_text = f"Sender: {sender} Body: {body}"
            input_df = pd.DataFrame([full_text], columns=['text'])
            probability = MODEL.predict_proba(input_df)[0][1]
        except: probability = 0.5
    
    # --- 4. FORENSICS (The "Veto" System) ---
    
    # A. Dangerous Extensions
    bad_extensions = re.findall(r'\.(exe|scr|vbs|bat|apk|jar|js)\b', body.lower())
    if bad_extensions:
        warnings_list.append(f"MALWARE ALERT: Dangerous file extension found (.{bad_extensions[0]}).")
        probability = max(probability, 0.95)
        final_veto = True

    # B. Link Analysis
    if links:
        for link in links:
            # Check against whitelist using Subdomain Logic
            if is_domain_trusted(link, trusted_domains):
                safe_indicators.append(f"Official Link: {link}")
                continue 

            # DGA Check
            if calculate_entropy(link) > 3.8:
                warnings_list.append(f"DGA Alert: Link '{link}' looks suspicious.")
                probability = max(probability, 0.75)
                final_veto = True
            
            # Mismatch Logic
            # In OCR/Text mode, Unknown sender = Mismatch for ANY non-whitelisted link
            is_related = False
            if sender_domain and link:
                if sender_domain == link: is_related = True
                if "google" in sender_domain and "google" in link: is_related = True
            
            if is_ocr: is_related = False 
            
            if not is_related and "suspect" not in str(sender_domain):
                warnings_list.append(f"Mismatch: Sender '{sender}' != Link '{link}'.")
                probability = max(probability, 0.85)
                final_veto = True 

    # C. Intent Detection
    found_intents = []
    for label, keywords in INTENT_TRIGGERS.items():
        if any(k in text_norm for k in keywords): found_intents.append(label)
        
    URGENCY_WORDS = ["immediately", "urgent", "suspended", "restricted", "locked", "blocked", "unauthorized", "verify now", "action required", "24 hours"]
    has_urgency = any(u in body.lower() for u in URGENCY_WORDS)

    if found_intents:
        # If OCR, we normally forgive intents (like "Login") unless Urgency or Veto exists
        if is_ocr and not has_urgency and not final_veto:
            safe_indicators.append(f"Standard UI Detected: {', '.join(found_intents)}")
        else:
            warnings_list.append(f"Suspicious Context: {', '.join(found_intents)}.")
            probability += (len(found_intents) * 0.15)

    # D. Brand Impersonation (With Brand Alibi)
    for brand in PROTECTED_BRANDS:
        if brand in text_norm:
            # BRAND ALIBI: If text says "PayPal" and contains "paypal.com", it's fine.
            has_alibi = False
            for link in links:
                 if brand in link and is_domain_trusted(link, trusted_domains):
                     has_alibi = True
            
            if has_alibi: continue 
            
            # No Alibi? Check risk factors.
            if is_ocr:
                if final_veto or has_urgency:
                     warnings_list.append(f"Brand Warning: '{brand}' detected with risk factors.")
                     probability += 0.20
            elif brand not in sender.lower():
                warnings_list.append(f"Brand Mention: '{brand}' found in non-official channel.")
                probability += 0.10

    # 5. FINAL SCORING
    probability += (context_score / 100)
    
    # SAFETY VALVE (Logic Fixed)
    # If final_veto is True (Bad Link), this block is SKIPPED.
    if is_ocr and not has_urgency and not bad_extensions and not final_veto:
        if probability > 0.40: 
             probability = 0.10
             safe_indicators.append("Visual Analysis: Static Interface detected (No Threats).")

    # VETO ENFORCEMENT
    if final_veto: 
        probability = max(probability, 0.90) 

    risk_score = int(min(probability * 100, 100))
    is_phishing = (probability >= 0.75)
    
    if is_phishing:
        label = "Phishing"
        css_class = "danger"
    elif risk_score > 50:
        label = "Suspicious"
        css_class = "warning"
    else:
        label = "Safe"
        css_class = "success"

    if not warnings_list:
        if label == "Safe": warnings_list.append("No immediate threats detected.")
        else: warnings_list.append("AI Model detected potential risk patterns.")

    return {
        "label": label, 
        "confidence": risk_score, 
        "css": css_class, 
        "message": f"Risk Score: {risk_score}%", 
        "details": warnings_list + ([f"{s}" for s in safe_indicators] if safe_indicators else [])
    }