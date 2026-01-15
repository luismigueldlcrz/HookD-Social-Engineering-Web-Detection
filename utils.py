# utils.py
import re
import math
import html
from urllib.parse import urlparse
from config import *

# --- LAYER 7: VISUAL NORMALIZATION ---
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

    # FIX: Added 'ë' and other accented characters
    norm_map = {
        '€': 'e', '3': 'e', '0': 'o', '1': 'i', '4': 'a', '@': 'a', '5': 's', '$': 's', '!': 'i', 'I': 'l', '|': 'l',
        'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 
        'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 
        'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ñ': 'n', 'ç': 'c'
    }

    clean_tokens = []
    found_obfuscated_risk_words = []
    
    for token in text.split():
        invisible_chars = [c for c in token if not c.isprintable()]
        if invisible_chars:
            clean_token = "".join(c for c in token if c.isprintable())
            temp_norm = clean_token.lower()
            for char, replacement in norm_map.items(): temp_norm = temp_norm.replace(char, replacement)
            if temp_norm in RISK_WORDS: found_obfuscated_risk_words.append(clean_token)
            clean_tokens.append(clean_token)
        else:
            clean_tokens.append(token)
            
    text = " ".join(clean_tokens)
    text_nospace = text.replace(" ", "").lower()
    for char, replacement in norm_map.items(): text_nospace = text_nospace.replace(char, replacement)
        
    for word in RISK_WORDS:
        if word in text_nospace and word not in text.lower():
            if word == "signin" and "sign in" in text.lower(): continue
            if word == "login" and "log in" in text.lower(): continue
            logs.append(f"🛡️ SANITIZATION: Split-Word Obfuscation detected ('{word}')")
            break 

    if found_obfuscated_risk_words:
        unique_matches = list(set(found_obfuscated_risk_words))
        logs.append(f"🛡️ SANITIZATION: Obfuscation detected in RISK WORDS: {', '.join(unique_matches)}")

    normalized = text.lower()
    for char, replacement in norm_map.items(): normalized = normalized.replace(char, replacement)
    return normalized, logs

def normalize_text(text):
    norm, _ = normalize_and_log(text)
    return norm

# --- LAYER 1: DOMAIN AUTHORITY ---
def get_root_domain(address_or_url):
    try:
        if re.sub(r'[\s\-+()]', '', address_or_url).isdigit(): return None
        clean = address_or_url.split('@')[-1] if '@' in address_or_url else urlparse(address_or_url).netloc
        if not clean and "://" not in address_or_url: clean = address_or_url.split('/')[0]
        
        for c in clean:
            code = ord(c)
            if not (code < 128 or (192 <= code <= 255)): return f"[SUSPICIOUS-SCRIPT]:{clean}"

        clean = normalize_text(clean)
        parts = clean.split('.')
        # FIX: Handle multi-part TLDs like .com.ph or .co.uk
        if len(parts) > 2 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
            return ".".join(parts[-3:])
        if len(parts) >= 2: return ".".join(parts[-2:])
        return clean
    except: return None

# --- LAYER 4: CONTEXT ANALYSIS LAYER ---
def check_context(text):
    context_score, flags = 0, []
    text_lower = text.lower()
    
    # CRITICAL FIX: Use Regex Boundaries for Developer keywords to avoid "avoid" triggering "void"
    dev_keywords_regex = r'\b(const|function|git|debug|module|string|int|bool|class|void)\b'
    
    if re.search(r'\b(var|let|const)\s+[a-zA-Z_]', text_lower):
        flags.append("variable_decl")
        context_score -= 30

    if re.search(dev_keywords_regex, text_lower):
         context_score -= 30
         flags.append("✅ 💡 CONTEXT: 'Developer/Code' context detected.")

    if " code " in text_lower and not any(x in text_lower for x in ["qr code", "verification code", "security code"]):
        context_score -= 30
        flags.append("✅ 💡 CONTEXT: 'Developer/Code' context detected.")

    legal_keywords = ["confidentiality notice", "privileged", "received in error", "delete this message"]
    if any(k in text.lower() for k in legal_keywords):
        context_score -= 20
        flags.append("✅ 💡 CONTEXT: 'Legal Disclaimer' detected.")
    return context_score, list(set(flags))

# --- LAYER 6: ENTROPY ---
def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

# --- LAYER 2: INTENT DETECTION ---
def check_harvesting_intent(text):
    norm_text = normalize_text(text)
    found_intents = []
    for label, keywords in INTENT_TRIGGERS.items():
        if any(k in norm_text for k in keywords): found_intents.append(label)
    return found_intents