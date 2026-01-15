# phish_scanner.py

import joblib
import re
import sys
import json
import os
import pandas as pd
import numpy as np
import warnings
from urllib.parse import urlparse

# --- IMPORT LOCAL MODULES ---
# This pulls in your lists and helper functions without cluttering this file
from config import *
from utils import *

# --- SILENCE WARNINGS ---
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# --- IMPORT FEATURE ENGINE (CRITICAL) ---
try:
    from feature_engine_advanced import PhishFeatureExtractor
except ImportError:
    print("⚠️ Warning: feature_engine_advanced.py not found. AI Model might not load.")

# --- ESSENTIAL HELPER FOR AI MODEL LOADING ---
def get_numeric_features(text_series):
    extractor = PhishFeatureExtractor()
    return extractor.transform(text_series)

import __main__
setattr(__main__, "get_numeric_features", get_numeric_features)

# --- 1. LOAD EXTERNAL ASSETS ---
print("🔄 SYSTEM: Initializing Resources...")

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                data = json.load(f)
                count = len(data.get('trusted_senders', [])) + len(data.get('trusted_domains', []))
                print(f"✅ SYSTEM: Whitelist Loaded ({count} entries).")
                return data
        except Exception as e:
            print(f"⚠️ Warning: Could not parse whitelist.json: {e}")
    else:
        print("ℹ️ Info: No whitelist.json found. Creating a blank one.")
        blank = {"trusted_senders": [], "trusted_domains": []}
        try:
            with open(WHITELIST_FILE, 'w') as f:
                json.dump(blank, f, indent=4)
        except: pass
        return blank

whitelist = load_whitelist()

try:
    model = joblib.load(MODEL_FILE)
    print("✅ SYSTEM: Advanced AI Model Loaded.")
except FileNotFoundError:
    print(f"❌ ERROR: Could not load '{MODEL_FILE}'.")
    print("⚠️ WARNING: Running in 'Forensic Logic Only' mode.")
    model = None
except Exception as e:
    print(f"❌ ERROR: Model failed to load. Reason: {e}")
    model = None

# --- 7. FORENSIC REPORT ENGINE ---
def get_detailed_report(text, sender, probability):
    warnings, is_vetoed = [], False
    text_norm, sanitization_logs = normalize_and_log(text)
    context_score, context_flags = check_context(text)
    is_dev_email = "Developer/Code" in str(context_flags)
    
    if sanitization_logs:
        for log in sanitization_logs:
            text_clean_alpha = re.sub(r'[^a-z]', '', text_norm) 
            imperative = any(t in text_norm for t in ["reset", "verify", "confirm", "update"])
            if is_dev_email and "Escapes Decoded" in log and not imperative:
                warnings.append(f"ℹ️ INFO: {log} (Likely code snippet).")
            else:
                warnings.append(log)
                if probability > 0.60: is_vetoed = True 
            
    text_lower = text.lower()
    if sender and "@" in sender:
        try:
            sender_domain = sender.split('@')[1]
            if any(sender_domain.endswith(x) for x in ['.xyz', '.top', '.club', '.info', '.br', '.ru']):
                warnings.append(f"🔺 SENDER: 🚩 Suspicious TLD ('{sender_domain}').")
                is_vetoed = True
            if sum(c.isdigit() for c in sender_domain) > 3:
                warnings.append(f"🔺 SENDER: 🚩 Domain looks algorithmic.")
                is_vetoed = True
            safe_rn = ["corn", "internal", "journal", "modern", "internet"]
            if "rn" in sender_domain and not any(s in sender_domain for s in safe_rn): 
                warnings.append(f"🔺 ADDRESS: 🚨 HOMOGLYPH SPOOF: Detected 'rn' (fake 'm').")
                is_vetoed = True
        except: pass

    found_scam = [w for w in SCAM_WORDS if w in text_norm]
    has_money = "million" in text_norm or "usd" in text_norm or re.search(r'\$\s?[\d,]{5,}', text)
    
    if has_money and len(found_scam) >= 1:
        warnings.append(f"🔺 NARRATIVE: 🎭 419 SCAM: High-Value Promise + Triggers.")
        is_vetoed = True
        
    if any(t in text_norm for t in BEC_TRIGGERS):
        if "Legal Disclaimer" not in str(context_flags):
            warnings.append(f"🔺 NARRATIVE: 👔 BEC/CEO FRAUD: Urgent executive request.")
            is_vetoed = True

    if "processing fee" in text_norm or "customs charge" in text_norm or "customs fee" in text_norm or "unpaid" in text_norm:
        warnings.append(f"🔺 MONEY: 💸 FEE SCAM: Request for fees/unpaid charges.")
        is_vetoed = True

    hype = [w for w in HYPE_WORDS if w in text_norm]
    if len(hype) >= 2:
        warnings.append(f"🔸 SPAM: 📢 Marketing hype detected.")

    if len(re.findall(r'http.*?\d{1,3}\.\d{1,3}', text_lower)) > 0:
        warnings.append(f"🔺 LINK: 🚫 DANGEROUS URL: Raw IP address detected.")
        is_vetoed = True

    return warnings, is_vetoed, "PHISHING", context_flags, context_score

# --- 8. MAIN SCANNER ENGINE ---
def full_security_scan(sender, body, mode='1'):
    if mode == '3': sender = "No_Sender_Provided"
    elif not sender.strip(): sender = "Unknown_Sender"

    print("\n" + "="*70)
    print(f"🔍 ANALYZING: {sender}")
    print("-" * 70)

    # --- LAYER 0: WHITELIST CHECK ---
    if mode != '3':
        sender_clean = sender.lower().strip()
        sender_domain = get_root_domain(sender)
        is_whitelisted = False
        
        if sender_clean in [s.lower() for s in whitelist.get("trusted_senders", [])]: is_whitelisted = True
        elif sender_domain and sender_domain in [d.lower() for d in whitelist.get("trusted_domains", [])]: is_whitelisted = True
        
        if sender_clean.endswith(".gov.ph") or (sender_domain and sender_domain.endswith(".gov.ph")):
            is_whitelisted = True

        if is_whitelisted:
            print("🤖 RISK CONFIDENCE: 0%")
            print(f"✅ VERDICT: SAFE (Whitelisted Sender)")
            print("="*70 + "\n")
            return

    # --- STANDARD ANALYSIS ---
    warnings_list, safe_indicators = [], []
    full_text = f"Sender: {sender} Body: {body}"
    
    try:
        if model:
            input_df = pd.DataFrame([full_text], columns=['text'])
            probability = model.predict_proba(input_df)[0][1]
        else: probability = 0.0
    except: probability = 0.0

    # --- B. SENDER TYPE LOGIC ---
    is_phone_sender = re.sub(r'[\s\-+]', '', sender).isdigit()
    
    # FIX: Regex update to catch "naked" domains (without http), e.g. gcash-support.live
    links = re.findall(r'(?:https?://|www\.|[a-zA-Z0-9-]+\.(?:com|org|net|edu|gov|ph|live|xyz|info|site|online|co|me|io|ly|app|net)\b)(?:/[^\s]*)?', body)
    
    # FIX: Check for Dangerous Attachment Extensions
    bad_extensions = re.findall(r'\.(exe|scr|vbs|bat|apk|jar|js)\b', body.lower())
    if bad_extensions:
        warnings_list.append(f"🚨 MALWARE ALERT: Dangerous file extension found (.{bad_extensions[0]}).")
        probability = max(probability, 0.95)

    if mode == '2' and links:
        # CHECK: If link is Trusted, do NOT penalize SMS
        link_safe = False
        for link in links:
            lr = get_root_domain(link)
            if lr in whitelist.get("trusted_domains", []): link_safe = True
        
        if not link_safe:
            probability = max(probability, 0.65)
            warnings_list.append("🚨 SMS RISK: SMS contains a link.")

    sender_root, is_impersonating = None, False
    if mode != '3' and (not is_phone_sender or "@" in sender):
        sender_root = get_root_domain(sender)
        if sender_root and "[SUSPICIOUS-SCRIPT]" in sender_root:
            warnings_list.append(f"🚩 SENDER SPOOF: Non-Standard Characters detected in '{sender}'.")
            probability = max(probability, 0.95)
            is_impersonating = True

    if links:
        for link in links:
            link_root = get_root_domain(link)
            if link_root and "[SUSPICIOUS-SCRIPT]" in link_root:
                warnings_list.append(f"🚩 LINK SPOOF: Non-Standard Characters detected in link '{link_root}'.")
                probability = max(probability, 0.95)
                continue
            
            if link_root and calculate_entropy(link_root) > 3.8:
                probability = max(probability, 0.75)
                warnings_list.append(f"🚩 DGA ALERT: Link domain '{link_root}' looks generated.")

            if sender_root and link_root:
                # FIX: Cross-Domain Trust (e.g., Gmail -> Google Docs is fine)
                is_related = False
                if sender_root == link_root: is_related = True
                if "gmail.com" in sender_root and "google.com" in link_root: is_related = True
                if "google.com" in sender_root and "google" in link_root: is_related = True
                
                if is_related:
                    safe_indicators.append(f"✅ 🛡️ AUTHORITY: Link matches sender ({link_root}).")
                    probability -= 0.20
                else:
                    if "SUSPICIOUS" not in sender_root:
                        # Check if link is in whitelist before punishing mismatch
                        link_is_safe = link_root in whitelist.get("trusted_domains", [])
                        if not link_is_safe:
                            probability = max(probability, 0.85)
                            warnings_list.append(f"🚩 DOMAIN MISMATCH: Sender '{sender_root}' != Link '{link_root}'.")
            
            elif is_phone_sender and mode == '2' and link_root:
                # Check whitelist again for phone links
                if link_root not in whitelist.get("trusted_domains", []):
                    warnings_list.append(f"🚩 SMS CONTEXT: Phone sender providing link to '{link_root}'.")

    # --- BRAND IMPERSONATION CHECK (Layer 8) ---
    domains_to_check = []
    if mode != '3' and "@" in sender:
        try:
            # CRITICAL FIX: Normalize sender before checking impersonation to catch Homoglyphs (paypaI -> paypal)
            sender_host = sender.split('@')[1]
            domains_to_check.append(normalize_text(sender_host))
        except: pass
        
    if links:
        for link in links:
            try:
                parsed = urlparse(link)
                full_host = parsed.netloc
                # Handle cases where urlparse fails on naked domains
                if not full_host: full_host = link.split('/')[0]
                if full_host: domains_to_check.append(normalize_text(full_host))
            except: pass

    for domain in domains_to_check:
        for brand in PROTECTED_BRANDS:
            if brand in domain:
                root_dom = get_root_domain(domain)
                # If the domain IS the brand, ignore
                if root_dom == f"{brand}.com" or root_dom == f"{brand}.com.ph" or root_dom == f"{brand}.me":
                    continue 

                is_official = False
                for official_domain in whitelist.get("trusted_domains", []):
                    if root_dom == official_domain or domain == official_domain or domain.endswith("." + official_domain):
                        is_official = True; break
                
                if not is_official:
                    warnings_list.append(f"🚨 IMPERSONATION: Domain '{domain}' mimics protected brand '{brand}'.")
                    probability = max(probability, 0.95)
                    is_impersonating = True

    # --- C. INTENT & FORENSICS ---
    intents = check_harvesting_intent(body)
    if intents:
        probability += (len(intents) * 0.15)
        # REVERTED: No extra penalty for Job/Task/Prize scams, keeping them at base level
        if "Financial/Payroll" in intents or "Job/Task Scam" in intents: probability += 0.20
        warnings_list.append(f"🎭 HARVESTING INTENT: {', '.join(intents)} lure detected.")

    f_warnings, f_vetoed, v_type, ctx_flags, ctx_score = get_detailed_report(body, sender, probability)
    
    probability += (ctx_score / 100)
    safe_indicators.extend(ctx_flags)
    warnings_list.extend(f_warnings)

    final_veto = f_vetoed or is_impersonating or bad_extensions
    if final_veto: probability = max(probability, 0.85)
    
    safety_triggers = ["unsubscribe", "manage preferences", "safely ignore"]
    for phrase in safety_triggers:
        if phrase in body.lower():
            safe_indicators.append(f"✅ 💡 CONTEXT: Verified 'Safety Valve' found: '{phrase}'.")
            if not final_veto: probability -= 0.15
            
    # SAFETY MEASURE: Short Message Sanity Check
    # FIX: Added 'php', '₱', and reduced digit count to 3 to catch "₱1,500"
    has_money_trigger = "million" in normalize_text(body) or "usd" in normalize_text(body) or "php" in normalize_text(body) or re.search(r'[₱$]\s?[\d,]{3,}', body)
    
    # CRITICAL FIX: Do NOT pass sanity check if ANY bad intent is found (including Delivery/Account)
    has_bad_intent = "Job/Task Scam" in intents or "Financial/Payroll" in intents or "Prize/Lottery Scam" in intents or "Delivery/Parcel" in intents or "Account Security Lure" in intents or "Identity Verification" in intents

    # SANITY CHECK: Short + No Links + No Veto + No Bad Intent + No Money -> SAFE
    if len(body.split()) < 25 and not links and not final_veto and not has_bad_intent and not has_money_trigger and not warnings_list:
         probability = 0.10
         safe_indicators.append("✅ 💡 CONTEXT: Short, benign conversation detected.")

    is_phishing = (probability >= THRESHOLD) or (final_veto and probability > 0.75)
    risk_score = int(max(0, min(probability * 100, 100)))
    if is_phishing and risk_score < 90: risk_score = 90
    
    print(f"🤖 RISK CONFIDENCE: {risk_score}%")
    if is_phishing:
        if final_veto: print("🚫 VETO APPLIED: Forensic Trap confirms risk.")
        unique_warnings = list(set(warnings_list))
        for w in unique_warnings: print(f"   {w}")
        print("-" * 70)
        print(f"🚨 FINAL VERDICT: {v_type} DETECTED")
    elif probability >= 0.60: 
        print("   ⚠️  ANALYSIS: Signs of Spam or Aggression.")
        unique_warnings = list(set(warnings_list))
        for w in unique_warnings: print(f"   - {w}")
        print("-" * 70)
        print("⚠️ FINAL VERDICT: PROCEED WITH CAUTION")
    else:
        if safe_indicators:
            for s in safe_indicators: print(f"   {s}")
        if warnings_list:
            print("   --- MINOR WARNINGS ---")
            unique_warnings = list(set(warnings_list))
            for w in unique_warnings: print(f"   {w}")
        print("-" * 70)
        print("✅ FINAL VERDICT: SAFE MESSAGE")
    print("="*70 + "\n")

if __name__ == "__main__":
    print("\n🛡️  ADVANCED PHISHING & SMS DETECTOR - DIAMOND EDITION")
    while True:
        try:
            print("\n-------------------------")
            print("[1] Email Analysis (Sender + Body)")
            print("[2] SMS/Text Analysis (Phone# + Body)")
            print("[3] Text Only (Body Scan)")
            m = input("Select Mode (or type 'exit'): ")
            if m.lower() == 'exit': break
            s = ""
            if m == '1' or m == '2': s = input("1. Enter Sender (Email or Phone/ID): ")
            print(f"{'2.' if m != '3' else '1.'} Enter Message Body (Ctrl+Z/D to finish):")
            lines = []
            try:
                while True: lines.append(input())
            except EOFError: pass
            full_security_scan(s, "\n".join(lines), m)
        except KeyboardInterrupt: break