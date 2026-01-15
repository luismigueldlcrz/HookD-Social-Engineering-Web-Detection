# config.py

# --- CONFIGURATION ---
MODEL_FILE = 'Phish_Model_Advanced.pkl'
WHITELIST_FILE = 'whitelist.json'
THRESHOLD = 0.90 

# --- PROTECTED BRANDS LIST ---
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

# --- EXPANDED INTENT TRIGGERS ---
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

SCAM_WORDS = ["widow", "cancer", "sick bed", "late husband", "divine", "god bless", "fund", "charity", "barrister", "compensation", "inheritance", "beneficiary", "diplomat"]
BEC_TRIGGERS = ["wire transfer", "process a payment", "outstanding payment", "swift", "acquisition"]
HYPE_WORDS = [w for w in ["bonus", "limited-time", "offer ends", "hurry", "prize", "winner", "casino"]]