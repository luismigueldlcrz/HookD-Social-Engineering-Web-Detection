import email
import re
from email.policy import default
from typing import Dict, List, Tuple

def parse_eml_file(filepath: str) -> Dict:
    """
    Parse an EML file and extract key email components.
    Returns: {
        'from': sender_email,
        'to': recipient_email,
        'subject': subject,
        'date': sent_date,
        'headers': full_headers_dict,
        'body': email_body,
        'is_html': bool,
        'return_path': return_path,
        'reply_to': reply_to,
        'spf_result': spf_header or None,
        'dkim_result': dkim_header or None,
        'dmarc_result': dmarc_header or None
    }
    """
    try:
        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=default)
        
        # Extract basic fields
        email_from = msg.get('From', 'Unknown')
        email_to = msg.get('To', 'Unknown')
        subject = msg.get('Subject', 'No Subject')
        date = msg.get('Date', 'Unknown')
        return_path = msg.get('Return-Path', 'Unknown')
        reply_to = msg.get('Reply-To', 'Unknown')
        
        # Extract body
        body = ""
        is_html = False
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
                elif part.get_content_type() == "text/html":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    is_html = True
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            is_html = msg.get_content_type() == "text/html"
        
        # Extract authentication results
        spf_result = msg.get('Received-SPF', None)
        dkim_result = msg.get('DKIM-Signature', None)
        dmarc_result = msg.get('Authentication-Results', None)
        
        return {
            'from': email_from,
            'to': email_to,
            'subject': subject,
            'date': date,
            'return_path': return_path,
            'reply_to': reply_to,
            'body': body,
            'is_html': is_html,
            'spf_result': spf_result,
            'dkim_result': dkim_result is not None,
            'dmarc_result': dmarc_result,
            'headers': dict(msg.items())
        }
    except Exception as e:
        return {
            'error': str(e),
            'from': 'Unknown',
            'to': 'Unknown',
            'subject': 'Error parsing email',
            'body': '',
            'is_html': False,
            'spf_result': None,
            'dkim_result': False,
            'dmarc_result': None,
            'headers': {}
        }

def extract_sender_domain(email_addr: str) -> str:
    """Extract domain from email address."""
    try:
        return email_addr.split('@')[1].lower()
    except:
        return ""

def extract_emails_from_text(text: str) -> List[str]:
    """Extract all email addresses from text."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text.lower())))

def check_header_spoofing(email_data: Dict) -> Tuple[List[str], bool]:
    """
    Check for header spoofing indicators.
    Returns: (warnings_list, is_spoofed)
    """
    warnings = []
    is_spoofed = False
    
    sender_email = email_data.get('from', '').lower()
    return_path = email_data.get('return_path', '').lower()
    reply_to = email_data.get('reply_to', '').lower()
    
    # Check 1: Return-Path mismatch
    if return_path and sender_email and return_path != sender_email:
        try:
            sender_domain = extract_sender_domain(sender_email)
            return_domain = extract_sender_domain(return_path)
            if sender_domain and return_domain and sender_domain != return_domain:
                warnings.append(f"Return-Path mismatch: From '{sender_domain}' != Return-Path '{return_domain}'")
                is_spoofed = True
        except:
            pass
    
    # Check 2: Reply-To mismatch (potential fraud)
    if reply_to and sender_email and reply_to != sender_email:
        try:
            sender_domain = extract_sender_domain(sender_email)
            reply_domain = extract_sender_domain(reply_to)
            if sender_domain and reply_domain and sender_domain != reply_domain:
                warnings.append(f"Reply-To redirect: From '{sender_domain}' != Reply-To '{reply_domain}'")
                is_spoofed = True
        except:
            pass
    
    # Check 3: SPF missing or failed
    spf_result = email_data.get('spf_result', '')
    if spf_result:
        if 'fail' in spf_result.lower():
            warnings.append("SPF Check Failed - Email may be spoofed")
            is_spoofed = True
        elif 'none' in spf_result.lower():
            warnings.append("SPF Not Configured - Domain doesn't authenticate")
    
    # Check 4: DKIM missing
    if not email_data.get('dkim_result'):
        warnings.append("DKIM Signature Missing - Email not cryptographically signed")
    
    return warnings, is_spoofed