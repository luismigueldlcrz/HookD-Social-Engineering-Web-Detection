import dns.resolver
import dns.exception
from typing import Dict, Tuple, List
import re

def check_spf_record(domain: str) -> Dict:
    """
    Query SPF record for domain.
    Returns: {
        'domain': domain,
        'spf_record': record_text or None,
        'found': bool,
        'mechanisms': list_of_mechanisms
    }
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        
        for rdata in answers:
            record_text = str(rdata)
            if 'v=spf1' in record_text:
                spf_record = record_text
                break
        
        if spf_record:
            # Parse mechanisms
            mechanisms = re.findall(r'(?:^|\s)([-~?+]?[a-z]+[^\s]*)', spf_record)
            return {
                'domain': domain,
                'spf_record': spf_record,
                'found': True,
                'mechanisms': mechanisms
            }
        else:
            return {
                'domain': domain,
                'spf_record': None,
                'found': False,
                'mechanisms': []
            }
    except (dns.exception.DNSException, Exception) as e:
        return {
            'domain': domain,
            'spf_record': None,
            'found': False,
            'mechanisms': [],
            'error': str(e)
        }

def check_dmarc_record(domain: str) -> Dict:
    """
    Query DMARC record for domain.
    Returns: {
        'domain': domain,
        'dmarc_record': record_text or None,
        'found': bool,
        'policy': p=quarantine|reject|none
    }
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        
        for rdata in answers:
            record_text = str(rdata)
            if 'v=DMARC1' in record_text:
                # Extract policy
                policy_match = re.search(r'p=(\w+)', record_text)
                policy = policy_match.group(1) if policy_match else 'unknown'
                
                return {
                    'domain': domain,
                    'dmarc_record': record_text,
                    'found': True,
                    'policy': policy
                }
        
        return {
            'domain': domain,
            'dmarc_record': None,
            'found': False,
            'policy': None
        }
    except (dns.exception.DNSException, Exception) as e:
        return {
            'domain': domain,
            'dmarc_record': None,
            'found': False,
            'policy': None,
            'error': str(e)
        }

def check_mx_records(domain: str) -> Dict:
    """
    Query MX records for domain.
    Returns: {
        'domain': domain,
        'mx_records': list_of_mx_servers,
        'found': bool
    }
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        
        for rdata in answers:
            mx_records.append({
                'priority': int(rdata.preference),
                'server': str(rdata.exchange)
            })
        
        mx_records.sort(key=lambda x: x['priority'])
        
        return {
            'domain': domain,
            'mx_records': mx_records,
            'found': len(mx_records) > 0
        }
    except (dns.exception.DNSException, Exception) as e:
        return {
            'domain': domain,
            'mx_records': [],
            'found': False,
            'error': str(e)
        }

def verify_email_authenticity(sender_domain: str) -> Tuple[List[str], float]:
    """
    Comprehensive email authentication check.
    Returns: (warnings_list, risk_score_increase)
    
    risk_score_increase can be added to the probability in scan_logic
    """
    warnings = []
    risk_increase = 0.0
    
    # Check SPF
    spf_result = check_spf_record(sender_domain)
    if not spf_result['found']:
        warnings.append(f"⚠️ SPF Not Configured: Domain '{sender_domain}' has no SPF record")
        risk_increase += 0.15
    else:
        warnings.append(f"✅ SPF Record Found: {spf_result['domain']}")
    
    # Check DMARC
    dmarc_result = check_dmarc_record(sender_domain)
    if not dmarc_result['found']:
        warnings.append(f"⚠️ DMARC Not Configured: Domain '{sender_domain}' has no DMARC policy")
        risk_increase += 0.10
    else:
        policy = dmarc_result['policy']
        if policy == 'reject':
            warnings.append(f"✅ DMARC Policy: REJECT (Strongest protection)")
        elif policy == 'quarantine':
            warnings.append(f"✅ DMARC Policy: QUARANTINE (Good protection)")
        elif policy == 'none':
            warnings.append(f"⚠️ DMARC Policy: NONE (No enforcement)")
            risk_increase += 0.05
    
    # Check MX Records
    mx_result = check_mx_records(sender_domain)
    if not mx_result['found']:
        warnings.append(f"🚨 No MX Records: Domain '{sender_domain}' cannot receive emails (LIKELY SPOOFED)")
        risk_increase += 0.50
    else:
        warnings.append(f"✅ MX Records Found: Domain can receive emails")
    
    return warnings, risk_increase

def analyze_sender_domain(sender_email: str) -> Dict:
    """
    Full analysis of sender domain.
    Returns comprehensive report for display.
    """
    try:
        domain = sender_email.split('@')[1].lower()
    except:
        return {
            'error': 'Invalid email format',
            'domain': sender_email,
            'authentication_score': 0,
            'warnings': ['Invalid email address format']
        }
    
    spf = check_spf_record(domain)
    dmarc = check_dmarc_record(domain)
    mx = check_mx_records(domain)
    
    # Calculate authentication score (0-100)
    score = 50  # Base score
    if spf['found']: score += 20
    if dmarc['found']: score += 20
    if mx['found']: score += 10
    
    if dmarc['found'] and dmarc['policy'] == 'reject': score += 10
    
    return {
        'domain': domain,
        'spf': spf,
        'dmarc': dmarc,
        'mx': mx,
        'authentication_score': min(score, 100),
        'is_likely_legitimate': score >= 70,
        'warnings': []
    }