import re
from typing import List, Dict, Any

class Extractor:
    def __init__(self):
        # UPI Pattern: generic capture first, then validate
        self.upi_pattern = re.compile(
            r'[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]{2,}', re.IGNORECASE
        )
        
        self.excluded_domains = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
            "icloud.com", "protonmail.com", "rediffmail.com", "yandex.com"
        }
        
        self.common_upi_suffixes = {
            "ybl", "okaxis", "okhdfcbank", "okicici", "paytm", "axl", "sbi", 
            "icici", "hdfc", "kotak", "upi", "apl", "yono"
        }

        # Bank Account: 9-18 digits, avoiding obvious phone numbers
        self.bank_account_pattern = re.compile(
            r'\b(?![6789]\d{9}\b)\d{9,18}\b'
        )
        
        # Phone: +91 followed by 10 digits or just 10 digits starting with 6-9
        self.phone_pattern = re.compile(
            r'(?:\+91[\-\s]?)?[6789]\d{9}\b'
        )
        
        # URL: Capture http/https OR known shorteners
        self.url_pattern_strict = re.compile(
            r'https?://[^\s()<>"]+(?:[-\w./?=&%#]*)'
        )
        self.shortener_pattern = re.compile(
            r'\b(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy)/[a-zA-Z0-9_-]+', re.IGNORECASE
        )
        
        # Suspicious keywords
        self.suspicious_keywords = [
            "urgent", "verify", "blocked", "kyc", "otp", "refund", "reward", 
            "winner", "lottery", "click here", "update pan", "suspend", 
            "electricity", "disconnect", "prize", "gift", "loan", "investment"
        ]

    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract all intelligence from a single text block."""
        return {
            "upi": self.extract_upi(text),
            "bank": self.extract_bank_accounts(text),
            "links": self.extract_urls(text),
            "phones": self.extract_phone_numbers(text),
            "keywords": self.extract_keywords(text)
        }

    def extract_from_messages(self, messages: List[Any]) -> Dict[str, List[str]]:
        """Loop through messages and merge intelligence."""
        merged = {
            "upi": [], "bank": [], "links": [], "phones": [], "keywords": []
        }
        
        full_text = " ".join([m.text for m in messages])
        
        merged["upi"] = self.extract_upi(full_text)
        merged["bank"] = self.extract_bank_accounts(full_text)
        merged["links"] = self.extract_urls(full_text)
        merged["phones"] = self.extract_phone_numbers(full_text)
        merged["keywords"] = self.extract_keywords(full_text)
        
        return merged

    def extract_upi(self, text: str) -> List[str]:
        candidates = self.upi_pattern.findall(text)
        valid = []
        
        email_providers = {
            "gmail", "yahoo", "outlook", "hotmail", "icloud", 
            "protonmail", "zoho", "yandex", "live"
        }
        
        allowlist_psps = {
            "ybl", "okaxis", "okhdfcbank", "okicici", "paytm", "axl", "sbi", 
            "icici", "hdfc", "kotak", "upi", "apl", "ibl", "airtel", "jio"
        }

        for c in candidates:
            c = c.lower().strip()
            # Strip trailing dots or punctuation that might be captured from sentences
            c = re.sub(r'[.\-]$', '', c)
            
            parts = c.split('@')
            if len(parts) != 2:
                continue
            
            domain = parts[1].lower()
            
            # Extract the first part of the domain (e.g. 'gmail' from 'gmail.com')
            domain_primary = domain.split('.')[0]
            
            # Rule: Accept if (domain in allowlist) OR (domain has no dots AND len(domain) <= 12)
            # ALSO reject if domain_primary is a known email provider
            if domain_primary in email_providers:
                continue
                
            if domain in allowlist_psps:
                valid.append(c)
            elif '.' not in domain and len(domain) <= 12:
                valid.append(c)
            
        return list(set(valid))

    def extract_bank_accounts(self, text: str) -> List[str]:
        accounts = self.bank_account_pattern.findall(text)
        return list(set(accounts)) or []

    def extract_phone_numbers(self, text: str) -> List[str]:
        matches = self.phone_pattern.findall(text)
        normalized = []
        for m in matches:
            clean = re.sub(r'[^\d]', '', m)
            if len(clean) > 10 and clean.startswith('91'):
                clean = '+' + clean
            elif len(clean) == 10:
                clean = '+91' + clean
            normalized.append(clean)
        return list(set(normalized)) or []

    def extract_urls(self, text: str) -> List[str]:
        # Capture standard URLs: handle any non-whitespace after protocol
        # url_pattern_strict = re.compile(r'https?://\S+')
        urls = re.findall(r'https?://\S+', text)
        
        # Capture shorteners without protocol
        shorteners = self.shortener_pattern.findall(text)
        
        normalized = []
        # Trailing punctuation to strip: ) . , ; ! ? " '
        strip_chars = ').,;!?"'
        
        for u in urls:
            normalized.append(u.rstrip(strip_chars))
            
        for s in shorteners:
            # Prepend https:// and strip punctuation
            clean_s = s.rstrip(strip_chars)
            normalized.append(f"https://{clean_s}")
            
        return list(set(normalized)) or []

    def extract_keywords(self, text: str) -> List[str]:
        found = []
        text_lower = text.lower()
        for kw in self.suspicious_keywords:
            if kw in text_lower:
                found.append(kw)
        return list(set(found)) or []

extractor = Extractor()
