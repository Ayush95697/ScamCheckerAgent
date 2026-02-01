import re
from typing import Tuple, List, Set
from app.models import Message
from app.extraction import extractor
from app.config import settings

class ScamDetector:
    def __init__(self):
        self.extractor = extractor
        # High-risk keywords (add +0.22)
        self.high_risk_keywords = [
            "otp", "cvv", "kyc", "verify", "blocked", "lottery",
            "prize", "winner", "urgent", "urgently", "immediate", "immediately", "suspend", "suspended",
            "electricity", "disconnect", "customs", "gift",
            # Hinglish urgency/threat
            "turant", "jaldi", "abhi", "warna", "aaj", "band ho jayega", 
            "account band", "freeze", "frozen",
            # Hinglish/English OTP/KYC
            "otp bhejo", "otp send", "kyc update", "verify karo", "link kholo",
            "verify account", "verify your account", "update kyc",
            # High-signal payment/scam
            "refund", "cashback", "reward", "inaam", "prize", "collect request"
        ]
        # Medium-risk keywords (add +0.10)
        self.medium_risk_keywords = [
            "update", "pan", "aadhar", "link", "click",
            "manager", "bank", "account", "credit", "debit",
            # Hinglish/Mixed Payment/Reward
            "upi id", "paise"
        ]
        
        # Negative signals (subtract 0.10 to 0.20)
        self.negative_keywords = [
            "thank you", "ok", "yes", "no", "hello", "hi", 
            "meeting", "project", "assignment"
        ]

        # URL shorteners for extra detection
        self.shorteners = [
            "bit.ly/", "tinyurl.com/", "t.co/", "rb.gy/", "is.gd/", "goo.gl/"
        ]

    def _normalize_text(self, text: str) -> str:
        """Normalize text: lowercase, handle obfuscations, collapse whitespace."""
        text = text.lower()
        
        # Handle obfuscations for sensitive words
        # e.g., "o.t.p", "o t p", "0tp"
        for word in ["otp", "kyc", "cvv"]:
            # Pattern to find word with separators: . - _ or space
            chars = [re.escape(c) for c in word]
            # Match each char followed by optional separators, except the last char
            pattern = r"[.\-_ ]*".join(chars)
            text = re.sub(pattern, word, text)
        
        # 0 -> o in specific patterns (0tp -> otp)
        text = text.replace("0tp", "otp")
        
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _tokenize(self, text: str) -> Set[str]:
        """Extract alphanumeric tokens for word-boundary matching."""
        # Lowercase handled in _normalize_text, but we do it here just in case
        return set(re.findall(r'\b\w+\b', text.lower()))

    def _has_shortener(self, text: str) -> bool:
        """Check for common URL shorteners without protocol."""
        return any(s in text for s in self.shorteners)

    def calculate_text_score(self, text: str) -> Tuple[float, bool, bool]:
        """
        Calculates score for a text block.
        Returns (score, has_strong_evidence, has_any_evidence)
        """
        normalized = self._normalize_text(text)
        tokens = self._tokenize(normalized)
        
        s = 0.0
        keyword_score = 0.0
        matched_keywords = set()
        
        # Keyword matching (phrase or token)
        # Note: We use original text for multi-word matching sometimes, but normalized is better here
        for kw in self.high_risk_keywords:
            if kw in normalized:
                # Check if it's a multi-word phrase or a full token
                if ' ' in kw or kw in tokens:
                    keyword_score += 0.22
                    matched_keywords.add(kw)
        
        for kw in self.medium_risk_keywords:
            if kw in normalized:
                if ' ' in kw or kw in tokens:
                    keyword_score += 0.10
                    matched_keywords.add(kw)

        # Cap keyword score at 0.70
        s += min(keyword_score, 0.70)

        # URL detection (extractor + additional shortener check)
        urls = self.extractor.extract_urls(text)
        has_url = bool(urls) or self._has_shortener(normalized)
        if has_url:
            s += 0.22
            
        # Phone detection
        phones = self.extractor.extract_phone_numbers(text)
        has_phone = bool(phones)
        if has_phone:
            s += 0.15
            
        # UPI detection
        upis = self.extractor.extract_upi(text)
        has_upi = bool(upis)
        if has_upi:
            s += 0.18

        # Strong evidence: high-risk keyword OR url OR phone OR upi
        has_strong_keyword = any(kw in matched_keywords for kw in self.high_risk_keywords)
        has_strong_evidence = has_url or has_phone or has_upi or has_strong_keyword
        
        if not has_strong_evidence:
            for nkw in self.negative_keywords:
                if nkw in tokens:
                    s -= 0.15
        
        # Final cleanup for score
        s = max(0.0, s)
        
        return s, has_strong_evidence, (has_strong_evidence or keyword_score > 0)

    async def check_scam(self, message_text: str, history_text: str = "") -> Tuple[bool, float]:
        """
        Returns (is_scam, confidence_score)
        
        Examples:
        - English scam: "Your account is suspended. Click bit.ly/xfg2 to verify now!" -> is_scam=True
        - Hinglish scam: "OTP bhejo jaldi warna account band ho jayega" -> is_scam=True
        - Benign: "Hello, are we still meeting for the project tomorrow?" -> is_scam=False
        """
        score_current, strong_evidence_current, any_evidence_current = self.calculate_text_score(message_text)
        score_history, strong_evidence_history, any_evidence_history = self.calculate_text_score(history_text)
        
        # Weighted combination: history has damping factor
        total_score = score_current + (0.5 * score_history)
        total_score = min(total_score, 0.99)
        
        # Evidence rule:
        # 1. Require strong evidence in CURRENT message for immediate detection
        # 2. Allow history evidence ONLY if total_score is significantly high
        
        threshold = settings.SCAM_THRESHOLD
        
        is_scam = False
        if strong_evidence_current and total_score >= threshold:
            is_scam = True
        elif any_evidence_history and total_score >= (threshold + 0.10):
            is_scam = True
            
        return is_scam, total_score

detector = ScamDetector()
