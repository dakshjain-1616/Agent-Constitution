"""PII (Personally Identifiable Information) detector using regex and Ollama."""

import re
import json
from typing import Dict, List, Optional, Tuple, Any
import httpx
from dataclasses import dataclass


@dataclass
class PIIMatch:
    """Represents a detected PII entity."""
    pattern_name: str
    matched_text: str
    start_pos: int
    end_pos: int
    confidence: float = 1.0


class PIIDetector:
    """Detects PII in text using regex patterns and optional Ollama integration."""
    
    # Default regex patterns for common PII types
    DEFAULT_PATTERNS = {
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email addresses'
        },
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
            'description': 'Social Security Numbers'
        },
        'phone': {
            'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'description': 'Phone numbers'
        },
        'credit_card': {
            'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b',
            'description': 'Credit card numbers'
        },
        'ip_address': {
            'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'description': 'IP addresses'
        },
        'api_key': {
            'pattern': r'\b(?:api[_-]?key|apikey)[\s]*[=:]+[\s]*["\']?[a-zA-Z0-9_\-]{16,}["\']?\b',
            'description': 'API keys',
            'flags': re.IGNORECASE
        },
        'password': {
            'pattern': r'\b(?:password|passwd|pwd)[\s]*[=:]+[\s]*["\']?[^"\'\s]{4,}["\']?\b',
            'description': 'Passwords in text',
            'flags': re.IGNORECASE
        },
    }
    
    def __init__(
        self,
        enabled: bool = True,
        patterns: Optional[List[str]] = None,
        use_ollama: bool = False,
        ollama_model: str = "gemma3:4b",
        ollama_url: str = "http://localhost:11434",
        sensitivity: str = "medium",
        custom_patterns: Optional[Dict[str, Dict]] = None
    ):
        """Initialize the PII detector.
        
        Args:
            enabled: Whether PII detection is enabled
            patterns: List of pattern names to use (from DEFAULT_PATTERNS)
            use_ollama: Whether to use Ollama for advanced detection
            ollama_model: Ollama model name to use
            ollama_url: Ollama API URL
            sensitivity: Detection sensitivity (low, medium, high)
            custom_patterns: Additional custom regex patterns
        """
        self.enabled = enabled
        self.use_ollama = use_ollama
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url.rstrip('/')
        self.sensitivity = sensitivity
        
        # Compile regex patterns
        self._patterns = {}
        if patterns is None:
            patterns = list(self.DEFAULT_PATTERNS.keys())
        
        for name in patterns:
            if name in self.DEFAULT_PATTERNS:
                pattern_info = self.DEFAULT_PATTERNS[name]
                flags = pattern_info.get('flags', 0)
                try:
                    self._patterns[name] = re.compile(pattern_info['pattern'], flags)
                except re.error as e:
                    print(f"Warning: Failed to compile pattern '{name}': {e}")
        
        # Add custom patterns
        if custom_patterns:
            for name, pattern_info in custom_patterns.items():
                flags = pattern_info.get('flags', 0)
                try:
                    self._patterns[name] = re.compile(pattern_info['pattern'], flags)
                except re.error as e:
                    print(f"Warning: Failed to compile custom pattern '{name}': {e}")
    
    def detect_regex(self, text: str) -> List[PIIMatch]:
        """Detect PII using regex patterns.
        
        Args:
            text: The text to scan
            
        Returns:
            List of PIIMatch objects
        """
        if not self.enabled:
            return []
        
        matches = []
        for pattern_name, compiled_pattern in self._patterns.items():
            for match in compiled_pattern.finditer(text):
                matches.append(PIIMatch(
                    pattern_name=pattern_name,
                    matched_text=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=1.0
                ))
        
        return matches
    
    async def detect_ollama(self, text: str) -> List[PIIMatch]:
        """Detect PII using Ollama model.
        
        Args:
            text: The text to scan
            
        Returns:
            List of PIIMatch objects
        """
        if not self.enabled or not self.use_ollama:
            return []
        
        prompt = f"""Analyze the following text for PII (Personally Identifiable Information).
Identify any email addresses, phone numbers, social security numbers, credit card numbers, or other sensitive information.

Text to analyze:
{text}

Respond with a JSON array of detected PII items. Each item should have:
- "type": the type of PII (e.g., "email", "phone", "ssn")
- "value": the actual matched text
- "confidence": confidence score between 0 and 1

If no PII is found, return an empty array [].

JSON response:"""
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                response.raise_for_status()
                result = response.json()
                
                # Parse the response
                response_text = result.get("response", "[]")
                try:
                    pii_items = json.loads(response_text)
                except json.JSONDecodeError:
                    # Try to extract JSON from the text
                    json_match = re.search(r'\[.*?\]', response_text, re.DOTALL)
                    if json_match:
                        pii_items = json.loads(json_match.group())
                    else:
                        pii_items = []
                
                matches = []
                for item in pii_items:
                    if isinstance(item, dict):
                        # Find position in original text
                        value = item.get("value", "")
                        if value and value in text:
                            start = text.index(value)
                            matches.append(PIIMatch(
                                pattern_name=item.get("type", "unknown"),
                                matched_text=value,
                                start_pos=start,
                                end_pos=start + len(value),
                                confidence=item.get("confidence", 0.8)
                            ))
                
                return matches
                
        except httpx.ConnectError:
            # Ollama not available
            return []
        except httpx.TimeoutException:
            # Request timed out
            return []
        except Exception as e:
            # Log error but don't fail
            print(f"Ollama PII detection error: {e}")
            return []
    
    def detect_ollama_sync(self, text: str) -> List[PIIMatch]:
        """Synchronous version of Ollama detection."""
        import asyncio
        try:
            return asyncio.run(self.detect_ollama(text))
        except Exception as e:
            print(f"Ollama sync detection error: {e}")
            return []
    
    def detect(self, text: str, use_ollama: Optional[bool] = None) -> List[PIIMatch]:
        """Detect PII using both regex and optionally Ollama.
        
        Args:
            text: The text to scan
            use_ollama: Override for whether to use Ollama
            
        Returns:
            List of PIIMatch objects
        """
        if not self.enabled:
            return []
        
        # Always use regex
        matches = self.detect_regex(text)
        
        # Optionally use Ollama
        should_use_ollama = use_ollama if use_ollama is not None else self.use_ollama
        if should_use_ollama:
            ollama_matches = self.detect_ollama_sync(text)
            # Merge matches, avoiding duplicates
            existing_texts = {m.matched_text for m in matches}
            for match in ollama_matches:
                if match.matched_text not in existing_texts:
                    matches.append(match)
        
        return matches
    
    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """Redact detected PII from text.
        
        Args:
            text: The original text
            replacement: String to replace PII with
            
        Returns:
            Text with PII redacted
        """
        matches = self.detect(text)
        if not matches:
            return text
        
        # Sort by position in reverse order to avoid offset issues
        matches.sort(key=lambda m: m.start_pos, reverse=True)
        
        result = text
        for match in matches:
            result = result[:match.start_pos] + replacement + result[match.end_pos:]
        
        return result
    
    def has_pii(self, text: str) -> bool:
        """Check if text contains any PII.
        
        Args:
            text: The text to check
            
        Returns:
            True if PII is detected, False otherwise
        """
        return len(self.detect(text)) > 0
    
    def get_stats(self, text: str) -> Dict[str, Any]:
        """Get statistics about PII in text.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with PII statistics
        """
        matches = self.detect(text)
        
        stats = {
            'total_matches': len(matches),
            'by_type': {},
            'has_pii': len(matches) > 0
        }
        
        for match in matches:
            ptype = match.pattern_name
            if ptype not in stats['by_type']:
                stats['by_type'][ptype] = 0
            stats['by_type'][ptype] += 1
        
        return stats


# Convenience functions for standalone usage
def detect_pii(text: str, patterns: Optional[List[str]] = None) -> List[PIIMatch]:
    """Quick PII detection with default settings."""
    detector = PIIDetector(patterns=patterns)
    return detector.detect(text)


def redact_pii(text: str, replacement: str = "[REDACTED]") -> str:
    """Quick PII redaction with default settings."""
    detector = PIIDetector()
    return detector.redact(text, replacement)


if __name__ == "__main__":
    # Test the detector
    test_text = """
    Contact John Doe at john.doe@example.com or call 555-123-4567.
    His SSN is 123-45-6789 and credit card is 4111-1111-1111-1111.
    """
    
    detector = PIIDetector()
    print("Testing PII Detector")
    print("=" * 50)
    print(f"\nOriginal text:\n{test_text}")
    
    matches = detector.detect(test_text)
    print(f"\nDetected {len(matches)} PII items:")
    for match in matches:
        print(f"  - {match.pattern_name}: '{match.matched_text}' at position {match.start_pos}-{match.end_pos}")
    
    redacted = detector.redact(test_text)
    print(f"\nRedacted text:\n{redacted}")
    
    stats = detector.get_stats(test_text)
    print(f"\nStats: {stats}")