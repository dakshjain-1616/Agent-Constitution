"""Unit tests for PII detector."""

import pytest
from agent_constitution.rules.pii_detector import PIIDetector, PIIMatch, detect_pii, redact_pii


class TestPIIDetectorRegex:
    """Tests for regex-based PII detection."""
    
    def test_detect_email(self):
        """Test email detection."""
        detector = PIIDetector()
        text = "Contact me at john.doe@example.com for details."
        matches = detector.detect_regex(text)
        
        assert len(matches) == 1
        assert matches[0].pattern_name == "email"
        assert matches[0].matched_text == "john.doe@example.com"
    
    def test_detect_multiple_emails(self):
        """Test detection of multiple emails."""
        detector = PIIDetector()
        text = "Emails: alice@test.com and bob@company.org"
        matches = detector.detect_regex(text)
        
        assert len(matches) == 2
        emails = [m.matched_text for m in matches]
        assert "alice@test.com" in emails
        assert "bob@company.org" in emails
    
    def test_detect_ssn(self):
        """Test SSN detection."""
        detector = PIIDetector()
        text = "SSN: 123-45-6789"
        matches = detector.detect_regex(text)
        
        ssn_matches = [m for m in matches if m.pattern_name == "ssn"]
        assert len(ssn_matches) == 1
        assert ssn_matches[0].matched_text == "123-45-6789"
    
    def test_detect_phone(self):
        """Test phone number detection."""
        detector = PIIDetector()
        text = "Call me at 555-123-4567"
        matches = detector.detect_regex(text)
        
        phone_matches = [m for m in matches if m.pattern_name == "phone"]
        assert len(phone_matches) == 1
    
    def test_detect_credit_card(self):
        """Test credit card detection."""
        detector = PIIDetector()
        text = "Card: 4111-1111-1111-1111"
        matches = detector.detect_regex(text)
        
        cc_matches = [m for m in matches if m.pattern_name == "credit_card"]
        assert len(cc_matches) == 1
    
    def test_no_pii_detected(self):
        """Test text without PII."""
        detector = PIIDetector()
        text = "This is a normal message with no personal information."
        matches = detector.detect_regex(text)
        
        assert len(matches) == 0
    
    def test_disabled_detector(self):
        """Test that disabled detector returns no matches."""
        detector = PIIDetector(enabled=False)
        text = "Email: test@example.com"
        matches = detector.detect(text)
        
        assert len(matches) == 0


class TestPIIRedaction:
    """Tests for PII redaction."""
    
    def test_redact_email(self):
        """Test email redaction."""
        detector = PIIDetector()
        text = "Contact me at john.doe@example.com please."
        redacted = detector.redact(text)
        
        assert "john.doe@example.com" not in redacted
        assert "[REDACTED]" in redacted
    
    def test_redact_multiple_pii(self):
        """Test redaction of multiple PII types."""
        detector = PIIDetector()
        text = "Email: test@example.com, Phone: 555-123-4567"
        redacted = detector.redact(text)
        
        assert "test@example.com" not in redacted
        assert "555-123-4567" not in redacted
        assert redacted.count("[REDACTED]") == 2
    
    def test_custom_replacement(self):
        """Test custom replacement string."""
        detector = PIIDetector()
        text = "Email: test@example.com"
        redacted = detector.redact(text, replacement="[EMAIL]")
        
        assert "[EMAIL]" in redacted
        assert "[REDACTED]" not in redacted


class TestPIIStats:
    """Tests for PII statistics."""
    
    def test_get_stats_with_pii(self):
        """Test stats with PII present."""
        detector = PIIDetector()
        text = "Email: test@example.com and test2@example.org"
        stats = detector.get_stats(text)
        
        assert stats["has_pii"] is True
        assert stats["total_matches"] == 2
        assert "email" in stats["by_type"]
        assert stats["by_type"]["email"] == 2
    
    def test_get_stats_no_pii(self):
        """Test stats with no PII."""
        detector = PIIDetector()
        text = "This is a normal message."
        stats = detector.get_stats(text)
        
        assert stats["has_pii"] is False
        assert stats["total_matches"] == 0


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_detect_pii_function(self):
        """Test detect_pii convenience function."""
        text = "Email: test@example.com"
        matches = detect_pii(text)
        
        assert len(matches) == 1
        assert matches[0].pattern_name == "email"
    
    def test_redact_pii_function(self):
        """Test redact_pii convenience function."""
        text = "Email: test@example.com"
        redacted = redact_pii(text)
        
        assert "test@example.com" not in redacted
        assert "[REDACTED]" in redacted


class TestPIIMatch:
    """Tests for PIIMatch dataclass."""
    
    def test_pii_match_creation(self):
        """Test creating a PIIMatch."""
        match = PIIMatch(
            pattern_name="email",
            matched_text="test@example.com",
            start_pos=10,
            end_pos=26,
            confidence=1.0
        )
        
        assert match.pattern_name == "email"
        assert match.matched_text == "test@example.com"
        assert match.start_pos == 10
        assert match.end_pos == 26
        assert match.confidence == 1.0


class TestMockOllama:
    """Tests for Ollama integration (mocked)."""
    
    def test_ollama_not_called_when_disabled(self):
        """Test that Ollama is not called when disabled."""
        detector = PIIDetector(use_ollama=False)
        text = "Email: test@example.com"
        # Should not raise any connection errors
        matches = detector.detect(text)
        assert len(matches) == 1  # Regex still works
    
    def test_ollama_url_configuration(self):
        """Test Ollama URL configuration."""
        detector = PIIDetector(
            use_ollama=True,
            ollama_url="http://custom:11434"
        )
        assert detector.ollama_url == "http://custom:11434"
        assert detector.ollama_model == "gemma3:4b"  # default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])