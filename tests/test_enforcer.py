"""Unit tests for the policy enforcer."""

import pytest
from agent_constitution.enforcer import Enforcer, Violation, EnforcementResult, PolicyViolationError
from agent_constitution.constitution import Constitution, Rule, Policy, create_sample_constitution


class TestEnforcerBasic:
    """Basic enforcer tests."""
    
    def test_enforcer_creation(self):
        """Test creating an enforcer."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        assert enforcer is not None
        assert enforcer.constitution is not None
    
    def test_enforcer_from_path(self):
        """Test creating enforcer from YAML path."""
        enforcer = Enforcer(constitution_path="sample_constitution.yaml")
        assert enforcer is not None
    
    def test_check_blocked_tool(self):
        """Test that blocked tools are detected."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        result = enforcer.check(tool_name="rm", tool_args={"path": "/tmp/test"})
        
        assert result.blocked is True
        assert result.allowed is False
        assert len(result.violations) > 0
        assert result.violations[0].rule_name == "block_file_deletion"
    
    def test_check_allowed_tool(self):
        """Test that allowed tools pass."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        result = enforcer.check(tool_name="ls", tool_args={"path": "/tmp"})
        
        assert result.allowed is True
        assert result.blocked is False
        assert len(result.violations) == 0
    
    def test_check_notify_action(self):
        """Test that notify actions don't block."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        # curl without approval should trigger notify
        result = enforcer.check(
            tool_name="curl",
            tool_args={"url": "http://example.com"},
            extra_context={"approved": False}
        )
        
        # Should be allowed but with a violation
        assert result.allowed is True
        assert len(result.violations) > 0
        assert any(v.action == "notify" for v in result.violations)


class TestEnforcerDecorator:
    """Tests for the @enforce decorator."""
    
    def test_decorator_blocks_forbidden_tool(self):
        """Test that decorator blocks forbidden tools."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        @enforcer.enforce(tool_name="rm")
        def dangerous_delete(path: str):
            return f"Deleted {path}"
        
        with pytest.raises(PolicyViolationError) as exc_info:
            dangerous_delete("/tmp/test")
        
        assert "blocked" in str(exc_info.value).lower()
        assert exc_info.value.result.blocked is True
    
    def test_decorator_allows_safe_tool(self):
        """Test that decorator allows safe tools."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        @enforcer.enforce
        def safe_list(path: str = "/"):
            return f"Listing {path}"
        
        result = safe_list("/tmp")
        assert result == "Listing /tmp"
    
    def test_decorator_with_custom_tool_name(self):
        """Test decorator with custom tool name."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        @enforcer.enforce(tool_name="rm")
        def my_function(path: str):
            return f"Done with {path}"
        
        with pytest.raises(PolicyViolationError):
            my_function("/tmp/test")


class TestEnforcerPII:
    """Tests for PII detection in enforcer."""
    
    def test_pii_detection_in_output(self):
        """Test PII detection in tool output."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        result = enforcer.check(
            tool_name="echo",
            tool_output="Contact me at test@example.com"
        )
        
        assert result.context["pii_detected"] is True
        assert len(result.context["pii_matches"]) > 0
    
    def test_no_pii_in_output(self):
        """Test when no PII is present."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        result = enforcer.check(
            tool_name="echo",
            tool_output="This is a normal message."
        )
        
        assert result.context["pii_detected"] is False
        assert len(result.context["pii_matches"]) == 0


class TestEnforcerStats:
    """Tests for enforcer statistics."""
    
    def test_violation_tracking(self):
        """Test that violations are tracked."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        # Trigger some violations
        enforcer.check(tool_name="rm", tool_args={"path": "/tmp"})
        enforcer.check(tool_name="unlink", tool_args={"path": "/tmp"})
        
        violations = enforcer.get_violations()
        assert len(violations) == 2
    
    def test_stats(self):
        """Test statistics collection."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        # Trigger violations
        enforcer.check(tool_name="rm", tool_args={"path": "/tmp"})
        
        stats = enforcer.get_stats()
        assert stats["total_violations"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_action"]["block"] == 1
    
    def test_clear_violations(self):
        """Test clearing violation history."""
        constitution = create_sample_constitution()
        enforcer = Enforcer(constitution=constitution)
        
        enforcer.check(tool_name="rm", tool_args={"path": "/tmp"})
        assert len(enforcer.get_violations()) == 1
        
        enforcer.clear_violations()
        assert len(enforcer.get_violations()) == 0


class TestViolation:
    """Tests for Violation dataclass."""
    
    def test_violation_creation(self):
        """Test creating a violation."""
        v = Violation(
            rule_name="test_rule",
            rule_description="Test rule",
            severity="high",
            action="block"
        )
        
        assert v.rule_name == "test_rule"
        assert v.severity == "high"
        assert v.action == "block"
    
    def test_violation_to_dict(self):
        """Test violation serialization."""
        v = Violation(
            rule_name="test_rule",
            rule_description="Test rule",
            severity="high",
            action="block"
        )
        
        d = v.to_dict()
        assert d["rule_name"] == "test_rule"
        assert d["severity"] == "high"
        assert "timestamp" in d


class TestEnforcementResult:
    """Tests for EnforcementResult."""
    
    def test_result_allowed(self):
        """Test allowed result."""
        result = EnforcementResult(allowed=True)
        assert result.allowed is True
        assert result.blocked is False
    
    def test_result_blocked(self):
        """Test blocked result."""
        result = EnforcementResult(allowed=False)
        assert result.allowed is False
        assert result.blocked is True
    
    def test_result_with_violations(self):
        """Test result with violations."""
        v = Violation(
            rule_name="test",
            rule_description="Test",
            severity="medium",
            action="block"
        )
        result = EnforcementResult(
            allowed=False,
            violations=[v],
            action_taken="block"
        )
        
        assert len(result.violations) == 1
        assert result.action_taken == "block"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])