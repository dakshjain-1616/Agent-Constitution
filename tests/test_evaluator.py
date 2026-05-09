"""Unit tests for the AST-based expression evaluator."""

import pytest
from agent_constitution.rules.evaluator import (
    evaluate_expression,
    validate_expression,
    EvaluatorError,
    UnsafeExpressionError
)


class TestValidateExpression:
    """Tests for expression validation."""
    
    def test_valid_simple_comparison(self):
        """Test simple comparison expressions."""
        is_valid, error = validate_expression("x > 5")
        assert is_valid is True
        assert error == ""
    
    def test_valid_equality_check(self):
        """Test equality expressions."""
        is_valid, error = validate_expression("name == 'test'")
        assert is_valid is True
        assert error == ""
    
    def test_valid_in_operator(self):
        """Test 'in' operator."""
        is_valid, error = validate_expression("tool_name in ['rm', 'del']")
        assert is_valid is True
        assert error == ""
    
    def test_valid_logical_and(self):
        """Test logical AND."""
        is_valid, error = validate_expression("x > 0 and y < 10")
        assert is_valid is True
        assert error == ""
    
    def test_valid_logical_or(self):
        """Test logical OR."""
        is_valid, error = validate_expression("x == 1 or x == 2")
        assert is_valid is True
        assert error == ""
    
    def test_valid_method_call(self):
        """Test method calls on allowed objects."""
        is_valid, error = validate_expression("context.get('key', False)")
        assert is_valid is True
        assert error == ""
    
    def test_valid_builtin_call(self):
        """Test allowed built-in function calls."""
        is_valid, error = validate_expression("len(items) > 0")
        assert is_valid is True
        assert error == ""
    
    def test_invalid_syntax(self):
        """Test invalid syntax is rejected."""
        is_valid, error = validate_expression("x > > 5")
        assert is_valid is False
        assert "Syntax error" in error
    
    def test_dangerous_eval_call(self):
        """Test eval() calls are blocked."""
        is_valid, error = validate_expression("eval('1+1')")
        assert is_valid is False
        assert "Dangerous function call" in error
    
    def test_dangerous_exec_call(self):
        """Test exec() calls are blocked."""
        is_valid, error = validate_expression("exec('pass')")
        assert is_valid is False
        assert "Dangerous function call" in error
    
    def test_dangerous_import_call(self):
        """Test __import__() calls are blocked."""
        is_valid, error = validate_expression("__import__('os')")
        assert is_valid is False
        assert "Dangerous function call" in error


class TestEvaluateExpression:
    """Tests for expression evaluation."""
    
    def test_simple_comparison_true(self):
        """Test simple comparison that evaluates to True."""
        result = evaluate_expression("x > 5", {"x": 10})
        assert result is True
    
    def test_simple_comparison_false(self):
        """Test simple comparison that evaluates to False."""
        result = evaluate_expression("x > 5", {"x": 3})
        assert result is False
    
    def test_equality_check(self):
        """Test equality comparison."""
        result = evaluate_expression("name == 'test'", {"name": "test"})
        assert result is True
        
        result = evaluate_expression("name == 'test'", {"name": "other"})
        assert result is False
    
    def test_in_operator_list(self):
        """Test 'in' operator with list."""
        result = evaluate_expression(
            "tool_name in ['rm', 'unlink', 'rmdir']",
            {"tool_name": "rm"}
        )
        assert result is True
        
        result = evaluate_expression(
            "tool_name in ['rm', 'unlink', 'rmdir']",
            {"tool_name": "safe_tool"}
        )
        assert result is False
    
    def test_in_operator_string(self):
        """Test 'in' operator with string."""
        result = evaluate_expression(
            "'@' in email",
            {"email": "test@example.com"}
        )
        assert result is True
    
    def test_logical_and(self):
        """Test logical AND."""
        result = evaluate_expression(
            "x > 0 and y < 10",
            {"x": 5, "y": 5}
        )
        assert result is True
        
        result = evaluate_expression(
            "x > 0 and y < 10",
            {"x": -1, "y": 5}
        )
        assert result is False
    
    def test_logical_or(self):
        """Test logical OR."""
        result = evaluate_expression(
            "x == 1 or x == 2",
            {"x": 1}
        )
        assert result is True
        
        result = evaluate_expression(
            "x == 1 or x == 2",
            {"x": 3}
        )
        assert result is False
    
    def test_not_operator(self):
        """Test NOT operator."""
        result = evaluate_expression("not x", {"x": False})
        assert result is True
        
        result = evaluate_expression("not x", {"x": True})
        assert result is False
    
    def test_method_call(self):
        """Test method calls."""
        context = {"approved": True, "level": "high"}
        result = evaluate_expression(
            "context.get('approved', False)",
            {"context": context}
        )
        assert result is True
    
    def test_builtin_len(self):
        """Test len() built-in."""
        result = evaluate_expression("len(items) > 0", {"items": [1, 2, 3]})
        assert result is True
        
        result = evaluate_expression("len(items) > 0", {"items": []})
        assert result is False
    
    def test_builtin_any(self):
        """Test any() built-in."""
        result = evaluate_expression("any(items)", {"items": [False, True, False]})
        assert result is True
        
        result = evaluate_expression("any(items)", {"items": [False, False]})
        assert result is False
    
    def test_builtin_all(self):
        """Test all() built-in."""
        result = evaluate_expression("all(items)", {"items": [True, True, True]})
        assert result is True
        
        result = evaluate_expression("all(items)", {"items": [True, False, True]})
        assert result is False
    
    def test_arithmetic_operations(self):
        """Test arithmetic in expressions."""
        result = evaluate_expression("x + y > 10", {"x": 5, "y": 6})
        assert result is True
        
        result = evaluate_expression("x * 2 == 10", {"x": 5})
        assert result is True
    
    def test_string_operations(self):
        """Test string operations."""
        result = evaluate_expression("len(name) > 3", {"name": "hello"})
        assert result is True
        
        result = evaluate_expression("name.startswith('te')", {"name": "test"})
        assert result is True
    
    def test_undefined_variable(self):
        """Test undefined variable raises error."""
        with pytest.raises(EvaluatorError) as exc_info:
            evaluate_expression("x > 5", {})
        assert "Name 'x' is not defined" in str(exc_info.value)
    
    def test_dangerous_eval_blocked(self):
        """Test eval() is blocked during evaluation."""
        with pytest.raises(EvaluatorError) as exc_info:
            evaluate_expression("eval('1+1')", {})
        assert "Invalid expression" in str(exc_info.value)


class TestComplexConditions:
    """Tests for complex real-world conditions."""
    
    def test_tool_restriction_condition(self):
        """Test typical tool restriction condition."""
        result = evaluate_expression(
            "tool_name in ['rm', 'unlink', 'rmdir']",
            {"tool_name": "rm"}
        )
        assert result is True
        
        result = evaluate_expression(
            "tool_name in ['rm', 'unlink', 'rmdir']",
            {"tool_name": "ls"}
        )
        assert result is False
    
    def test_network_access_condition(self):
        """Test network access restriction condition."""
        result = evaluate_expression(
            "tool_name == 'curl' and not context.get('approved', False)",
            {"tool_name": "curl", "context": {"approved": False}}
        )
        assert result is True
        
        result = evaluate_expression(
            "tool_name == 'curl' and not context.get('approved', False)",
            {"tool_name": "curl", "context": {"approved": True}}
        )
        assert result is False
    
    def test_pii_detection_condition(self):
        """Test PII detection condition."""
        result = evaluate_expression(
            "pii_detected == True",
            {"pii_detected": True}
        )
        assert result is True
    
    def test_severity_check(self):
        """Test severity level check."""
        result = evaluate_expression(
            "severity in ['high', 'critical']",
            {"severity": "high"}
        )
        assert result is True
        
        result = evaluate_expression(
            "severity in ['high', 'critical']",
            {"severity": "low"}
        )
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])