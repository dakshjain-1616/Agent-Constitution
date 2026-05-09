"""Enforcer module - Policy enforcement with decorator and violation tracking."""

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime

from agent_constitution.constitution import Constitution, Rule
from agent_constitution.rules.evaluator import evaluate_expression, EvaluatorError
from agent_constitution.rules.pii_detector import PIIDetector


@dataclass
class Violation:
    """Represents a policy violation."""
    rule_name: str
    rule_description: str
    severity: str
    action: str
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "rule_name": self.rule_name,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "action": self.action,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message
        }


@dataclass
class EnforcementResult:
    """Result of policy enforcement check."""
    allowed: bool
    violations: List[Violation] = field(default_factory=list)
    action_taken: str = "allow"
    context: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def blocked(self) -> bool:
        """Check if the action was blocked."""
        return not self.allowed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "allowed": self.allowed,
            "blocked": self.blocked,
            "violations": [v.to_dict() for v in self.violations],
            "action_taken": self.action_taken,
            "context": self.context
        }


class Enforcer:
    """Main enforcer class for policy compliance."""
    
    def __init__(
        self,
        constitution: Optional[Constitution] = None,
        constitution_path: Optional[str] = None,
        pii_detector: Optional[PIIDetector] = None
    ):
        """Initialize the enforcer.
        
        Args:
            constitution: Constitution object with policies
            constitution_path: Path to YAML constitution file
            pii_detector: Optional PII detector instance
        """
        if constitution:
            self.constitution = constitution
        elif constitution_path:
            self.constitution = Constitution.from_yaml(constitution_path)
        else:
            # Create default empty constitution
            self.constitution = Constitution()
        
        # Initialize PII detector from config or create default
        if pii_detector:
            self.pii_detector = pii_detector
        elif self.constitution.pii_config.enabled:
            self.pii_detector = PIIDetector(
                enabled=self.constitution.pii_config.enabled,
                patterns=self.constitution.pii_config.patterns,
                use_ollama=self.constitution.pii_config.use_ollama,
                ollama_model=self.constitution.pii_config.ollama_model,
                ollama_url=self.constitution.pii_config.ollama_url,
                sensitivity=self.constitution.pii_config.sensitivity
            )
        else:
            self.pii_detector = PIIDetector(enabled=False)
        
        self._violation_history: List[Violation] = []
    
    def check(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        tool_output: Optional[str] = None,
        extra_context: Optional[Dict[str, Any]] = None
    ) -> EnforcementResult:
        """Check if a tool call complies with policies.
        
        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            tool_output: Output from the tool (for post-call checks)
            extra_context: Additional context variables
            
        Returns:
            EnforcementResult with violations and action taken
        """
        # Build evaluation context
        context = {
            "tool_name": tool_name,
            "args": tool_args or {},
            "output": tool_output or "",
            "context": extra_context or {}
        }
        
        # Check for PII in output
        if tool_output and self.pii_detector.enabled:
            pii_matches = self.pii_detector.detect(tool_output)
            context["pii_detected"] = len(pii_matches) > 0
            context["pii_matches"] = [
                {
                    "type": m.pattern_name,
                    "text": m.matched_text,
                    "confidence": m.confidence
                }
                for m in pii_matches
            ]
        else:
            context["pii_detected"] = False
            context["pii_matches"] = []
        
        # Evaluate all enabled rules
        violations = []
        should_block = False
        highest_severity = "low"
        
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        
        for rule in self.constitution.get_enabled_rules():
            try:
                rule_triggered = evaluate_expression(rule.condition, context)
            except EvaluatorError as e:
                # Log evaluation error but don't block
                print(f"Warning: Rule '{rule.name}' evaluation failed: {e}")
                continue
            
            if rule_triggered:
                violation = Violation(
                    rule_name=rule.name,
                    rule_description=rule.description,
                    severity=rule.severity,
                    action=rule.action,
                    context=context,
                    message=f"Rule '{rule.name}' triggered: {rule.description}"
                )
                violations.append(violation)
                self._violation_history.append(violation)
                
                # Determine if we should block
                if rule.action == "block":
                    should_block = True
                
                # Track highest severity
                if severity_order.get(rule.severity, 0) > severity_order.get(highest_severity, 0):
                    highest_severity = rule.severity
        
        # Determine final action
        if should_block:
            action_taken = "block"
            allowed = False
        elif violations:
            # Check if any violations require notification
            notify_violations = [v for v in violations if v.action == "notify"]
            if notify_violations:
                action_taken = "notify"
            else:
                action_taken = "log"
            allowed = True
        else:
            action_taken = "allow"
            allowed = True
        
        return EnforcementResult(
            allowed=allowed,
            violations=violations,
            action_taken=action_taken,
            context=context
        )
    
    def enforce(self, func: Callable = None, *, tool_name: Optional[str] = None):
        """Decorator to enforce policies on a function.
        
        Args:
            func: The function to wrap
            tool_name: Optional tool name override (defaults to function name)
            
        Returns:
            Decorated function that checks policies before execution
        """
        def decorator(f: Callable) -> Callable:
            nonlocal tool_name
            if tool_name is None:
                tool_name = f.__name__
            
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                # Build tool arguments from function signature
                sig = inspect.signature(f)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                
                # Check policies
                result = self.check(
                    tool_name=tool_name,
                    tool_args=dict(bound.arguments)
                )
                
                if result.blocked:
                    # Raise exception or return error
                    error_msg = f"Tool '{tool_name}' blocked by policy"
                    if result.violations:
                        error_msg += f": {result.violations[0].message}"
                    raise PolicyViolationError(error_msg, result)
                
                # Execute the function
                output = f(*args, **kwargs)
                
                # Post-execution check (for PII in output)
                if isinstance(output, str):
                    post_result = self.check(
                        tool_name=tool_name,
                        tool_args=dict(bound.arguments),
                        tool_output=output
                    )
                    
                    if post_result.blocked:
                        error_msg = f"Tool '{tool_name}' output blocked by policy"
                        raise PolicyViolationError(error_msg, post_result)
                
                return output
            
            # Attach enforcer reference for inspection
            wrapper._enforcer = self
            wrapper._tool_name = tool_name
            
            return wrapper
        
        if func is None:
            # Called with arguments: @enforce(tool_name="...")
            return decorator
        else:
            # Called without arguments: @enforce
            return decorator(func)
    
    def get_violations(self, since: Optional[datetime] = None) -> List[Violation]:
        """Get violation history.
        
        Args:
            since: Only return violations after this timestamp
            
        Returns:
            List of violations
        """
        if since:
            return [v for v in self._violation_history if v.timestamp >= since]
        return self._violation_history.copy()
    
    def clear_violations(self) -> None:
        """Clear violation history."""
        self._violation_history.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enforcement statistics."""
        stats = {
            "total_violations": len(self._violation_history),
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_action": {"block": 0, "allow": 0, "log": 0, "notify": 0}
        }
        
        for violation in self._violation_history:
            stats["by_severity"][violation.severity] += 1
            stats["by_action"][violation.action] += 1
        
        return stats


class PolicyViolationError(Exception):
    """Exception raised when a policy violation blocks execution."""
    
    def __init__(self, message: str, result: EnforcementResult):
        super().__init__(message)
        self.result = result
        self.violations = result.violations


# Convenience functions
def create_enforcer(
    constitution_path: Optional[str] = None,
    **constitution_kwargs
) -> Enforcer:
    """Create an enforcer from a constitution file or kwargs."""
    if constitution_path:
        return Enforcer(constitution_path=constitution_path)
    
    constitution = Constitution(**constitution_kwargs)
    return Enforcer(constitution=constitution)


if __name__ == "__main__":
    # Demo
    from agent_constitution.constitution import create_sample_constitution
    
    print("Enforcer Demo")
    print("=" * 50)
    
    # Create enforcer with sample constitution
    constitution = create_sample_constitution()
    enforcer = Enforcer(constitution=constitution)
    
    # Test 1: Blocked tool
    print("\n1. Testing blocked tool (rm):")
    result = enforcer.check(tool_name="rm", tool_args={"path": "/tmp/test"})
    print(f"   Allowed: {result.allowed}")
    print(f"   Action: {result.action_taken}")
    print(f"   Violations: {len(result.violations)}")
    for v in result.violations:
        print(f"     - {v.rule_name}: {v.message}")
    
    # Test 2: Allowed tool
    print("\n2. Testing allowed tool (ls):")
    result = enforcer.check(tool_name="ls", tool_args={"path": "/tmp"})
    print(f"   Allowed: {result.allowed}")
    print(f"   Action: {result.action_taken}")
    print(f"   Violations: {len(result.violations)}")
    
    # Test 3: PII detection
    print("\n3. Testing PII detection:")
    result = enforcer.check(
        tool_name="echo",
        tool_output="Contact me at john@example.com"
    )
    print(f"   Allowed: {result.allowed}")
    print(f"   PII detected: {result.context.get('pii_detected')}")
    print(f"   PII matches: {result.context.get('pii_matches')}")
    
    # Test 4: Using decorator
    print("\n4. Testing @enforce decorator:")
    
    @enforcer.enforce
    def dangerous_delete(path: str):
        return f"Would delete: {path}"
    
    try:
        dangerous_delete("/tmp/test")
    except PolicyViolationError as e:
        print(f"   Blocked as expected: {e}")
    
    print("\n5. Violation stats:")
    print(f"   {enforcer.get_stats()}")