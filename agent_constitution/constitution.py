"""Constitution module - Pydantic models and YAML validation for agent policies."""

from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator


class Rule(BaseModel):
    """A single rule within a policy."""
    
    name: str = Field(..., description="Unique identifier for the rule")
    description: str = Field(default="", description="Human-readable description")
    condition: str = Field(..., description="AST-evaluable condition expression")
    action: str = Field(default="block", description="Action to take: block, allow, log, or notify")
    severity: str = Field(default="medium", description="Severity level: low, medium, high, critical")
    enabled: bool = Field(default=True, description="Whether the rule is active")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional rule metadata")
    
    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"block", "allow", "log", "notify"}
        if v.lower() not in allowed:
            raise ValueError(f"action must be one of {allowed}, got {v}")
        return v.lower()
    
    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got {v}")
        return v.lower()


class Policy(BaseModel):
    """A collection of rules grouped by category."""
    
    name: str = Field(..., description="Policy category name")
    description: str = Field(default="", description="Policy description")
    rules: List[Rule] = Field(default_factory=list, description="List of rules in this policy")
    enabled: bool = Field(default=True, description="Whether the policy is active")
    priority: int = Field(default=100, description="Priority order (lower = higher priority)")


class PIIConfig(BaseModel):
    """Configuration for PII detection."""
    
    enabled: bool = Field(default=True, description="Enable PII detection")
    patterns: List[str] = Field(
        default_factory=lambda: ["email", "ssn", "phone", "credit_card"],
        description="PII patterns to detect"
    )
    use_ollama: bool = Field(default=True, description="Use Ollama for advanced PII detection")
    ollama_model: str = Field(default="gemma3:4b", description="Ollama model for PII detection")
    ollama_url: str = Field(default="http://localhost:11434", description="Ollama API URL")
    sensitivity: str = Field(default="medium", description="Detection sensitivity: low, medium, high")
    
    @field_validator("sensitivity")
    @classmethod
    def validate_sensitivity(cls, v: str) -> str:
        allowed = {"low", "medium", "high"}
        if v.lower() not in allowed:
            raise ValueError(f"sensitivity must be one of {allowed}, got {v}")
        return v.lower()


class AuditConfig(BaseModel):
    """Configuration for audit logging."""
    
    enabled: bool = Field(default=True, description="Enable audit logging")
    log_path: str = Field(default="./audit_logs.jsonl", description="Path to audit log file")
    max_file_size_mb: int = Field(default=100, description="Max log file size before rotation")
    retention_days: int = Field(default=30, description="Number of days to retain logs")
    log_level: str = Field(default="info", description="Logging level")


class Constitution(BaseModel):
    """Root configuration model for agent constitution."""
    
    version: str = Field(default="1.0", description="Constitution version")
    name: str = Field(default="Agent Constitution", description="Constitution name")
    description: str = Field(default="", description="Constitution description")
    policies: List[Policy] = Field(default_factory=list, description="List of policies")
    pii_config: PIIConfig = Field(default_factory=PIIConfig, description="PII detection configuration")
    audit_config: AuditConfig = Field(default_factory=AuditConfig, description="Audit logging configuration")
    global_settings: Dict[str, Any] = Field(default_factory=dict, description="Global configuration settings")
    
    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> Constitution:
        """Load constitution from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Constitution file not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        if data is None:
            raise ValueError(f"YAML file is empty or invalid: {path}")
        
        return cls.model_validate(data)
    
    def to_yaml(self, path: Union[str, Path]) -> None:
        """Save constitution to a YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)
    
    def get_enabled_rules(self) -> List[Rule]:
        """Get all enabled rules from all enabled policies, sorted by priority."""
        enabled_policies = [p for p in self.policies if p.enabled]
        enabled_policies.sort(key=lambda p: p.priority)
        
        rules = []
        for policy in enabled_policies:
            rules.extend([r for r in policy.rules if r.enabled])
        return rules
    
    def get_rule_by_name(self, name: str) -> Optional[Rule]:
        """Find a rule by its name across all policies."""
        for policy in self.policies:
            for rule in policy.rules:
                if rule.name == name:
                    return rule
        return None
    
    def validate_conditions(self) -> List[str]:
        """Validate all rule conditions are parseable AST expressions.
        
        Returns list of error messages for invalid conditions.
        """
        from agent_constitution.rules.evaluator import validate_expression
        
        errors = []
        for policy in self.policies:
            for rule in policy.rules:
                if not rule.enabled:
                    continue
                is_valid, error = validate_expression(rule.condition)
                if not is_valid:
                    errors.append(f"Policy '{policy.name}', Rule '{rule.name}': {error}")
        return errors


def create_sample_constitution() -> Constitution:
    """Create a sample constitution with example policies."""
    return Constitution(
        version="1.0",
        name="Sample Agent Constitution",
        description="Example constitution with common security policies",
        policies=[
            Policy(
                name="tool_restrictions",
                description="Restrict access to dangerous tools",
                priority=10,
                rules=[
                    Rule(
                        name="block_file_deletion",
                        description="Prevent file system deletion operations",
                        condition="tool_name in ['rm', 'unlink', 'rmdir']",
                        action="block",
                        severity="critical"
                    ),
                    Rule(
                        name="restrict_network_access",
                        description="Limit unrestricted network access",
                        condition="tool_name == 'curl' and not context.get('approved', False)",
                        action="notify",
                        severity="high"
                    )
                ]
            ),
            Policy(
                name="data_protection",
                description="Protect sensitive data",
                priority=5,
                rules=[
                    Rule(
                        name="pii_detection",
                        description="Detect and protect PII in outputs",
                        condition="pii_detected == True",
                        action="block",
                        severity="high"
                    )
                ]
            )
        ],
        pii_config=PIIConfig(
            enabled=True,
            patterns=["email", "ssn", "phone"],
            use_ollama=True,
            ollama_model="gemma3:4b"
        ),
        audit_config=AuditConfig(
            enabled=True,
            log_path="./audit_logs.jsonl"
        )
    )


if __name__ == "__main__":
    import sys
    
    # Create and save a sample constitution
    sample = create_sample_constitution()
    sample_path = Path("sample_constitution.yaml")
    sample.to_yaml(sample_path)
    print(f"Created sample constitution: {sample_path.absolute()}")
    
    # Load and validate
    loaded = Constitution.from_yaml(sample_path)
    print(f"Loaded constitution: {loaded.name}")
    print(f"Policies: {len(loaded.policies)}")
    print(f"Total rules: {sum(len(p.rules) for p in loaded.policies)}")
    
    # Validate conditions
    errors = loaded.validate_conditions()
    if errors:
        print("\nValidation errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("\nAll conditions are valid!")
    
    # Print enabled rules
    print("\nEnabled rules:")
    for rule in loaded.get_enabled_rules():
        print(f"  - {rule.name}: {rule.action} (severity: {rule.severity})")