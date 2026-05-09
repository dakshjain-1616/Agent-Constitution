#!/usr/bin/env python3
"""
Agent Constitution Demo Script

This script demonstrates the key features of the agent-constitution library:
1. Loading a constitution from YAML
2. Policy enforcement with the @enforce decorator
3. PII detection and redaction
4. Audit logging
5. Manual policy checking

Run with: python example/demo.py
"""

import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_constitution import Constitution, Enforcer
from agent_constitution.rules.pii_detector import PIIDetector
from agent_constitution.audit import AuditLogger
from agent_constitution.enforcer import PolicyViolationError


def create_sample_constitution():
    """Create a sample constitution file for the demo."""
    constitution_yaml = """
version: "1.0"
name: "Demo Agent Constitution"
description: "Demonstration policies for agent-constitution"

policies:
  - name: security
    description: "Security-related policies"
    priority: 10
    rules:
      - name: block_file_deletion
        description: "Prevent file deletion operations"
        condition: "tool_name in ['rm', 'unlink', 'rmdir', 'delete']"
        action: block
        severity: critical

      - name: restrict_network_access
        description: "Limit unrestricted network access"
        condition: "tool_name == 'curl' and not context.get('approved', False)"
        action: block
        severity: high

      - name: block_shell_execution
        description: "Prevent shell command execution"
        condition: "tool_name in ['bash', 'sh', 'exec', 'system']"
        action: block
        severity: critical

  - name: data_protection
    description: "Data protection policies"
    priority: 5
    rules:
      - name: pii_detection
        description: "Detect PII in tool arguments"
        condition: "pii_detected == True"
        action: block
        severity: high

pii_config:
  enabled: true
  patterns: ["email", "ssn", "phone"]
  use_ollama: false

audit_config:
  enabled: true
  log_path: "./demo_audit.jsonl"
"""
    
    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(constitution_yaml)
        return f.name


def demo_constitution_loading():
    """Demo: Loading a constitution from YAML."""
    print("=" * 60)
    print("DEMO 1: Constitution Loading")
    print("=" * 60)
    
    # Create sample constitution
    constitution_path = create_sample_constitution()
    
    # Load constitution
    constitution = Constitution.from_yaml(constitution_path)
    
    print(f"\n✓ Loaded constitution: {constitution.name}")
    print(f"  Version: {constitution.version}")
    print(f"  Description: {constitution.description}")
    print(f"  Policies: {len(constitution.policies)}")
    
    for policy in constitution.policies:
        print(f"\n  Policy: {policy.name}")
        print(f"    Priority: {policy.priority}")
        print(f"    Rules: {len(policy.rules)}")
        for rule in policy.rules:
            print(f"      - {rule.name}: {rule.description}")
    
    # Cleanup
    os.unlink(constitution_path)
    print()
    return constitution


def demo_pii_detection():
    """Demo: PII detection and redaction."""
    print("=" * 60)
    print("DEMO 2: PII Detection")
    print("=" * 60)
    
    detector = PIIDetector()
    
    # Sample text with PII
    text = """
    Contact Information:
    - Email: john.doe@example.com
    - Phone: (555) 123-4567
    - SSN: 123-45-6789
    - Credit Card: 4532-1234-5678-9012
    
    Please reach out to jane.smith@company.org or call 800-555-0199
    """
    
    print("\nOriginal text:")
    print(text)
    
    # Detect PII
    matches = detector.detect(text)
    
    print(f"\n✓ Found {len(matches)} PII matches:")
    for match in matches:
        print(f"  [{match.pattern_name}] {match.matched_text}")
    
    # Redact PII
    redacted = detector.redact(text)
    print("\nRedacted text:")
    print(redacted)
    print()


def demo_enforcer_decorator(constitution):
    """Demo: Using the @enforce decorator."""
    print("=" * 60)
    print("DEMO 3: @enforce Decorator")
    print("=" * 60)

    enforcer = Enforcer(constitution=constitution)

    # Define a function with the decorator
    @enforcer.enforce(tool_name="rm")
    def delete_file(path: str):
        """Delete a file."""
        print(f"  [Would delete: {path}]")
        return True

    @enforcer.enforce(tool_name="curl")
    def fetch_url(url: str):
        """Fetch a URL."""
        print(f"  [Would fetch: {url}]")
        return True

    @enforcer.enforce(tool_name="echo")
    def echo_message(message: str):
        """Echo a message."""
        print(f"  [Echo: {message}]")
        return True

    # Test blocked operation (file deletion)
    print("\n1. Testing blocked operation (rm):")
    try:
        delete_file("/tmp/test.txt")
        print("  ✗ Should have been blocked!")
    except PolicyViolationError as e:
        print(f"  ✓ Blocked: {e}")

    # Test blocked operation (unapproved curl)
    print("\n2. Testing blocked operation (curl without approval):")
    try:
        fetch_url("https://example.com")
        print("  ✗ Should have been blocked!")
    except PolicyViolationError as e:
        print(f"  ✓ Blocked: {e}")

    # Test allowed operation (approved curl via manual check with extra_context)
    print("\n3. Testing allowed operation (curl with approval via context):")
    result = enforcer.check(
        tool_name="curl",
        tool_args={"url": "https://example.com"},
        extra_context={"approved": True}
    )
    if result.allowed:
        print(f"  ✓ Allowed via context")
    else:
        print(f"  ✗ Should have been allowed: {result.violations}")

    # Test allowed operation (not restricted)
    print("\n4. Testing allowed operation (echo - not restricted):")
    try:
        result = echo_message("Hello, World!")
        print(f"  ✓ Allowed (result: {result})")
    except PolicyViolationError as e:
        print(f"  ✗ Should have been allowed: {e}")

    print()


def demo_manual_policy_checking(constitution):
    """Demo: Manual policy checking."""
    print("=" * 60)
    print("DEMO 4: Manual Policy Checking")
    print("=" * 60)
    
    enforcer = Enforcer(constitution=constitution)
    
    # Check various tool calls
    test_cases = [
        ("rm", {"path": "/tmp/test.txt"}, {}),
        ("curl", {"url": "https://example.com"}, {"approved": False}),
        ("curl", {"url": "https://example.com"}, {"approved": True}),
        ("bash", {"command": "ls -la"}, {}),
        ("echo", {"message": "Hello"}, {}),
    ]
    
    print("\nChecking tool calls:")
    for tool_name, tool_args, context in test_cases:
        result = enforcer.check(
            tool_name=tool_name,
            tool_args=tool_args,
            extra_context=context
        )
        
        status = "✓ ALLOWED" if result.allowed else "✗ BLOCKED"
        print(f"  {status}: {tool_name}({tool_args})")
        
        if result.violations:
            for v in result.violations:
                print(f"      -> Violation: {v.rule_name} ({v.severity})")
    
    print()


def demo_audit_logging(constitution):
    """Demo: Audit logging."""
    print("=" * 60)
    print("DEMO 5: Audit Logging")
    print("=" * 60)
    
    # Create audit logger
    audit_path = "./demo_audit.jsonl"
    logger = AuditLogger(log_path=audit_path)
    
    # Clear any existing logs
    logger.clear()
    # Create enforcer
    enforcer = Enforcer(constitution=constitution)
    
    @enforcer.enforce(tool_name="rm")
    def delete_file(path: str):
        return True
    
    @enforcer.enforce(tool_name="curl")
    def fetch_url(url: str, approved: bool = False):
        return True
    
    # Generate some audit events
    print("\nGenerating audit events...")
    
    # Blocked operations
    for _ in range(3):
        try:
            delete_file("/tmp/test.txt")
        except PolicyViolationError:
            pass
    
    try:
        fetch_url("https://example.com")
    except PolicyViolationError:
        pass
    
    # Allowed
    try:
        fetch_url("https://example.com", approved=True)
    except PolicyViolationError:
        pass
    
    # Manually log events
    logger.log(
        event_type="tool_call",
        tool_name="rm",
        action="block",
        allowed=False,
        violations=[{"rule_name": "block_file_deletion"}]
    )
    logger.log(
        event_type="tool_call",
        tool_name="curl",
        action="block",
        allowed=False,
        violations=[{"rule_name": "restrict_network_access"}]
    )
    logger.log(
        event_type="tool_call",
        tool_name="curl",
        action="allow",
        allowed=True,
        violations=[]
    )
    
    # Read and display audit logs
    print("\nAudit log entries:")
    entries = logger.read_logs()
    for entry in entries:
        status = "✓" if entry.allowed else "✗"
        print(f"  [{status}] {entry.timestamp}: {entry.tool_name} -> {entry.action}")
        if entry.violations:
            print(f"      Violations: {', '.join(v.get('rule_name', 'unknown') for v in entry.violations)}")
    
    # Show stats
    stats = logger.get_stats()
    print(f"\nAudit stats:")
    print(f"  Total entries: {stats['entries_written']}")
    print(f"  Bytes written: {stats['bytes_written']}")
    print(f"  Current log size: {stats['current_log_size']} bytes")
    print(f"  Total log files: {stats['total_log_files']}")
    
    # Cleanup
    os.unlink(audit_path)
    print()


def demo_statistics(constitution):
    """Demo: Enforcement statistics."""
    print("=" * 60)
    print("DEMO 6: Enforcement Statistics")
    print("=" * 60)

    enforcer = Enforcer(constitution=constitution)

    @enforcer.enforce(tool_name="rm")
    def delete_file(path: str):
        return True

    @enforcer.enforce(tool_name="curl")
    def fetch_url(url: str):
        return True

    @enforcer.enforce(tool_name="bash")
    def run_shell(command: str):
        return True

    # Generate some events
    print("\nGenerating enforcement events...")

    # Blocked
    for _ in range(3):
        try:
            delete_file("/tmp/test.txt")
        except PolicyViolationError:
            pass

    try:
        run_shell("ls -la")
    except PolicyViolationError:
        pass

    # Allowed (using check with extra_context for approved)
    enforcer.check(
        tool_name="curl",
        tool_args={"url": "https://example.com"},
        extra_context={"approved": True}
    )

    # Show statistics
    stats = enforcer.get_stats()
    print(f"\nEnforcement statistics:")
    print(f"  Total violations: {stats['total_violations']}")
    print(f"  By severity:")
    for severity, count in stats['by_severity'].items():
        if count > 0:
            print(f"    - {severity}: {count}")
    print(f"  By action:")
    for action, count in stats['by_action'].items():
        if count > 0:
            print(f"    - {action}: {count}")

    print()


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("AGENT CONSTITUTION DEMO")
    print("=" * 60 + "\n")
    
    # Demo 1: Constitution loading
    constitution = demo_constitution_loading()
    
    # Demo 2: PII detection
    demo_pii_detection()
    
    # Demo 3: @enforce decorator
    demo_enforcer_decorator(constitution)
    
    # Demo 4: Manual policy checking
    demo_manual_policy_checking(constitution)
    
    # Demo 5: Audit logging
    demo_audit_logging(constitution)
    
    # Demo 6: Statistics
    demo_statistics(constitution)
    
    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("\nFor more information, see:")
    print("  - README.md for full documentation")
    print("  - CLI: agent-constitution --help")
    print("  - Dashboard: agent-constitution dashboard")
    print()


if __name__ == "__main__":
    main()