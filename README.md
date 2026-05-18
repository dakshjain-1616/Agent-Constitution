# Agent Constitution

A policy enforcement framework for AI agents with PII detection, audit logging, and real-time dashboard.

---

## 🤖 Autonomously Built with NEO

**Built entirely by [NEO — Your Autonomous AI Engineering Agent](https://heyneo.com)**

[![Get NEO for VS Code](https://img.shields.io/badge/NEO-VS%20Code-007ACC?style=flat&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=NeoResearchInc.heyneo)
[![Get NEO for Cursor](https://img.shields.io/badge/NEO-Cursor-000000?style=flat&logo=cursor)](https://marketplace.cursorapi.com/items/?itemName=NeoResearchInc.heyneo)

NEO is the autonomous AI engineering agent that orchestrates multi-step development tasks, manages complex codebases, and builds production systems end-to-end. [Learn more →](https://heyneo.com)

---

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why We Built This

AI agents now run real workflows with access to customer data, internal systems, and external APIs — but most of them have no enforceable rules about what they are allowed to do. A single prompt injection or careless tool call can leak PII, hit the wrong endpoint, or quietly violate a compliance policy, and there is usually nothing in the loop to stop it or even leave an audit trail.

Agent Constitution was built so every agent action runs through a **policy layer you control**: declare the rules in YAML, evaluate conditions safely without `eval`, detect PII in inputs and outputs, log every decision to a tamper-evident audit trail, and watch enforcement in real time from a dashboard. The goal is to make agent guardrails something you can write down, version, and prove — not a hope.

## Features

- **Policy-Based Enforcement**: Define rules using YAML constitution files
- **AST-Based Expression Evaluation**: Safe condition evaluation without code injection risks
- **PII Detection**: Regex and Ollama-powered detection of sensitive information
- **Audit Logging**: JSONL-based audit trail with rotation support
- **Real-Time Dashboard**: FastAPI + WebSocket + React dashboard for monitoring
- **CLI Interface**: Rich command-line interface for management

## Installation

```bash
# Clone the repository
git clone https://github.com/dakshjain-1616/Agent-Constitution.git
cd Agent-Constitution

# Install dependencies
pip install -e .
```

## Quick Start

### 1. Create a Constitution

```bash
# Create a sample constitution
agent-constitution init --sample -o my_constitution.yaml

# Or create an empty one
agent-constitution init -o my_constitution.yaml
```

### 2. Validate Your Constitution

```bash
agent-constitution validate my_constitution.yaml
```

### 3. Test Policy Enforcement

```bash
# Check if a tool call would be allowed
agent-constitution check rm --arg path=/tmp/test --constitution my_constitution.yaml
```

### 4. Start the Dashboard

```bash
agent-constitution dashboard --constitution my_constitution.yaml
```

Then open http://localhost:8000 in your browser.

## Usage

### Using the @enforce Decorator

```python
from agent_constitution import Constitution, Enforcer

# Load constitution
constitution = Constitution.from_yaml("my_constitution.yaml")
enforcer = Enforcer(constitution=constitution)

@enforcer.enforce
def delete_file(path: str):
    """Delete a file."""
    import os
    os.remove(path)

# This will be blocked if rm/delete operations are restricted
try:
    delete_file("/tmp/test.txt")
except PolicyViolationError as e:
    print(f"Blocked: {e}")
```

### Manual Policy Checking

```python
from agent_constitution import Constitution, Enforcer

constitution = Constitution.from_yaml("my_constitution.yaml")
enforcer = Enforcer(constitution=constitution)

# Check a tool call
result = enforcer.check(
    tool_name="curl",
    tool_args={"url": "https://example.com"},
    extra_context={"approved": False}
)

if result.blocked:
    print(f"Blocked by rule: {result.violations[0].rule_name}")
else:
    print("Allowed")
```

### PII Detection

```python
from agent_constitution.rules.pii_detector import PIIDetector

detector = PIIDetector()

# Detect PII in text
text = "Contact me at john@example.com or call 555-123-4567"
matches = detector.detect(text)

for match in matches:
    print(f"Found {match.pattern_name}: {match.matched_text}")

# Redact PII
redacted = detector.redact(text)
print(redacted)  # "Contact me at [REDACTED] or call [REDACTED]"
```

### Audit Logging

```python
from agent_constitution.audit import AuditLogger

logger = AuditLogger(log_path="./audit.jsonl")

# Log an event
logger.log(
    event_type="tool_call",
    tool_name="rm",
    action="block",
    allowed=False,
    violations=[{"rule_name": "block_file_deletion"}]
)

# Read logs
for entry in logger.read_logs(limit=10):
    print(f"{entry.timestamp}: {entry.event_type} - {entry.tool_name}")
```

## Constitution Format

```yaml
version: "1.0"
name: "My Agent Constitution"
description: "Security policies for my AI agent"

policies:
  - name: tool_restrictions
    description: "Restrict access to dangerous tools"
    priority: 10
    rules:
      - name: block_file_deletion
        description: "Prevent file system deletion operations"
        condition: "tool_name in ['rm', 'unlink', 'rmdir']"
        action: block
        severity: critical

      - name: restrict_network_access
        description: "Limit unrestricted network access"
        condition: "tool_name == 'curl' and not context.get('approved', False)"
        action: notify
        severity: high

  - name: data_protection
    description: "Protect sensitive data"
    priority: 5
    rules:
      - name: pii_detection
        description: "Detect and protect PII in outputs"
        condition: "pii_detected == True"
        action: block
        severity: high

pii_config:
  enabled: true
  patterns: ["email", "ssn", "phone"]
  use_ollama: true
  ollama_model: "gemma3:4b"
  ollama_url: "http://localhost:11434"

audit_config:
  enabled: true
  log_path: "./audit_logs.jsonl"
  max_file_size_mb: 100
  retention_days: 30
```

## CLI Commands

```bash
# Initialize a constitution
agent-constitution init --sample

# Validate a constitution
agent-constitution validate my_constitution.yaml

# Display constitution contents
agent-constitution show my_constitution.yaml

# Check if a tool call would be allowed
agent-constitution check rm --arg path=/tmp/test --constitution my_constitution.yaml

# Start the dashboard
agent-constitution dashboard --constitution my_constitution.yaml

# View audit logs
agent-constitution audit --log-path ./audit.jsonl

# Show statistics
agent-constitution stats --constitution my_constitution.yaml

# Test expression evaluation
agent-constitution eval-expr "x > 5" --context x=10
```

## Dashboard

The dashboard provides real-time monitoring of:
- Policy violations
- Audit logs
- Constitution rules and policies
- Enforcement statistics

![Dashboard](docs/dashboard.png)

## Testing

This project has comprehensive test coverage with **84 unit tests**, all passing:

```bash
# Run all tests
pytest tests/ -v

# All tests passing: 84/84 ✓
```

Test coverage includes:
- Constitution loading and YAML parsing
- Policy enforcement with the @enforce decorator
- Manual policy checking
- PII detection (regex and patterns)
- Audit logging with rotation
- Expression evaluation and security validation
- Rule violation tracking and statistics

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run specific test file
pytest tests/test_evaluator.py -v

# Run linting
flake8 agent_constitution

# Run type checking
mypy agent_constitution
```

## Architecture

```
agent_constitution/
├── constitution.py      # Pydantic models and YAML handling
├── enforcer.py          # Policy enforcement and @enforce decorator
├── audit.py            # JSONL audit logging
├── cli.py              # Click CLI interface
├── rules/
│   ├── evaluator.py    # AST-based expression evaluation
│   └── pii_detector.py # PII detection with regex/Ollama
└── dashboard/
    ├── server.py       # FastAPI + WebSocket server
    └── frontend/       # React + Tailwind dashboard
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For questions or issues, please open an issue on GitHub.

---

## 🤖 Built with NEO

This project was developed using [NEO](https://heyneo.com) — the autonomous AI engineering agent. NEO enabled rapid implementation, testing, and iteration across all 10 implementation steps, resulting in a production-ready policy enforcement framework with comprehensive test coverage (84/84 tests passing).
