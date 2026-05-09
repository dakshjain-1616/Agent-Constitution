# agent-constitution

## Goal
Build a production-ready runtime behavioral contract enforcer for multi-agent LLM systems, including a library, CLI, and dashboard.

## Research Summary
- **Model Verification**: `gemma3:4b` is confirmed as a valid Ollama model identifier for 2026.
- **Tech Stack**: Python (FastAPI, Pydantic, AST, Click, Rich), React (Vite, Tailwind), SQLite for caching, JSONL for audit logs.
- **Security**: AST-based expression evaluation is used instead of `eval()` to prevent code injection.

## Approach
1. **Core Library**: Implement a robust YAML parser (Pydantic) and a safe AST-based expression evaluator.
2. **Enforcement Engine**: Create a decorator-based enforcer that intercepts agent actions, evaluates rules, and applies actions (BLOCK, REDIRECT, etc.).
3. **PII Detection**: Multi-layer detection using regex and `gemma3:4b` via Ollama for high-stakes content.
4. **Audit & Dashboard**: JSONL-based logging for performance, with a FastAPI/React dashboard for real-time monitoring.
5. **CLI**: Unified interface for validation, simulation, and dashboard management.

## Subtasks
1. Setup project structure and install dependencies (pyyaml, pydantic, fastapi, uvicorn, click, rich, watchdog, regex, pytest, httpx). (verify: `pip list` shows packages)
2. Implement `constitution.py` with Pydantic models and YAML validation. (verify: `python -m agent_constitution.constitution` on sample YAML)
3. Build `rules/evaluator.py` using `ast` for safe expression evaluation. (verify: unit tests for comparisons and logic)
4. Build `rules/pii_detector.py` with regex and Ollama integration. (verify: detection of emails/SSNs and mock Ollama call)
5. Implement `enforcer.py` with the `@enforce` decorator and violation tracking. (verify: decorator blocks a forbidden tool call in a test script)
6. Build `audit.py` for JSONL logging and reading. (verify: log file contains expected JSON entries after enforcement)
7. Build `dashboard/server.py` (FastAPI + WebSockets). (verify: `curl` to `/api/stats` returns valid JSON)
8. Build `dashboard/frontend` (React + Tailwind + Vite). (verify: `npm run build` produces `dist/` folder)
9. Implement `cli.py` using Click. (verify: `agent-constitution --help` works)
10. Create `README.md`, `LICENSE`, `pyproject.toml`, and `example/` demo. (verify: `pip install -e .` and `pytest` pass)

## Deliverables
| File Path | Description |
|-----------|-------------|
| `/home/daksh/7May/projects/agent-constitution/agent_constitution/` | Core library package |
| `/home/daksh/7May/projects/agent-constitution/agent_constitution/dashboard/` | FastAPI backend and React frontend |
| `/home/daksh/7May/projects/agent-constitution/tests/` | Pytest suite |
| `/home/daksh/7May/projects/agent-constitution/example/` | Runnable demo |
| `/home/daksh/7May/projects/agent-constitution/README.md` | Documentation |

## Evaluation Criteria
- Zero stubs/placeholders in the codebase.
- `gemma3:4b` correctly integrated for PII detection.
- Dashboard streams live audit logs via WebSockets.
- CLI successfully validates and simulates constitutions.
- 100% pass rate on core logic tests (evaluator, enforcer, parser).

## Notes
- Requires Ollama running locally for Layer 2 PII detection.
- Dashboard frontend requires Node.js/npm for the build step.
