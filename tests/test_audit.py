"""Unit tests for the audit logger."""

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from agent_constitution.audit import AuditLogger, AuditEntry, audit_session


class TestAuditLoggerBasic:
    """Basic audit logger tests."""
    
    def test_logger_creation(self):
        """Test creating an audit logger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            assert logger is not None
            assert logger.log_path == log_path
    
    def test_log_entry_creation(self):
        """Test logging an entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            entry = logger.log(
                event_type="test_event",
                tool_name="test_tool",
                action="allow",
                allowed=True
            )
            
            assert entry is not None
            assert entry.event_type == "test_event"
            assert entry.tool_name == "test_tool"
            assert entry.action == "allow"
            assert entry.allowed is True
            assert "timestamp" in entry.to_dict()
    
    def test_log_file_created(self):
        """Test that log file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="test")
            
            assert log_path.exists()
    
    def test_log_file_contains_jsonl(self):
        """Test that log file contains valid JSON lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="test_event", tool_name="tool1")
            logger.log(event_type="test_event", tool_name="tool2")
            
            with open(log_path, "r") as f:
                lines = f.readlines()
            
            assert len(lines) == 2
            
            # Verify each line is valid JSON
            for line in lines:
                data = json.loads(line)
                assert "timestamp" in data
                assert "event_type" in data


class TestAuditLoggerReading:
    """Tests for reading audit logs."""
    
    def test_read_logs(self):
        """Test reading logged entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="event1", tool_name="tool1")
            logger.log(event_type="event2", tool_name="tool2")
            
            entries = list(logger.read_logs())
            
            assert len(entries) == 2
            assert entries[0].event_type == "event1"
            assert entries[1].event_type == "event2"
    
    def test_read_logs_with_limit(self):
        """Test reading with limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            for i in range(10):
                logger.log(event_type=f"event{i}")
            
            entries = list(logger.read_logs(limit=5))
            
            assert len(entries) == 5
    
    def test_read_logs_filter_by_event_type(self):
        """Test filtering by event type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="tool_call", tool_name="tool1")
            logger.log(event_type="violation", tool_name="tool2")
            logger.log(event_type="tool_call", tool_name="tool3")
            
            entries = list(logger.read_logs(event_type="tool_call"))
            
            assert len(entries) == 2
            for entry in entries:
                assert entry.event_type == "tool_call"
    
    def test_read_logs_filter_by_tool_name(self):
        """Test filtering by tool name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="test", tool_name="ls")
            logger.log(event_type="test", tool_name="rm")
            logger.log(event_type="test", tool_name="ls")
            
            entries = list(logger.read_logs(tool_name="ls"))
            
            assert len(entries) == 2
            for entry in entries:
                assert entry.tool_name == "ls"


class TestAuditLoggerFiltering:
    """Tests for filtering audit logs by time."""
    
    def test_read_logs_since(self):
        """Test filtering by start time."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            # Log an entry
            logger.log(event_type="old_event")
            
            # Get timestamp after first entry
            since = datetime.now(timezone.utc)
            
            # Log another entry
            logger.log(event_type="new_event")
            
            entries = list(logger.read_logs(since=since))
            
            assert len(entries) == 1
            assert entries[0].event_type == "new_event"
    
    def test_read_logs_until(self):
        """Test filtering by end time."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            # Log entries
            logger.log(event_type="event1")
            
            until = datetime.now(timezone.utc)
            
            logger.log(event_type="event2")
            
            entries = list(logger.read_logs(until=until))
            
            assert len(entries) == 1
            assert entries[0].event_type == "event1"


class TestAuditLoggerStats:
    """Tests for audit logger statistics."""
    
    def test_get_stats(self):
        """Test getting statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            # Log some entries
            for i in range(5):
                logger.log(event_type=f"event{i}")
            
            stats = logger.get_stats()
            
            assert stats["entries_written"] == 5
            assert stats["enabled"] is True
            assert "log_path" in stats
    
    def test_stats_after_clear(self):
        """Test stats after clearing logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="test")
            logger.clear()
            
            stats = logger.get_stats()
            
            assert stats["entries_written"] == 0


class TestAuditLoggerClear:
    """Tests for clearing audit logs."""
    
    def test_clear_logs(self):
        """Test clearing all logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            logger.log(event_type="test")
            assert log_path.exists()
            
            logger.clear()
            
            assert not log_path.exists()
            entries = list(logger.read_logs())
            assert len(entries) == 0


class TestAuditEntry:
    """Tests for AuditEntry dataclass."""
    
    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="test",
            tool_name="tool1",
            action="allow",
            allowed=True,
            violations=[],
            context={},
            metadata={}
        )
        
        d = entry.to_dict()
        
        assert d["event_type"] == "test"
        assert d["tool_name"] == "tool1"
        assert "timestamp" in d
    
    def test_entry_from_dict(self):
        """Test creating entry from dictionary."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "test",
            "tool_name": "tool1",
            "action": "block",
            "allowed": False,
            "violations": [{"rule": "test_rule"}],
            "context": {"key": "value"},
            "metadata": {}
        }
        
        entry = AuditEntry.from_dict(data)
        
        assert entry.event_type == "test"
        assert entry.allowed is False
        assert len(entry.violations) == 1


class TestAuditSession:
    """Tests for audit session context manager."""
    
    def test_audit_session(self):
        """Test audit session context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path)
            
            with audit_session(logger, session_id="test_session") as session:
                session["events"].append("event1")
                session["events"].append("event2")
            
            # Check that session_end was logged
            entries = list(logger.read_logs(event_type="session_end"))
            assert len(entries) == 1
            assert entries[0].metadata["session_id"] == "test_session"
            assert len(entries[0].metadata["events"]) == 2


class TestAuditLoggerDisabled:
    """Tests for disabled audit logger."""
    
    def test_disabled_logger_returns_none(self):
        """Test that disabled logger returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path, enabled=False)
            
            entry = logger.log(event_type="test")
            
            assert entry is None
    
    def test_disabled_logger_does_not_create_file(self):
        """Test that disabled logger doesn't create log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path=log_path, enabled=False)
            
            logger.log(event_type="test")
            
            assert not log_path.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])