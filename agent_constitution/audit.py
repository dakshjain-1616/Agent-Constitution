"""Audit module - JSONL logging and reading for enforcement events."""

import json
import os
import gzip
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import threading


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""
    timestamp: str
    event_type: str
    tool_name: Optional[str]
    action: str
    allowed: bool
    violations: List[Dict[str, Any]]
    context: Dict[str, Any]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Create entry from dictionary."""
        return cls(**data)


class AuditLogger:
    """JSONL audit logger with rotation support."""
    
    def __init__(
        self,
        log_path: Union[str, Path] = "./audit_logs.jsonl",
        max_file_size_mb: int = 100,
        retention_days: int = 30,
        enabled: bool = True,
        compress_rotated: bool = True
    ):
        """Initialize the audit logger.
        
        Args:
            log_path: Path to the audit log file
            max_file_size_mb: Maximum file size before rotation
            retention_days: Number of days to retain logs
            enabled: Whether logging is enabled
            compress_rotated: Whether to gzip rotated files
        """
        self.log_path = Path(log_path)
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.enabled = enabled
        self.compress_rotated = compress_rotated
        
        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread lock for concurrent writes
        self._lock = threading.Lock()
        
        # Statistics
        self._entries_written = 0
        self._bytes_written = 0
    
    def log(
        self,
        event_type: str,
        tool_name: Optional[str] = None,
        action: str = "allow",
        allowed: bool = True,
        violations: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AuditEntry]:
        """Write an entry to the audit log.
        
        Args:
            event_type: Type of event (e.g., 'tool_call', 'policy_violation')
            tool_name: Name of the tool involved
            action: Action taken (allow, block, notify, log)
            allowed: Whether the action was allowed
            violations: List of policy violations
            context: Additional context data
            metadata: Additional metadata
            
        Returns:
            The created AuditEntry or None if logging is disabled
        """
        if not self.enabled:
            return None
        
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            tool_name=tool_name,
            action=action,
            allowed=allowed,
            violations=violations or [],
            context=context or {},
            metadata=metadata or {}
        )
        
        self._write_entry(entry)
        return entry
    
    def log_enforcement_result(
        self,
        tool_name: str,
        result: Any,  # EnforcementResult
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AuditEntry]:
        """Log an enforcement result.
        
        Args:
            tool_name: Name of the tool
            result: EnforcementResult object
            metadata: Additional metadata
            
        Returns:
            The created AuditEntry or None if logging is disabled
        """
        if not self.enabled:
            return None
        
        violations_data = []
        if hasattr(result, 'violations'):
            violations_data = [
                {
                    "rule_name": v.rule_name,
                    "rule_description": v.rule_description,
                    "severity": v.severity,
                    "action": v.action
                }
                for v in result.violations
            ]
        
        return self.log(
            event_type="enforcement_check",
            tool_name=tool_name,
            action=getattr(result, 'action_taken', 'unknown'),
            allowed=getattr(result, 'allowed', True),
            violations=violations_data,
            context=getattr(result, 'context', {}),
            metadata=metadata
        )
    
    def _write_entry(self, entry: AuditEntry) -> None:
        """Write entry to log file with rotation support."""
        with self._lock:
            # Check if rotation is needed
            if self._should_rotate():
                self._rotate_log()
            
            # Write entry as JSON line
            line = json.dumps(entry.to_dict(), default=str) + "\n"
            
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            
            self._entries_written += 1
            self._bytes_written += len(line.encode('utf-8'))
    
    def _should_rotate(self) -> bool:
        """Check if log file should be rotated."""
        if not self.log_path.exists():
            return False
        
        return self.log_path.stat().st_size >= self.max_file_size_bytes
    
    def _rotate_log(self) -> None:
        """Rotate the current log file."""
        if not self.log_path.exists():
            return
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rotated_path = self.log_path.parent / f"{self.log_path.stem}.{timestamp}{self.log_path.suffix}"
        
        # Rename current log
        shutil.move(str(self.log_path), str(rotated_path))
        
        # Compress if enabled
        if self.compress_rotated:
            compressed_path = Path(str(rotated_path) + ".gz")
            with open(rotated_path, "rb") as f_in:
                with gzip.open(compressed_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            rotated_path.unlink()  # Remove uncompressed file
    
    def read_logs(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        tool_name: Optional[str] = None,
        limit: Optional[int] = None
    ) -> Iterator[AuditEntry]:
        """Read audit log entries with optional filtering.
        
        Args:
            since: Only return entries after this timestamp
            until: Only return entries before this timestamp
            event_type: Filter by event type
            tool_name: Filter by tool name
            limit: Maximum number of entries to return
            
        Yields:
            AuditEntry objects
        """
        count = 0
        
        # Get all log files (current + rotated)
        log_files = self._get_log_files()
        
        for log_file in log_files:
            if limit and count >= limit:
                break
            
            entries = self._read_log_file(log_file)
            
            for entry in entries:
                if limit and count >= limit:
                    break
                
                # Parse timestamp for filtering
                entry_time = datetime.fromisoformat(entry.timestamp)
                
                # Apply filters
                if since and entry_time < since:
                    continue
                if until and entry_time > until:
                    continue
                if event_type and entry.event_type != event_type:
                    continue
                if tool_name and entry.tool_name != tool_name:
                    continue
                
                yield entry
                count += 1
    
    def _get_log_files(self) -> List[Path]:
        """Get all log files including rotated ones."""
        files = []
        
        # Current log file
        if self.log_path.exists():
            files.append(self.log_path)
        
        # Rotated files
        pattern = f"{self.log_path.stem}.*{self.log_path.suffix}*"
        for file_path in self.log_path.parent.glob(pattern):
            files.append(file_path)
        
        # Sort by modification time (newest first)
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        return files
    
    def _read_log_file(self, path: Path) -> Iterator[AuditEntry]:
        """Read entries from a single log file."""
        if not path.exists():
            return
        
        # Handle compressed files
        if path.suffix == ".gz":
            opener = lambda: gzip.open(path, "rt", encoding="utf-8")
        else:
            opener = lambda: open(path, "r", encoding="utf-8")
        
        try:
            with opener() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        yield AuditEntry.from_dict(data)
                    except (json.JSONDecodeError, TypeError) as e:
                        # Skip malformed entries
                        continue
        except (IOError, OSError) as e:
            # Skip unreadable files
            pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        stats = {
            "log_path": str(self.log_path),
            "enabled": self.enabled,
            "entries_written": self._entries_written,
            "bytes_written": self._bytes_written,
            "current_log_size": 0,
            "total_log_files": len(self._get_log_files())
        }
        
        if self.log_path.exists():
            stats["current_log_size"] = self.log_path.stat().st_size
        
        return stats
    
    def cleanup_old_logs(self) -> int:
        """Remove logs older than retention_days.
        
        Returns:
            Number of files removed
        """
        if self.retention_days <= 0:
            return 0
        
        cutoff = datetime.now(timezone.utc).timestamp() - (self.retention_days * 24 * 60 * 60)
        removed = 0
        
        for file_path in self._get_log_files():
            if file_path == self.log_path:
                continue  # Don't remove current log
            
            try:
                if file_path.stat().st_mtime < cutoff:
                    file_path.unlink()
                    removed += 1
            except (IOError, OSError):
                pass
        
        return removed
    
    def clear(self) -> None:
        """Clear all audit logs (use with caution)."""
        with self._lock:
            # Remove current log
            if self.log_path.exists():
                self.log_path.unlink()
            
            # Remove rotated logs
            for file_path in self._get_log_files():
                if file_path != self.log_path:
                    try:
                        file_path.unlink()
                    except (IOError, OSError):
                        pass
            
            self._entries_written = 0
            self._bytes_written = 0


@contextmanager
def audit_session(
    logger: AuditLogger,
    session_id: Optional[str] = None
):
    """Context manager for audit logging sessions.
    
    Args:
        logger: AuditLogger instance
        session_id: Optional session identifier
        
    Yields:
        Dict for accumulating session data
    """
    session_data = {
        "session_id": session_id or datetime.now(timezone.utc).isoformat(),
        "start_time": datetime.now(timezone.utc).isoformat(),
        "events": []
    }
    
    try:
        yield session_data
    finally:
        session_data["end_time"] = datetime.now(timezone.utc).isoformat()
        logger.log(
            event_type="session_end",
            metadata=session_data
        )


def create_audit_logger(
    log_path: Optional[str] = None,
    **kwargs
) -> AuditLogger:
    """Factory function to create an audit logger."""
    if log_path:
        return AuditLogger(log_path=log_path, **kwargs)
    return AuditLogger(**kwargs)


if __name__ == "__main__":
    # Demo
    print("Audit Logger Demo")
    print("=" * 50)
    
    # Create logger
    logger = AuditLogger(log_path="./demo_audit.jsonl")
    
    # Log some events
    print("\n1. Logging events:")
    
    logger.log(
        event_type="tool_call",
        tool_name="ls",
        action="allow",
        allowed=True,
        context={"path": "/tmp"}
    )
    print("   - Logged allowed tool call")
    
    logger.log(
        event_type="tool_call",
        tool_name="rm",
        action="block",
        allowed=False,
        violations=[{
            "rule_name": "block_file_deletion",
            "severity": "critical"
        }],
        context={"path": "/tmp/test"}
    )
    print("   - Logged blocked tool call")
    
    # Read logs back
    print("\n2. Reading logs:")
    for entry in logger.read_logs(limit=10):
        print(f"   - {entry.timestamp}: {entry.event_type} - {entry.tool_name} ({entry.action})")
    
    # Show stats
    print("\n3. Statistics:")
    stats = logger.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Cleanup
    print("\n4. Cleanup:")
    logger.clear()
    print("   - Logs cleared")