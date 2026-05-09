"""FastAPI server with WebSocket support for the agent-constitution dashboard."""

import json
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

from agent_constitution.constitution import Constitution
from agent_constitution.audit import AuditLogger
from agent_constitution.enforcer import Enforcer


# Global state
class DashboardState:
    """Shared state for the dashboard."""
    def __init__(self):
        self.constitution: Optional[Constitution] = None
        self.audit_logger: Optional[AuditLogger] = None
        self.enforcer: Optional[Enforcer] = None
        self.connected_clients: List[WebSocket] = []
        self.stats_cache: Dict[str, Any] = {}
        self.cache_timestamp: Optional[datetime] = None
        
    def load_constitution(self, path: str) -> None:
        """Load constitution from file."""
        self.constitution = Constitution.from_yaml(path)
        if self.constitution:
            self.enforcer = Enforcer(constitution=self.constitution)
    
    def setup_audit_logger(self, path: str = "./audit_logs.jsonl") -> None:
        """Setup audit logger."""
        self.audit_logger = AuditLogger(log_path=path)
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all connected WebSocket clients."""
        disconnected = []
        for client in self.connected_clients:
            try:
                await client.send_json(message)
            except:
                disconnected.append(client)
        
        # Remove disconnected clients
        for client in disconnected:
            if client in self.connected_clients:
                self.connected_clients.remove(client)


# Global state instance
state = DashboardState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print("Starting Agent Constitution Dashboard Server...")
    
    # Load default constitution if exists
    default_constitution = Path("sample_constitution.yaml")
    if default_constitution.exists():
        try:
            state.load_constitution(str(default_constitution))
            print(f"Loaded constitution: {state.constitution.name}")
        except Exception as e:
            print(f"Warning: Could not load default constitution: {e}")
    
    # Setup audit logger
    state.setup_audit_logger()
    print("Audit logger initialized")
    
    yield
    
    # Shutdown
    print("Shutting down...")
    state.connected_clients.clear()


def create_server() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Agent Constitution Dashboard",
        description="Real-time policy enforcement monitoring",
        version="0.1.0",
        lifespan=lifespan
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # API Routes
    @app.get("/api/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "constitution_loaded": state.constitution is not None,
            "connected_clients": len(state.connected_clients)
        }
    
    @app.get("/api/stats")
    async def get_stats():
        """Get dashboard statistics."""
        stats = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "constitution": None,
            "violations": {"total": 0, "by_severity": {}},
            "audit": {"total_entries": 0},
            "connected_clients": len(state.connected_clients)
        }
        
        if state.constitution:
            stats["constitution"] = {
                "name": state.constitution.name,
                "version": state.constitution.version,
                "policies_count": len(state.constitution.policies),
                "rules_count": sum(len(p.rules) for p in state.constitution.policies)
            }
        
        if state.enforcer:
            enforcer_stats = state.enforcer.get_stats()
            stats["violations"] = {
                "total": enforcer_stats["total_violations"],
                "by_severity": enforcer_stats["by_severity"],
                "by_action": enforcer_stats["by_action"]
            }
        
        if state.audit_logger:
            audit_stats = state.audit_logger.get_stats()
            stats["audit"] = {
                "total_entries": audit_stats["entries_written"],
                "log_path": audit_stats["log_path"],
                "enabled": audit_stats["enabled"]
            }
        
        return JSONResponse(content=stats)
    
    @app.get("/api/constitution")
    async def get_constitution():
        """Get current constitution."""
        if not state.constitution:
            raise HTTPException(status_code=404, detail="No constitution loaded")
        
        return JSONResponse(content=state.constitution.model_dump())
    
    @app.post("/api/constitution/load")
    async def load_constitution(path: str):
        """Load constitution from file path."""
        try:
            state.load_constitution(path)
            return JSONResponse(content={
                "success": True,
                "message": f"Loaded constitution: {state.constitution.name}",
                "constitution": state.constitution.model_dump()
            })
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @app.get("/api/violations")
    async def get_violations(
        limit: int = Query(100, ge=1, le=1000),
        since: Optional[str] = None
    ):
        """Get recent violations."""
        if not state.enforcer:
            return JSONResponse(content={"violations": []})
        
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                pass
        
        violations = state.enforcer.get_violations(since=since_dt)
        violations_data = [
            {
                "rule_name": v.rule_name,
                "rule_description": v.rule_description,
                "severity": v.severity,
                "action": v.action,
                "timestamp": v.timestamp.isoformat(),
                "context": v.context
            }
            for v in violations[-limit:]
        ]
        
        return JSONResponse(content={"violations": violations_data})
    
    @app.get("/api/audit")
    async def get_audit_logs(
        limit: int = Query(100, ge=1, le=1000),
        event_type: Optional[str] = None,
        tool_name: Optional[str] = None
    ):
        """Get audit logs."""
        if not state.audit_logger:
            return JSONResponse(content={"entries": []})
        
        entries = list(state.audit_logger.read_logs(
            limit=limit,
            event_type=event_type,
            tool_name=tool_name
        ))
        
        entries_data = [entry.to_dict() for entry in entries]
        
        return JSONResponse(content={"entries": entries_data})
    
    @app.get("/api/policies")
    async def get_policies():
        """Get all policies."""
        if not state.constitution:
            raise HTTPException(status_code=404, detail="No constitution loaded")
        
        policies = [
            {
                "name": p.name,
                "description": p.description,
                "enabled": p.enabled,
                "priority": p.priority,
                "rules_count": len(p.rules)
            }
            for p in state.constitution.policies
        ]
        
        return JSONResponse(content={"policies": policies})
    
    @app.get("/api/rules")
    async def get_rules(policy_name: Optional[str] = None):
        """Get all rules or rules for a specific policy."""
        if not state.constitution:
            raise HTTPException(status_code=404, detail="No constitution loaded")
        
        rules = []
        for policy in state.constitution.policies:
            if policy_name and policy.name != policy_name:
                continue
            for rule in policy.rules:
                rules.append({
                    "name": rule.name,
                    "description": rule.description,
                    "condition": rule.condition,
                    "action": rule.action,
                    "severity": rule.severity,
                    "enabled": rule.enabled,
                    "policy": policy.name
                })
        
        return JSONResponse(content={"rules": rules})
    
    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time updates."""
        await websocket.accept()
        state.connected_clients.append(websocket)
        
        try:
            # Send initial stats
            await websocket.send_json({
                "type": "connected",
                "message": "Connected to Agent Constitution Dashboard",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            # Keep connection alive and handle client messages
            while True:
                try:
                    data = await websocket.receive_json()
                    
                    # Handle different message types
                    if data.get("type") == "ping":
                        await websocket.send_json({
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                    elif data.get("type") == "get_stats":
                        # Send current stats
                        stats = await get_stats()
                        await websocket.send_json({
                            "type": "stats",
                            "data": stats.body
                        })
                    
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })
        
        except WebSocketDisconnect:
            pass
        finally:
            if websocket in state.connected_clients:
                state.connected_clients.remove(websocket)
    
    # Static files (for frontend)
    frontend_path = Path(__file__).parent / "frontend" / "dist"
    if frontend_path.exists():
        app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="static")
    
    return app


def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    constitution_path: Optional[str] = None,
    reload: bool = False
) -> None:
    """Run the dashboard server."""
    import uvicorn
    
    if constitution_path:
        try:
            state.load_constitution(constitution_path)
            print(f"Loaded constitution: {state.constitution.name}")
        except Exception as e:
            print(f"Warning: Could not load constitution: {e}")
    
    print(f"Starting server on http://{host}:{port}")
    uvicorn.run(
        "agent_constitution.dashboard.server:create_server",
        host=host,
        port=port,
        reload=reload,
        factory=True
    )


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent Constitution Dashboard Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--constitution", help="Path to constitution YAML file")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    run_server(
        host=args.host,
        port=args.port,
        constitution_path=args.constitution,
        reload=args.reload
    )