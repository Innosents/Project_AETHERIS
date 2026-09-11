"""
Agent Blackboard Ledger & Concurrency Lock Manager
Provides a thread-safe, multi-agent shared session state ledger for coordinating
concurrent AI agents, managing node/resource locks, and recording atomic checkpoints.
"""

import os
import json
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent

class BlackboardLedger:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(BlackboardLedger, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, storage_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return

        self.storage_path = storage_path or (BASE_DIR / "blackboard_ledger.json")
        self.state: Dict[str, Any] = {
            "active_locks": {},        # resource_id -> {agent_id, acquired_at, expires_at, ttl_seconds, reason}
            "agent_checkpoints": [],   # list of checkpoint objects
            "active_tasks": {},        # task_id -> {title, assigned_agent, status, started_at, updated_at}
            "shared_memory": {},       # key -> value dict
            "message_feed": []         # list of inter-agent messages
        }
        self.load_state()
        self._initialized = True

    def load_state(self) -> None:
        """Loads blackboard state from disk."""
        with self._lock:
            if self.storage_path.exists():
                try:
                    with self.storage_path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.state = {
                            "active_locks": data.get("active_locks", {}),
                            "agent_checkpoints": data.get("agent_checkpoints", []),
                            "active_tasks": data.get("active_tasks", {}),
                            "shared_memory": data.get("shared_memory", {}),
                            "message_feed": data.get("message_feed", [])
                        }
                except Exception as e:
                    pass
            self._purge_expired_locks()

    def save_state(self) -> None:
        """Atomically saves blackboard state to disk."""
        with self._lock:
            self._purge_expired_locks()
            try:
                temp_path = self.storage_path.with_suffix(".tmp")
                with temp_path.open("w", encoding="utf-8") as f:
                    json.dump(self.state, f, indent=2)
                temp_path.replace(self.storage_path)
            except Exception as e:
                pass

    def _purge_expired_locks(self) -> None:
        """Purges any expired resource locks."""
        now = time.time()
        expired = []
        for res_id, lock_info in self.state["active_locks"].items():
            if lock_info.get("expires_at", 0) <= now:
                expired.append(res_id)
        for res_id in expired:
            del self.state["active_locks"][res_id]

    def acquire_lock(
        self,
        resource_id: str,
        agent_id: str,
        ttl_seconds: int = 60,
        reason: str = ""
    ) -> Dict[str, Any]:
        """
        Attempts to acquire an exclusive lock on a resource/node with TTL expiration.
        """
        if not resource_id or not agent_id:
            return {"status": "error", "message": "Missing resource_id or agent_id"}

        with self._lock:
            self._purge_expired_locks()
            now = time.time()

            existing_lock = self.state["active_locks"].get(resource_id)
            if existing_lock:
                if existing_lock["agent_id"] == agent_id:
                    # Renew existing lock
                    existing_lock["expires_at"] = now + ttl_seconds
                    existing_lock["ttl_seconds"] = ttl_seconds
                    existing_lock["reason"] = reason or existing_lock.get("reason", "")
                    self.save_state()
                    return {
                        "status": "renewed",
                        "resource_id": resource_id,
                        "agent_id": agent_id,
                        "expires_in_seconds": ttl_seconds
                    }
                else:
                    remaining = round(max(0.0, existing_lock["expires_at"] - now), 1)
                    return {
                        "status": "contended",
                        "resource_id": resource_id,
                        "current_owner": existing_lock["agent_id"],
                        "remaining_ttl_seconds": remaining,
                        "reason": existing_lock.get("reason", "")
                    }

            # Acquire new lock
            lock_entry = {
                "resource_id": resource_id,
                "agent_id": agent_id,
                "acquired_at": now,
                "expires_at": now + ttl_seconds,
                "ttl_seconds": ttl_seconds,
                "reason": reason
            }
            self.state["active_locks"][resource_id] = lock_entry
            self.save_state()

            return {
                "status": "acquired",
                "resource_id": resource_id,
                "agent_id": agent_id,
                "expires_in_seconds": ttl_seconds
            }

    def release_lock(self, resource_id: str, agent_id: str, force: bool = False) -> Dict[str, Any]:
        """Releases an acquired lock on a resource/node."""
        with self._lock:
            self._purge_expired_locks()
            existing_lock = self.state["active_locks"].get(resource_id)

            if not existing_lock:
                return {"status": "not_locked", "resource_id": resource_id}

            if not force and existing_lock["agent_id"] != agent_id:
                return {
                    "status": "unauthorized",
                    "resource_id": resource_id,
                    "current_owner": existing_lock["agent_id"]
                }

            del self.state["active_locks"][resource_id]
            self.save_state()

            return {"status": "released", "resource_id": resource_id, "released_by": agent_id}

    def post_checkpoint(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        summary: str,
        payload: Optional[Dict[str, Any]] = None,
        artifacts_modified: Optional[List[str]] = None,
        step_index: Optional[int] = None
    ) -> Dict[str, Any]:
        """Posts an atomic progress checkpoint from an agent."""
        with self._lock:
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            checkpoint = {
                "checkpoint_id": f"chk_{int(time.time()*1000)}_{agent_id}",
                "agent_id": agent_id,
                "task_id": task_id,
                "step_index": step_index or (len(self.state["agent_checkpoints"]) + 1),
                "status": status,
                "summary": summary,
                "payload": payload or {},
                "artifacts_modified": artifacts_modified or [],
                "timestamp": now_iso
            }

            self.state["agent_checkpoints"].append(checkpoint)

            # Update active task record
            if task_id:
                if task_id not in self.state["active_tasks"]:
                    self.state["active_tasks"][task_id] = {
                        "task_id": task_id,
                        "title": summary,
                        "assigned_agent": agent_id,
                        "status": status,
                        "started_at": now_iso,
                        "updated_at": now_iso
                    }
                else:
                    task_entry = self.state["active_tasks"][task_id]
                    task_entry["status"] = status
                    task_entry["updated_at"] = now_iso
                    if status == "completed":
                        task_entry["completed_at"] = now_iso

            self.save_state()
            return {"status": "success", "checkpoint": checkpoint}

    def read_state(
        self,
        section: str = "all",
        filter_agent_id: str = "",
        filter_task_status: str = "",
        limit: int = 50
    ) -> Dict[str, Any]:
        """Reads blackboard state with optional filtering."""
        with self._lock:
            self._purge_expired_locks()

            result: Dict[str, Any] = {}
            sec = section.strip().lower()

            if sec in ("all", "locks"):
                now = time.time()
                locks_output = {}
                for res_id, lock in self.state["active_locks"].items():
                    if not filter_agent_id or lock.get("agent_id") == filter_agent_id:
                        remaining = max(0.0, round(lock.get("expires_at", 0) - now, 1))
                        locks_output[res_id] = {
                            "agent_id": lock.get("agent_id"),
                            "remaining_ttl_seconds": remaining,
                            "reason": lock.get("reason", "")
                        }
                result["active_locks"] = locks_output

            if sec in ("all", "tasks"):
                tasks = {}
                for tid, t in self.state["active_tasks"].items():
                    if filter_agent_id and t.get("assigned_agent") != filter_agent_id:
                        continue
                    if filter_task_status and t.get("status") != filter_task_status:
                        continue
                    tasks[tid] = t
                result["active_tasks"] = tasks

            if sec in ("all", "checkpoints"):
                chks = self.state["agent_checkpoints"]
                if filter_agent_id:
                    chks = [c for c in chks if c.get("agent_id") == filter_agent_id]
                result["agent_checkpoints"] = chks[-limit:]

            if sec in ("all", "memory"):
                result["shared_memory"] = self.state["shared_memory"]

            if sec in ("all", "feed"):
                result["message_feed"] = self.state["message_feed"][-limit:]

            result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return result

    def post_message(
        self,
        sender_agent_id: str,
        message: str,
        message_type: str = "info",
        recipient: str = "all"
    ) -> Dict[str, Any]:
        """Broadcasts an inter-agent message to the blackboard feed."""
        with self._lock:
            entry = {
                "message_id": f"msg_{int(time.time()*1000)}",
                "sender": sender_agent_id,
                "recipient": recipient,
                "type": message_type,
                "message": message,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            self.state["message_feed"].append(entry)
            self.save_state()
            return {"status": "posted", "message": entry}

    def set_memory(self, key: str, value: Any) -> Dict[str, Any]:
        """Sets a key-value record in the shared memory blackboard."""
        with self._lock:
            self.state["shared_memory"][key] = value
            self.save_state()
            return {"status": "stored", "key": key, "value": value}

    def reset_state(self) -> None:
        """Administrative reset of the blackboard state."""
        with self._lock:
            self.state = {
                "active_locks": {},
                "agent_checkpoints": [],
                "active_tasks": {},
                "shared_memory": {},
                "message_feed": []
            }
            self.save_state()

