"""Worktree registry for tracking active worktrees"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class WorktreeRegistry:
    """Registry for tracking active worktrees"""

    def __init__(self, worktree_base: Path):
        self.registry_file = worktree_base / ".worktree-registry.json"
        self._ensure_registry()

    def _ensure_registry(self):
        """Ensure registry file exists"""
        if not self.registry_file.exists():
            self.registry_file.parent.mkdir(parents=True, exist_ok=True)
            self.registry_file.write_text("{}")

    def _load(self) -> Dict:
        """Load registry from disk"""
        try:
            return json.loads(self.registry_file.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save(self, data: Dict):
        """Save registry to disk"""
        self.registry_file.write_text(json.dumps(data, indent=2))

    def register(self, worktree_id: str, info: Dict):
        """Register a new worktree"""
        registry = self._load()
        registry[worktree_id] = info
        self._save(registry)
        logger.debug(f"Registered worktree: {worktree_id}")

    def unregister(self, worktree_id: str):
        """Unregister a worktree"""
        registry = self._load()
        if worktree_id in registry:
            del registry[worktree_id]
            self._save(registry)
            logger.debug(f"Unregistered worktree: {worktree_id}")

    def get(self, worktree_id: str) -> Optional[Dict]:
        """Get worktree info"""
        registry = self._load()
        return registry.get(worktree_id)

    def list_all(self) -> Dict[str, dict]:
        """List all registered worktrees"""
        return self._load()
