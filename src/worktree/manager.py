"""Git worktree manager for isolated vulnerability scanning"""

import fcntl
import logging
import os
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

from .registry import WorktreeRegistry

logger = logging.getLogger(__name__)


class WorktreeManager:
    """Manages git worktrees for isolated vulnerability scanning"""

    def __init__(self, repo_path: str, worktree_base: str = "/tmp/vulner-worktrees"):
        self.repo_path = Path(repo_path).resolve()
        self.worktree_base = Path(worktree_base)
        self.lock_file = self.worktree_base / ".worktree.lock"
        self.registry = WorktreeRegistry(self.worktree_base)

        # Create base directory with restricted permissions
        self.worktree_base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.worktree_base, 0o700)

        # Ensure lock file exists
        self.lock_file.touch(exist_ok=True)

    @contextmanager
    def _lock(self):
        """Atomic locking mechanism for git operations"""
        with open(self.lock_file) as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def create_worktree(
        self, commit_ref: str = "HEAD", scan_id: Optional[str] = None, detached: bool = True
    ) -> Dict[str, str]:
        """
        Create a new worktree for vulnerability scanning

        Args:
            commit_ref: Git commit reference (default: HEAD)
            scan_id: Optional scan identifier
            detached: Use detached HEAD (no branch pollution)

        Returns:
            Dict with worktree_id, path, commit_ref, created_at
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())[:8]

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        worktree_name = f"vuln-scan-{scan_id}-{timestamp}"
        worktree_path = self.worktree_base / worktree_name

        with self._lock():
            try:
                # Create worktree
                cmd = ["git", "-C", str(self.repo_path), "worktree", "add"]

                if detached:
                    cmd.append("--detach")

                cmd.extend([str(worktree_path), commit_ref])

                result = subprocess.run(cmd, capture_output=True, text=True, check=True)

                # Register worktree
                worktree_info = {
                    "worktree_id": worktree_name,
                    "path": str(worktree_path),
                    "commit_ref": commit_ref,
                    "created_at": datetime.now().isoformat(),
                    "scan_id": scan_id,
                }

                self.registry.register(worktree_name, worktree_info)

                logger.info(f"Created worktree: {worktree_name} at {worktree_path}")
                return worktree_info

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create worktree: {e.stderr}")
                raise

    def remove_worktree(self, worktree_id: str, force: bool = False):
        """
        Remove a worktree and clean up

        Args:
            worktree_id: Worktree identifier
            force: Force removal even if dirty
        """
        worktree_info = self.registry.get(worktree_id)
        if not worktree_info:
            logger.warning(f"Worktree not found in registry: {worktree_id}")
            return

        worktree_path = Path(worktree_info["path"])

        with self._lock():
            try:
                # Remove worktree using git
                cmd = ["git", "-C", str(self.repo_path), "worktree", "remove"]

                if force:
                    cmd.append("--force")

                cmd.append(str(worktree_path))

                subprocess.run(cmd, capture_output=True, text=True, check=True)

                # Unregister
                self.registry.unregister(worktree_id)

                logger.info(f"Removed worktree: {worktree_id}")

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to remove worktree: {e.stderr}")
                # Force cleanup if directory still exists
                if worktree_path.exists():
                    import shutil

                    shutil.rmtree(worktree_path, ignore_errors=True)
                    self.registry.unregister(worktree_id)

    def list_active_worktrees(self) -> Dict[str, dict]:
        """List all active worktrees"""
        return self.registry.list_all()

    def cleanup_old_worktrees(self, max_age_hours: int = 24):
        """
        Remove worktrees older than specified age

        Args:
            max_age_hours: Maximum age in hours
        """
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        worktrees = self.list_active_worktrees()

        for worktree_id, info in worktrees.items():
            created_at = datetime.fromisoformat(info["created_at"])
            if created_at < cutoff:
                logger.info(f"Cleaning up old worktree: {worktree_id}")
                self.remove_worktree(worktree_id, force=True)

    def prune(self):
        """Prune stale worktree references"""
        try:
            subprocess.run(
                ["git", "-C", str(self.repo_path), "worktree", "prune"],
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info("Pruned stale worktree references")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to prune worktrees: {e.stderr}")


@contextmanager
def worktree_context(manager: WorktreeManager, commit_ref: str = "HEAD"):
    """Context manager for automatic worktree cleanup"""
    worktree_info = manager.create_worktree(commit_ref=commit_ref)
    try:
        yield worktree_info
    finally:
        manager.remove_worktree(worktree_info["worktree_id"], force=True)
