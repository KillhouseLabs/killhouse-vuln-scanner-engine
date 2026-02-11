"""Test git worktree manager"""

import pytest
import tempfile
import shutil
from pathlib import Path
import subprocess

from src.worktree.manager import WorktreeManager, worktree_context


@pytest.fixture
def temp_repo():
    """Create temporary git repository for testing"""
    temp_dir = tempfile.mkdtemp()
    repo_path = Path(temp_dir) / "test_repo"
    repo_path.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        check=True
    )

    # Create initial commit
    test_file = repo_path / "test.txt"
    test_file.write_text("test content")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        check=True
    )

    yield repo_path

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_create_worktree(temp_repo):
    """Test worktree creation"""
    manager = WorktreeManager(str(temp_repo))

    worktree_info = manager.create_worktree(commit_ref="HEAD", scan_id="test123")

    assert worktree_info["scan_id"] == "test123"
    assert "worktree_id" in worktree_info
    assert Path(worktree_info["path"]).exists()

    # Cleanup
    manager.remove_worktree(worktree_info["worktree_id"], force=True)


def test_remove_worktree(temp_repo):
    """Test worktree removal"""
    manager = WorktreeManager(str(temp_repo))

    worktree_info = manager.create_worktree()
    worktree_path = Path(worktree_info["path"])

    assert worktree_path.exists()

    manager.remove_worktree(worktree_info["worktree_id"], force=True)

    assert not worktree_path.exists()


def test_list_worktrees(temp_repo):
    """Test listing worktrees"""
    manager = WorktreeManager(str(temp_repo))

    # Create multiple worktrees
    wt1 = manager.create_worktree(scan_id="scan1")
    wt2 = manager.create_worktree(scan_id="scan2")

    worktrees = manager.list_active_worktrees()

    assert len(worktrees) == 2
    assert wt1["worktree_id"] in worktrees
    assert wt2["worktree_id"] in worktrees

    # Cleanup
    manager.remove_worktree(wt1["worktree_id"], force=True)
    manager.remove_worktree(wt2["worktree_id"], force=True)


def test_worktree_context(temp_repo):
    """Test worktree context manager"""
    manager = WorktreeManager(str(temp_repo))

    with worktree_context(manager, "HEAD") as worktree_info:
        worktree_path = Path(worktree_info["path"])
        assert worktree_path.exists()

        # Verify we can read files
        test_file = worktree_path / "test.txt"
        assert test_file.exists()
        assert test_file.read_text() == "test content"

    # Verify cleanup happened
    assert not worktree_path.exists()


def test_cleanup_old_worktrees(temp_repo):
    """Test cleanup of old worktrees"""
    import time
    from datetime import datetime, timedelta

    manager = WorktreeManager(str(temp_repo))

    # Create worktree and manually modify its timestamp
    wt = manager.create_worktree()

    # Modify registry to make it look old
    registry_data = manager.registry._load()
    old_time = (datetime.now() - timedelta(hours=25)).isoformat()
    registry_data[wt["worktree_id"]]["created_at"] = old_time
    manager.registry._save(registry_data)

    # Run cleanup
    manager.cleanup_old_worktrees(max_age_hours=24)

    # Verify worktree was removed
    worktrees = manager.list_active_worktrees()
    assert wt["worktree_id"] not in worktrees


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
