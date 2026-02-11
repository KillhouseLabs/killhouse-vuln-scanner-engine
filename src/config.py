"""Configuration management for Vulner platform"""

from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # OpenAI
    openai_api_key: str

    # Supabase (optional for core testing)
    supabase_url: Optional[str] = None
    supabase_key: Optional[str] = None

    # Worktree
    worktree_base_dir: Path = Path("/tmp/vulner-worktrees")
    worktree_max_age_hours: int = 24

    # Container
    container_runtime: str = "podman"  # or "docker"
    container_cpu_limit: float = 0.5
    container_memory_limit: str = "512m"
    container_pids_limit: int = 100

    # Security
    max_concurrent_scans: int = 5
    rate_limit_per_min: int = 10

    # Database
    database_path: Path = Path("./vulner.db")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
