"""OpenAI embedding client with local caching"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


class EmbeddingCache:
    """OpenAI embedding client with file-based caching"""

    def __init__(
        self,
        openai_api_key: str,
        cache_dir: Path = Path(".cache/embeddings"),
        cache_ttl_days: int = 30,
        model: str = "text-embedding-3-small",
    ):
        """
        Initialize embedding cache

        Args:
            openai_api_key: OpenAI API key
            cache_dir: Directory for cache files
            cache_ttl_days: Cache time-to-live in days
            model: OpenAI embedding model
        """
        self.openai = AsyncOpenAI(api_key=openai_api_key)
        self.model = model
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(days=cache_ttl_days)

        # In-memory cache for this session
        self._memory_cache: Dict[str, List[float]] = {}

        # Stats
        self.stats = {"hits": 0, "misses": 0, "api_calls": 0}

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key from text"""
        return hashlib.sha256(text.encode()).hexdigest()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path"""
        # Split into subdirectories for better filesystem performance
        return self.cache_dir / cache_key[:2] / f"{cache_key}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_path.exists():
            return False

        try:
            cache_data = json.loads(cache_path.read_text())
            created_at = datetime.fromisoformat(cache_data["created_at"])
            return datetime.now() - created_at < self.cache_ttl
        except Exception:
            return False

    async def get_embedding(self, text: str) -> List[float]:
        """
        Get embedding for text with caching

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        cache_key = self._get_cache_key(text)

        # Check memory cache
        if cache_key in self._memory_cache:
            self.stats["hits"] += 1
            logger.debug("Memory cache hit")
            return self._memory_cache[cache_key]

        # Check file cache
        cache_path = self._get_cache_path(cache_key)
        if self._is_cache_valid(cache_path):
            try:
                cache_data = json.loads(cache_path.read_text())
                embedding = cache_data["embedding"]
                self._memory_cache[cache_key] = embedding
                self.stats["hits"] += 1
                logger.debug("File cache hit")
                return embedding
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        # Cache miss - call OpenAI API
        self.stats["misses"] += 1
        self.stats["api_calls"] += 1
        logger.debug("Cache miss - calling OpenAI API")

        try:
            response = await self.openai.embeddings.create(model=self.model, input=text)
            embedding = response.data[0].embedding

            # Store in memory cache
            self._memory_cache[cache_key] = embedding

            # Store in file cache
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_data = {
                "text_preview": text[:100],  # For debugging
                "embedding": embedding,
                "model": self.model,
                "created_at": datetime.now().isoformat(),
            }
            cache_path.write_text(json.dumps(cache_data))

            logger.info(f"Created embedding and cached (key: {cache_key[:8]}...)")
            return embedding

        except Exception as e:
            logger.error(f"Failed to create embedding: {e}")
            raise

    async def batch_get_embeddings(
        self, texts: List[str], batch_size: int = 100
    ) -> List[List[float]]:
        """
        Get embeddings for multiple texts with batching

        Args:
            texts: List of texts to embed
            batch_size: Maximum batch size for API call

        Returns:
            List of embedding vectors
        """
        embeddings = []

        # Separate cached and uncached texts
        uncached_texts = []
        uncached_indices = []

        for i, text in enumerate(texts):
            cache_key = self._get_cache_key(text)

            # Check memory cache
            if cache_key in self._memory_cache:
                embeddings.append(self._memory_cache[cache_key])
                continue

            # Check file cache
            cache_path = self._get_cache_path(cache_key)
            if self._is_cache_valid(cache_path):
                try:
                    cache_data = json.loads(cache_path.read_text())
                    embedding = cache_data["embedding"]
                    self._memory_cache[cache_key] = embedding
                    embeddings.append(embedding)
                    self.stats["hits"] += 1
                    continue
                except Exception:
                    pass

            # Need to fetch from API
            uncached_texts.append(text)
            uncached_indices.append(i)
            embeddings.append(None)  # Placeholder

        # Batch process uncached texts
        if uncached_texts:
            self.stats["misses"] += len(uncached_texts)
            logger.info(f"Fetching {len(uncached_texts)} uncached embeddings")

            # Process in batches
            for batch_start in range(0, len(uncached_texts), batch_size):
                batch = uncached_texts[batch_start : batch_start + batch_size]
                batch_indices = uncached_indices[batch_start : batch_start + batch_size]

                try:
                    response = await self.openai.embeddings.create(model=self.model, input=batch)
                    self.stats["api_calls"] += 1

                    # Store embeddings
                    for i, data in enumerate(response.data):
                        embedding = data.embedding
                        text = batch[i]
                        original_idx = batch_indices[i]

                        # Store in memory cache
                        cache_key = self._get_cache_key(text)
                        self._memory_cache[cache_key] = embedding

                        # Store in file cache
                        cache_path = self._get_cache_path(cache_key)
                        cache_path.parent.mkdir(parents=True, exist_ok=True)
                        cache_data = {
                            "text_preview": text[:100],
                            "embedding": embedding,
                            "model": self.model,
                            "created_at": datetime.now().isoformat(),
                        }
                        cache_path.write_text(json.dumps(cache_data))

                        # Update result list
                        embeddings[original_idx] = embedding

                except Exception as e:
                    logger.error(f"Batch embedding failed: {e}")
                    raise

        return embeddings

    def clear_cache(self, older_than_days: Optional[int] = None):
        """
        Clear cache files

        Args:
            older_than_days: Only clear files older than N days
        """
        cleared = 0
        cutoff = None

        if older_than_days:
            cutoff = datetime.now() - timedelta(days=older_than_days)

        for cache_file in self.cache_dir.rglob("*.json"):
            try:
                if cutoff:
                    cache_data = json.loads(cache_file.read_text())
                    created_at = datetime.fromisoformat(cache_data["created_at"])
                    if created_at > cutoff:
                        continue

                cache_file.unlink()
                cleared += 1

            except Exception as e:
                logger.warning(f"Failed to clear cache file: {e}")

        logger.info(f"Cleared {cleared} cache files")

        # Clear memory cache
        self._memory_cache.clear()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests * 100 if total_requests > 0 else 0

        return {
            **self.stats,
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2),
            "cache_size_mb": sum(f.stat().st_size for f in self.cache_dir.rglob("*.json"))
            / (1024 * 1024),
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
