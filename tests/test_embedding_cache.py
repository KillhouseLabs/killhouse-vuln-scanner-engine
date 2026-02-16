"""Test embedding cache"""

import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.database.embedding_cache import EmbeddingCache


@pytest.fixture
def temp_cache_dir():
    """Create temporary cache directory"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response"""
    mock_response = AsyncMock()
    mock_response.data = [
        AsyncMock(embedding=[0.1, 0.2, 0.3] + [0.0] * 1533)  # 1536 dimensions
    ]
    return mock_response


@pytest.mark.asyncio
async def test_embedding_cache_init(temp_cache_dir):
    """Test embedding cache initialization"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    assert cache.cache_dir == temp_cache_dir
    assert temp_cache_dir.exists()
    assert cache.model == "text-embedding-3-small"


@pytest.mark.asyncio
async def test_get_embedding_with_api_call(temp_cache_dir, mock_openai_response):
    """Test getting embedding with API call"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    with patch.object(cache.openai.embeddings, "create", return_value=mock_openai_response):
        embedding = await cache.get_embedding("test text")

        assert len(embedding) == 1536
        assert cache.stats["api_calls"] == 1
        assert cache.stats["misses"] == 1
        assert cache.stats["hits"] == 0


@pytest.mark.asyncio
async def test_get_embedding_with_cache_hit(temp_cache_dir, mock_openai_response):
    """Test getting embedding with cache hit"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    with patch.object(cache.openai.embeddings, "create", return_value=mock_openai_response):
        # First call - API call
        embedding1 = await cache.get_embedding("test text")
        assert cache.stats["api_calls"] == 1
        assert cache.stats["misses"] == 1

        # Second call - cache hit
        embedding2 = await cache.get_embedding("test text")
        assert cache.stats["api_calls"] == 1  # No additional API call
        assert cache.stats["hits"] == 1

        # Embeddings should be identical
        assert embedding1 == embedding2


@pytest.mark.asyncio
async def test_batch_get_embeddings(temp_cache_dir):
    """Test batch embedding retrieval"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    texts = ["text1", "text2", "text3"]

    # Mock batch response with 3 embeddings
    mock_batch_response = AsyncMock()
    mock_batch_response.data = [
        AsyncMock(embedding=[0.1, 0.2, 0.3] + [0.0] * 1533),  # text1
        AsyncMock(embedding=[0.4, 0.5, 0.6] + [0.0] * 1533),  # text2
        AsyncMock(embedding=[0.7, 0.8, 0.9] + [0.0] * 1533),  # text3
    ]

    with patch.object(cache.openai.embeddings, "create", return_value=mock_batch_response):
        embeddings = await cache.batch_get_embeddings(texts)

        assert len(embeddings) == 3
        assert all(len(emb) == 1536 for emb in embeddings)


@pytest.mark.asyncio
async def test_cache_key_generation(temp_cache_dir):
    """Test cache key generation"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    key1 = cache._get_cache_key("test text")
    key2 = cache._get_cache_key("test text")
    key3 = cache._get_cache_key("different text")

    # Same text should produce same key
    assert key1 == key2

    # Different text should produce different key
    assert key1 != key3


@pytest.mark.asyncio
async def test_clear_cache(temp_cache_dir, mock_openai_response):
    """Test cache clearing"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    with patch.object(cache.openai.embeddings, "create", return_value=mock_openai_response):
        # Create some cache entries
        await cache.get_embedding("text1")
        await cache.get_embedding("text2")

        # Verify cache files exist
        cache_files = list(temp_cache_dir.rglob("*.json"))
        assert len(cache_files) == 2

        # Clear cache
        cache.clear_cache()

        # Verify cache files are deleted
        cache_files = list(temp_cache_dir.rglob("*.json"))
        assert len(cache_files) == 0

        # Memory cache should be cleared
        assert len(cache._memory_cache) == 0


@pytest.mark.asyncio
async def test_get_stats(temp_cache_dir, mock_openai_response):
    """Test cache statistics"""
    cache = EmbeddingCache(openai_api_key="test-key", cache_dir=temp_cache_dir)

    with patch.object(cache.openai.embeddings, "create", return_value=mock_openai_response):
        # First call
        await cache.get_embedding("test1")
        # Second call (cache hit)
        await cache.get_embedding("test1")
        # Third call (new text)
        await cache.get_embedding("test2")

        stats = cache.get_stats()

        assert stats["total_requests"] == 3
        assert stats["hits"] == 1
        assert stats["misses"] == 2
        assert stats["api_calls"] == 2
        assert "hit_rate_percent" in stats
        assert "cache_size_mb" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
