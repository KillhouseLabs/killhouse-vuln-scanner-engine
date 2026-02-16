"""Test vulnerability database"""

from unittest.mock import Mock, patch

import pytest

from src.vulnerability.vuln_database import VulnerabilityDatabase


@pytest.fixture
def mock_osv_response():
    """Mock OSV.dev API response"""
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "XSS vulnerability in React",
                "details": "Cross-site scripting vulnerability in React versions < 17.0.2",
                "severity": [{"type": "CVSS_V3", "score": 7.5}],
                "affected": [
                    {"ranges": [{"events": [{"introduced": "16.0.0"}, {"fixed": "17.0.2"}]}]}
                ],
                "references": [{"url": "https://example.com/advisory"}],
                "published": "2021-03-15T00:00:00Z",
            }
        ]
    }


@pytest.mark.asyncio
async def test_vuln_database_init():
    """Test vulnerability database initialization"""
    db = VulnerabilityDatabase()
    assert db.osv_client is not None
    await db.close()


@pytest.mark.asyncio
async def test_parse_osv_vulnerability():
    """Test parsing OSV vulnerability data"""
    db = VulnerabilityDatabase()

    vuln_data = {
        "id": "GHSA-test-1234-abcd",
        "summary": "Test Vulnerability",
        "details": "This is a test vulnerability",
        "severity": [{"type": "CVSS_V3", "score": 8.5}],
        "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}]}],
        "references": [{"url": "https://example.com"}],
        "published": "2023-01-01T00:00:00Z",
    }

    vuln = db._parse_osv_vulnerability(vuln_data)

    assert vuln is not None
    assert vuln.id == "GHSA-test-1234-abcd"
    assert vuln.title == "Test Vulnerability"
    assert vuln.severity == "HIGH"
    assert vuln.cvss_score == 8.5
    assert "1.0.0" in vuln.affected_versions
    assert "1.2.0" in vuln.fixed_versions
    assert vuln.source == "osv"

    await db.close()


@pytest.mark.asyncio
async def test_query_vulnerabilities_with_cache(mock_osv_response):
    """Test vulnerability query with caching"""
    db = VulnerabilityDatabase()

    # Mock OSV API response
    with patch.object(db.osv_client, "post") as mock_post:
        mock_response = Mock()  # Use Mock, not AsyncMock
        mock_response.json.return_value = mock_osv_response
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        # First query - should hit API
        vulns1 = await db.query_vulnerabilities("react", version="16.0.0", ecosystem="npm")
        assert len(vulns1) > 0
        assert mock_post.call_count == 1

        # Second query with same params - should use cache
        vulns2 = await db.query_vulnerabilities("react", version="16.0.0", ecosystem="npm")
        assert len(vulns2) > 0
        assert mock_post.call_count == 1  # No additional API call

        # Verify results are the same
        assert vulns1[0].id == vulns2[0].id

    await db.close()


@pytest.mark.asyncio
async def test_query_osv(mock_osv_response):
    """Test OSV.dev API query"""
    db = VulnerabilityDatabase()

    with patch.object(db.osv_client, "post") as mock_post:
        mock_response = Mock()  # Use Mock, not AsyncMock
        mock_response.json.return_value = mock_osv_response
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        vulns = await db._query_osv("react", "16.0.0", "npm")

        assert len(vulns) == 1
        assert vulns[0].id == "GHSA-xxxx-yyyy-zzzz"
        assert vulns[0].severity == "HIGH"
        assert vulns[0].cvss_score == 7.5

    await db.close()


@pytest.mark.asyncio
async def test_context_manager():
    """Test context manager usage"""
    async with VulnerabilityDatabase() as db:
        assert db.osv_client is not None

    # Client should be closed after context


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
