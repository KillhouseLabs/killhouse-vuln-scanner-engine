"""Test tech stack detector"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from src.detection.tech_stack_detector import TechStackDetector, TechStackInfo


@pytest.fixture
def mock_response():
    """Mock httpx response"""
    response = Mock()
    response.status_code = 200
    response.text = """
    <html>
        <head>
            <meta name="generator" content="WordPress 5.8">
            <script src="https://cdn.jsdelivr.net/npm/react@17.0.2/dist/react.min.js"></script>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <h1>Test Page</h1>
        </body>
    </html>
    """
    response.headers = {
        "server": "nginx/1.20.1",
        "x-powered-by": "PHP/7.4.3"
    }
    return response


@pytest.mark.asyncio
async def test_tech_detector_init():
    """Test tech detector initialization"""
    detector = TechStackDetector()
    assert detector.wappalyzer is not None
    assert detector.client is not None
    await detector.close()


@pytest.mark.asyncio
async def test_detect_from_headers(mock_response):
    """Test detection from HTTP headers"""
    detector = TechStackDetector()

    technologies = await detector._detect_from_headers(mock_response)

    # Should detect Nginx and PHP
    tech_names = [tech.name for tech in technologies]
    assert "Nginx" in tech_names
    assert "PHP" in tech_names

    # Check categories
    for tech in technologies:
        if tech.name == "Nginx":
            assert tech.category == "Web Server"
        if tech.name == "PHP":
            assert tech.category == "Programming Language"

    await detector.close()


@pytest.mark.asyncio
async def test_detect_from_html(mock_response):
    """Test detection from HTML content"""
    detector = TechStackDetector()

    technologies = await detector._detect_from_html(mock_response.text)

    tech_names = [tech.name for tech in technologies]
    assert "React" in tech_names
    assert "Bootstrap" in tech_names

    await detector.close()


@pytest.mark.asyncio
async def test_detect_from_meta_tags(mock_response):
    """Test detection from meta tags"""
    detector = TechStackDetector()

    technologies = await detector._detect_from_meta_tags(mock_response.text)

    tech_names = [tech.name for tech in technologies]
    assert "WordPress" in tech_names

    for tech in technologies:
        if tech.name == "WordPress":
            assert tech.category == "CMS"
            assert tech.confidence == 1.0

    await detector.close()


@pytest.mark.asyncio
async def test_detect_integration(mock_response):
    """Test full detection with mocked HTTP request"""
    detector = TechStackDetector()

    # Mock the HTTP client
    with patch.object(detector.client, 'get', return_value=mock_response):
        technologies = await detector.detect("https://example.com")

        # Should detect multiple technologies
        assert len(technologies) > 0

        tech_names = [tech.name for tech in technologies]
        # At least some common technologies should be detected
        assert any(name in tech_names for name in ["Nginx", "PHP", "React", "Bootstrap", "WordPress"])

    await detector.close()


@pytest.mark.asyncio
async def test_context_manager():
    """Test context manager usage"""
    async with TechStackDetector() as detector:
        assert detector.client is not None

    # Client should be closed after context


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
