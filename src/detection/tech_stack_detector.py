"""Tech stack detection using multiple methods"""

import asyncio
import logging
from typing import Dict, List, Set
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
from Wappalyzer import Wappalyzer, WebPage
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class TechStackInfo:
    """Information about detected technology"""
    name: str
    version: str = ""
    category: str = ""
    confidence: float = 1.0
    detection_method: str = ""


class TechStackDetector:
    """Detect technology stack from URL using multiple methods"""

    def __init__(self):
        self.wappalyzer = Wappalyzer.latest()
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={
                "User-Agent": "Vulner-Scanner/1.0 (Security Research)"
            }
        )

    async def detect(self, url: str) -> List[TechStackInfo]:
        """
        Detect tech stack using multiple methods

        Args:
            url: Target URL to analyze

        Returns:
            List of detected technologies
        """
        logger.info(f"Detecting tech stack for: {url}")

        try:
            # Fetch the webpage
            response = await self.client.get(url)
            response.raise_for_status()

            # Run detection methods in parallel
            results = await asyncio.gather(
                self._detect_with_wappalyzer(url, response),
                self._detect_from_headers(response),
                self._detect_from_html(response.text),
                self._detect_from_meta_tags(response.text),
                return_exceptions=True
            )

            # Merge results
            technologies: Dict[str, TechStackInfo] = {}
            for method_results in results:
                if isinstance(method_results, Exception):
                    logger.warning(f"Detection method failed: {method_results}")
                    continue

                for tech in method_results:
                    if tech.name in technologies:
                        # Keep highest confidence
                        if tech.confidence > technologies[tech.name].confidence:
                            technologies[tech.name] = tech
                    else:
                        technologies[tech.name] = tech

            tech_list = list(technologies.values())
            logger.info(f"Detected {len(tech_list)} technologies")

            return tech_list

        except Exception as e:
            logger.error(f"Tech stack detection failed: {e}")
            return []

    async def _detect_with_wappalyzer(
        self,
        url: str,
        response: httpx.Response
    ) -> List[TechStackInfo]:
        """Detect using Wappalyzer library"""
        try:
            webpage = WebPage(url, response.text, response.headers)
            detected = self.wappalyzer.analyze(webpage)

            technologies = []
            for tech_name in detected:
                # Wappalyzer returns set of tech names
                technologies.append(TechStackInfo(
                    name=tech_name,
                    confidence=0.9,  # Wappalyzer is highly reliable
                    detection_method="wappalyzer"
                ))

            return technologies

        except Exception as e:
            logger.debug(f"Wappalyzer detection failed: {e}")
            return []

    async def _detect_from_headers(
        self,
        response: httpx.Response
    ) -> List[TechStackInfo]:
        """Detect from HTTP response headers"""
        technologies = []
        headers = response.headers

        # Server header
        if "server" in headers:
            server = headers["server"].lower()
            if "nginx" in server:
                technologies.append(TechStackInfo(
                    name="Nginx",
                    category="Web Server",
                    confidence=1.0,
                    detection_method="headers"
                ))
            elif "apache" in server:
                technologies.append(TechStackInfo(
                    name="Apache",
                    category="Web Server",
                    confidence=1.0,
                    detection_method="headers"
                ))
            elif "cloudflare" in server:
                technologies.append(TechStackInfo(
                    name="Cloudflare",
                    category="CDN",
                    confidence=1.0,
                    detection_method="headers"
                ))

        # X-Powered-By header
        if "x-powered-by" in headers:
            powered_by = headers["x-powered-by"].lower()
            if "php" in powered_by:
                technologies.append(TechStackInfo(
                    name="PHP",
                    category="Programming Language",
                    confidence=1.0,
                    detection_method="headers"
                ))
            elif "express" in powered_by:
                technologies.append(TechStackInfo(
                    name="Express",
                    category="Web Framework",
                    confidence=1.0,
                    detection_method="headers"
                ))

        # Framework-specific headers
        if "x-aspnet-version" in headers:
            technologies.append(TechStackInfo(
                name="ASP.NET",
                version=headers["x-aspnet-version"],
                category="Web Framework",
                confidence=1.0,
                detection_method="headers"
            ))

        return technologies

    async def _detect_from_html(self, html: str) -> List[TechStackInfo]:
        """Detect from HTML content (scripts, links)"""
        technologies = []
        soup = BeautifulSoup(html, "lxml")

        # Detect from script sources
        scripts = soup.find_all("script", src=True)
        for script in scripts:
            src = script.get("src", "").lower()

            if "react" in src:
                technologies.append(TechStackInfo(
                    name="React",
                    category="JavaScript Framework",
                    confidence=0.9,
                    detection_method="html_script"
                ))
            elif "vue" in src:
                technologies.append(TechStackInfo(
                    name="Vue.js",
                    category="JavaScript Framework",
                    confidence=0.9,
                    detection_method="html_script"
                ))
            elif "angular" in src:
                technologies.append(TechStackInfo(
                    name="Angular",
                    category="JavaScript Framework",
                    confidence=0.9,
                    detection_method="html_script"
                ))
            elif "jquery" in src:
                technologies.append(TechStackInfo(
                    name="jQuery",
                    category="JavaScript Library",
                    confidence=0.9,
                    detection_method="html_script"
                ))
            elif "bootstrap" in src:
                technologies.append(TechStackInfo(
                    name="Bootstrap",
                    category="CSS Framework",
                    confidence=0.9,
                    detection_method="html_script"
                ))

        # Detect from link tags
        links = soup.find_all("link", href=True)
        for link in links:
            href = link.get("href", "").lower()

            if "bootstrap" in href:
                technologies.append(TechStackInfo(
                    name="Bootstrap",
                    category="CSS Framework",
                    confidence=0.9,
                    detection_method="html_link"
                ))

        return technologies

    async def _detect_from_meta_tags(self, html: str) -> List[TechStackInfo]:
        """Detect from meta tags"""
        technologies = []
        soup = BeautifulSoup(html, "lxml")

        # Generator meta tag
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            content = generator.get("content", "").lower()
            if "wordpress" in content:
                technologies.append(TechStackInfo(
                    name="WordPress",
                    category="CMS",
                    confidence=1.0,
                    detection_method="meta_tag"
                ))
            elif "drupal" in content:
                technologies.append(TechStackInfo(
                    name="Drupal",
                    category="CMS",
                    confidence=1.0,
                    detection_method="meta_tag"
                ))
            elif "joomla" in content:
                technologies.append(TechStackInfo(
                    name="Joomla",
                    category="CMS",
                    confidence=1.0,
                    detection_method="meta_tag"
                ))

        return technologies

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
