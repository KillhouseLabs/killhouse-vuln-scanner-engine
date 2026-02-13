"""LLM-based vulnerability validation engine"""

import logging
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from openai import AsyncOpenAI
from datetime import datetime

from .state_machine import ValidationHypothesis, ValidationAction

logger = logging.getLogger(__name__)


class LLMVulnerabilityValidator:
    """
    LLM-based validator for vulnerability hypotheses

    Uses AI to intelligently assess whether detected vulnerabilities
    are actually exploitable in the target context
    """

    def __init__(
        self,
        openai_api_key: str,
        model: str = "gpt-4o-mini",
        cache_dir: Path = Path(".cache/llm_validation")
    ):
        """
        Initialize LLM validator

        Args:
            openai_api_key: OpenAI API key
            model: Model to use (default: gpt-4o-mini for cost efficiency)
            cache_dir: Directory for caching validation results
        """
        self.client = AsyncOpenAI(api_key=openai_api_key)
        self.model = model
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initialized LLMVulnerabilityValidator with model {model}")

    def _get_cache_path(self, hypothesis: ValidationHypothesis) -> Path:
        """Get cache file path for a hypothesis"""
        cache_key = f"{hypothesis.vulnerability_id}_{hash(hypothesis.hypothesis)}"
        return self.cache_dir / f"{cache_key}.json"

    def _load_from_cache(self, hypothesis: ValidationHypothesis) -> Optional[Dict]:
        """Load validation result from cache"""
        cache_path = self._get_cache_path(hypothesis)

        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                    logger.debug(f"Loaded validation from cache: {hypothesis.vulnerability_id}")
                    return cached
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        return None

    def _save_to_cache(self, hypothesis: ValidationHypothesis, result: Dict):
        """Save validation result to cache"""
        cache_path = self._get_cache_path(hypothesis)

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
                logger.debug(f"Saved validation to cache: {hypothesis.vulnerability_id}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    async def validate_hypothesis(
        self,
        hypothesis: ValidationHypothesis,
        tech_stack: Dict,
        target_url: str,
        use_cache: bool = True
    ) -> Dict:
        """
        Validate a single vulnerability hypothesis using LLM

        Args:
            hypothesis: Hypothesis to validate
            tech_stack: Technology stack information
            target_url: Target URL
            use_cache: Whether to use cached results

        Returns:
            Dict with validation results:
            {
                "vulnerability_id": str,
                "is_exploitable": bool,
                "confidence": float (0.0-1.0),
                "reasoning": str,
                "attack_vectors": List[str],
                "prerequisites": List[str],
                "impact_assessment": str,
                "recommended_actions": List[str],
                "validation_metadata": Dict
            }
        """
        # Check cache first
        if use_cache:
            cached = self._load_from_cache(hypothesis)
            if cached:
                return cached

        # Prepare prompt for LLM
        prompt = f"""You are a cybersecurity expert analyzing a potential vulnerability.

Target Information:
- URL: {target_url}
- Technology Stack: {json.dumps(tech_stack, indent=2)}

Hypothesis:
- Vulnerability ID: {hypothesis.vulnerability_id}
- Hypothesis: {hypothesis.hypothesis}
- Initial Confidence: {hypothesis.confidence}
- Evidence: {json.dumps(hypothesis.evidence, indent=2)}
- Validation Plan: {json.dumps(hypothesis.validation_plan, indent=2)}

Your task is to analyze this hypothesis and determine:
1. Whether this vulnerability is actually exploitable in this specific context
2. What attack vectors could be used
3. What prerequisites are needed for exploitation
4. The potential impact if exploited
5. Recommended security actions

Consider:
- The specific technology versions in the stack
- The deployment context (containerized environment)
- The likelihood of successful exploitation
- Whether the vulnerability is theoretical or practical

Provide your analysis in JSON format with the following structure:
{{
    "is_exploitable": true/false,
    "confidence": 0.0-1.0 (your confidence in this assessment),
    "reasoning": "Detailed explanation of your analysis",
    "attack_vectors": ["vector1", "vector2", ...],
    "prerequisites": ["prereq1", "prereq2", ...],
    "impact_assessment": "Description of potential impact",
    "recommended_actions": ["action1", "action2", ...]
}}

Be specific, practical, and consider real-world exploitability."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in vulnerability assessment and validation. Provide accurate, practical analysis based on real-world exploitability."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.3  # Lower temperature for more consistent analysis
            )

            # Parse response
            analysis = json.loads(response.choices[0].message.content)

            # Build result
            result = {
                "vulnerability_id": hypothesis.vulnerability_id,
                "is_exploitable": analysis.get("is_exploitable", False),
                "confidence": analysis.get("confidence", hypothesis.confidence),
                "reasoning": analysis.get("reasoning", ""),
                "attack_vectors": analysis.get("attack_vectors", []),
                "prerequisites": analysis.get("prerequisites", []),
                "impact_assessment": analysis.get("impact_assessment", ""),
                "recommended_actions": analysis.get("recommended_actions", []),
                "validation_metadata": {
                    "model": self.model,
                    "timestamp": datetime.now().isoformat(),
                    "tokens_used": response.usage.total_tokens,
                    "original_hypothesis": hypothesis.hypothesis,
                    "original_confidence": hypothesis.confidence
                }
            }

            # Cache result
            if use_cache:
                self._save_to_cache(hypothesis, result)

            logger.info(
                f"Validated {hypothesis.vulnerability_id}: "
                f"exploitable={result['is_exploitable']}, "
                f"confidence={result['confidence']:.2f}"
            )

            return result

        except Exception as e:
            logger.error(f"Failed to validate hypothesis {hypothesis.vulnerability_id}: {e}")

            # Return fallback result
            return {
                "vulnerability_id": hypothesis.vulnerability_id,
                "is_exploitable": False,
                "confidence": 0.0,
                "reasoning": f"Validation failed: {str(e)}",
                "attack_vectors": [],
                "prerequisites": [],
                "impact_assessment": "Unable to assess",
                "recommended_actions": ["Manual review required"],
                "validation_metadata": {
                    "model": self.model,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                }
            }

    async def validate_hypotheses(
        self,
        hypotheses: List[ValidationHypothesis],
        tech_stack: Dict,
        target_url: str,
        max_concurrent: int = 3,
        use_cache: bool = True
    ) -> List[Dict]:
        """
        Validate multiple hypotheses with concurrency control

        Args:
            hypotheses: List of hypotheses to validate
            tech_stack: Technology stack information
            target_url: Target URL
            max_concurrent: Maximum concurrent API calls
            use_cache: Whether to use cached results

        Returns:
            List of validation results
        """
        import asyncio

        results = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def validate_with_semaphore(hypothesis: ValidationHypothesis):
            async with semaphore:
                return await self.validate_hypothesis(
                    hypothesis,
                    tech_stack,
                    target_url,
                    use_cache
                )

        # Process all hypotheses
        tasks = [
            validate_with_semaphore(hypothesis)
            for hypothesis in hypotheses
        ]

        results = await asyncio.gather(*tasks)

        logger.info(f"Validated {len(results)} hypotheses")

        return results

    async def refine_hypothesis(
        self,
        hypothesis: ValidationHypothesis,
        validation_result: Dict,
        action_results: List[ValidationAction]
    ) -> ValidationHypothesis:
        """
        Refine a hypothesis based on validation and action results

        Args:
            hypothesis: Original hypothesis
            validation_result: LLM validation result
            action_results: Results from validation actions

        Returns:
            Refined hypothesis with updated confidence and evidence
        """
        # Collect evidence from action results
        new_evidence = list(hypothesis.evidence)

        for action in action_results:
            if action.success and action.actual_result:
                new_evidence.append(f"Action {action.action_type}: {action.actual_result}")

        # Update confidence based on validation and actions
        new_confidence = validation_result["confidence"]

        # Adjust confidence based on successful actions
        successful_actions = sum(1 for a in action_results if a.success)
        if successful_actions > 0:
            confidence_boost = min(0.2, successful_actions * 0.05)
            new_confidence = min(1.0, new_confidence + confidence_boost)

        # Create refined hypothesis
        refined = ValidationHypothesis(
            vulnerability_id=hypothesis.vulnerability_id,
            hypothesis=f"{hypothesis.hypothesis} [Refined: {validation_result['reasoning'][:100]}...]",
            confidence=new_confidence,
            evidence=new_evidence,
            validation_plan=hypothesis.validation_plan,
            created_at=hypothesis.created_at
        )

        logger.info(
            f"Refined hypothesis {hypothesis.vulnerability_id}: "
            f"confidence {hypothesis.confidence:.2f} -> {new_confidence:.2f}"
        )

        return refined

    async def generate_validation_report(
        self,
        hypotheses: List[ValidationHypothesis],
        validation_results: List[Dict],
        tech_stack: Dict,
        target_url: str
    ) -> Dict:
        """
        Generate comprehensive validation report

        Args:
            hypotheses: List of hypotheses
            validation_results: List of validation results
            tech_stack: Technology stack
            target_url: Target URL

        Returns:
            Comprehensive validation report
        """
        # Calculate statistics
        total = len(validation_results)
        exploitable = sum(1 for r in validation_results if r["is_exploitable"])
        high_confidence = sum(
            1 for r in validation_results
            if r["is_exploitable"] and r["confidence"] >= 0.7
        )

        # Collect all attack vectors
        all_vectors = []
        for result in validation_results:
            if result["is_exploitable"]:
                all_vectors.extend(result["attack_vectors"])

        unique_vectors = list(set(all_vectors))

        # Collect all recommendations
        all_recommendations = []
        for result in validation_results:
            if result["is_exploitable"]:
                all_recommendations.extend(result["recommended_actions"])

        unique_recommendations = list(set(all_recommendations))

        report = {
            "summary": {
                "target_url": target_url,
                "total_hypotheses": total,
                "exploitable_count": exploitable,
                "high_confidence_count": high_confidence,
                "validation_rate": f"{(exploitable/total*100):.1f}%" if total > 0 else "0%"
            },
            "tech_stack": tech_stack,
            "exploitable_vulnerabilities": [
                {
                    "vulnerability_id": r["vulnerability_id"],
                    "confidence": r["confidence"],
                    "impact": r["impact_assessment"],
                    "attack_vectors": r["attack_vectors"]
                }
                for r in validation_results
                if r["is_exploitable"]
            ],
            "attack_surface": {
                "unique_vectors": unique_vectors,
                "vector_count": len(unique_vectors)
            },
            "recommendations": {
                "priority_actions": unique_recommendations[:10],  # Top 10
                "total_recommendations": len(unique_recommendations)
            },
            "detailed_results": validation_results,
            "generated_at": datetime.now().isoformat()
        }

        logger.info(
            f"Generated validation report: "
            f"{exploitable}/{total} exploitable vulnerabilities"
        )

        return report
