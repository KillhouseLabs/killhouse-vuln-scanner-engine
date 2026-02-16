"""Integration tests for Phase 3 components"""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.feedback.llm_validator import LLMVulnerabilityValidator
from src.feedback.persistence import FeedbackLoopPersistence
from src.feedback.state_machine import (
    FeedbackLoopStateMachine,
    State,
    ValidationHypothesis,
)
from src.policy.engine import ActionType, ExecutionContext, PolicyEngine


class TestPolicyEngine:
    """Test policy engine functionality"""

    def test_policy_engine_initialization(self):
        """Test policy engine initializes with default policies"""
        engine = PolicyEngine()

        assert engine.jwt_secret is not None
        assert ActionType.SCAN in engine.policies
        assert ActionType.EXPLOIT in engine.policies
        assert ActionType.DELETE in engine.policies

    def test_scan_action_allowed_by_default(self):
        """Test scan action is allowed without authorization"""
        engine = PolicyEngine()
        context = ExecutionContext(target_url="https://example.com", user_id="test_user")

        allowed, reason = engine.check_permission(ActionType.SCAN, context)

        assert allowed is True
        assert "allowed" in reason.lower()

    def test_exploit_action_denied_without_token(self):
        """Test exploit action is denied without authorization token"""
        engine = PolicyEngine()
        context = ExecutionContext(target_url="https://example.com", user_id="test_user")

        allowed, reason = engine.check_permission(ActionType.EXPLOIT, context)

        assert allowed is False
        assert "authorization" in reason.lower() or "denied" in reason.lower()

    def test_exploit_action_allowed_with_valid_token(self):
        """Test exploit action is allowed with valid JWT token"""
        engine = PolicyEngine()

        # Generate token with exploit permission
        token = engine.generate_token(
            user_id="test_user", permissions=["exploit"], expires_in_hours=1
        )

        context = ExecutionContext(
            target_url="https://example.com", user_id="test_user", authorization_token=token
        )

        allowed, reason = engine.check_permission(ActionType.EXPLOIT, context)

        assert allowed is True

    def test_token_validation(self):
        """Test JWT token validation"""
        engine = PolicyEngine()

        # Generate valid token
        token = engine.generate_token(user_id="test_user", permissions=["scan", "exploit"])

        # Validate token
        payload = engine.validate_token(token)

        assert payload["user_id"] == "test_user"
        assert "scan" in payload["permissions"]
        assert "exploit" in payload["permissions"]

    def test_denied_actions_logging(self):
        """Test denied actions are logged"""
        engine = PolicyEngine()
        context = ExecutionContext(target_url="https://example.com", user_id="test_user")

        # Attempt denied action
        engine.check_permission(ActionType.EXPLOIT, context)

        denied = engine.get_denied_actions()
        assert len(denied) > 0
        assert denied[0]["action"] == "exploit"


class TestFeedbackLoopStateMachine:
    """Test feedback loop state machine"""

    def test_state_machine_initialization(self):
        """Test state machine initializes in IDLE state"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        assert sm.current_state == State.IDLE
        assert sm.scan_id == "test-scan"
        assert len(sm.observations) == 0
        assert len(sm.hypotheses) == 0

    def test_observe_transition(self):
        """Test IDLE -> OBSERVING -> ORIENTING transition"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        vulnerabilities = [
            {"id": "CVE-2024-0001", "severity": "HIGH"},
            {"id": "CVE-2024-0002", "severity": "MEDIUM"},
        ]

        sm.observe(
            vulnerabilities=vulnerabilities,
            tech_stack={"technologies": {}},
            target_url="https://example.com",
        )

        # Should auto-transition to ORIENTING
        assert sm.current_state == State.ORIENTING
        assert len(sm.observations) == 1
        assert sm.metrics.observations_made == 1

    def test_orient_analyzes_vulnerabilities(self):
        """Test ORIENTING state analyzes vulnerabilities"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup observation
        vulnerabilities = [
            {"id": "CVE-2024-0001", "severity": "CRITICAL"},
            {"id": "CVE-2024-0002", "severity": "HIGH"},
            {"id": "CVE-2024-0003", "severity": "MEDIUM"},
        ]

        sm.observe(vulnerabilities, {}, "https://example.com")

        # Orient
        analysis = sm.orient()

        assert sm.current_state == State.HYPOTHESIZING
        assert analysis["total_vulnerabilities"] == 3
        assert analysis["high_priority_count"] == 2

    def test_hypothesize_generates_hypotheses(self):
        """Test HYPOTHESIZING state generates hypotheses"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup
        vulnerabilities = [
            {
                "id": "CVE-2024-0001",
                "severity": "CRITICAL",
                "cvss_score": 9.5,
                "description": "Critical vulnerability",
            }
        ]

        sm.observe(vulnerabilities, {}, "https://example.com")
        sm.orient()

        # Hypothesize
        hypotheses = sm.hypothesize()

        assert sm.current_state == State.DECIDING
        assert len(hypotheses) > 0
        assert hypotheses[0].vulnerability_id == "CVE-2024-0001"
        assert 0.0 <= hypotheses[0].confidence <= 1.0

    def test_decide_plans_actions(self):
        """Test DECIDING state plans validation actions"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup through hypothesize
        vulnerabilities = [{"id": "CVE-2024-0001", "severity": "HIGH"}]
        sm.observe(vulnerabilities, {}, "https://example.com")
        sm.orient()
        sm.hypothesize()

        # Decide
        actions = sm.decide()

        assert sm.current_state == State.ACTING
        assert len(actions) > 0
        assert actions[0].action_type == "verify"

    @pytest.mark.asyncio
    async def test_act_executes_actions(self):
        """Test ACTING state executes actions"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup through decide
        vulnerabilities = [{"id": "CVE-2024-0001", "severity": "HIGH"}]
        sm.observe(vulnerabilities, {}, "https://example.com")
        sm.orient()
        sm.hypothesize()
        sm.decide()

        # Act
        executed = await sm.act()

        assert sm.current_state == State.VALIDATING
        assert len(executed) > 0
        assert executed[0].executed_at is not None

    def test_validate_verifies_hypotheses(self):
        """Test VALIDATING state verifies hypotheses"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup through act
        vulnerabilities = [{"id": "CVE-2024-0001", "severity": "HIGH", "cvss_score": 8.0}]
        sm.observe(vulnerabilities, {}, "https://example.com")
        sm.orient()
        sm.hypothesize()
        sm.decide()
        asyncio.run(sm.act())

        # Validate
        validations = sm.validate()

        assert sm.current_state == State.REPORTING
        assert len(validations) > 0

    def test_report_generates_summary(self):
        """Test REPORTING state generates report"""
        sm = FeedbackLoopStateMachine(scan_id="test-scan")

        # Setup through validate
        vulnerabilities = [{"id": "CVE-2024-0001", "severity": "HIGH", "cvss_score": 8.0}]
        sm.observe(vulnerabilities, {}, "https://example.com")
        sm.orient()
        sm.hypothesize()
        sm.decide()
        asyncio.run(sm.act())
        sm.validate()

        # Report
        report = sm.report()

        assert sm.current_state == State.IDLE  # Back to idle
        assert report["scan_id"] == "test-scan"
        assert "metrics" in report
        assert "validated_vulnerabilities" in report


class TestFeedbackLoopPersistence:
    """Test feedback loop persistence"""

    def test_persistence_initialization(self, tmp_path):
        """Test persistence layer initializes database"""
        db_path = tmp_path / "test_feedback.db"
        persistence = FeedbackLoopPersistence(db_path=db_path)

        assert db_path.exists()

    def test_create_session(self, tmp_path):
        """Test creating scan session"""
        db_path = tmp_path / "test_feedback.db"
        persistence = FeedbackLoopPersistence(db_path=db_path)

        success = persistence.create_session(
            scan_id="test-scan", target_url="https://example.com", metadata={"test": "data"}
        )

        assert success is True

        # Verify session exists
        session = persistence.get_session("test-scan")
        assert session is not None
        assert session["scan_id"] == "test-scan"
        assert session["target_url"] == "https://example.com"

    def test_add_observation(self, tmp_path):
        """Test adding observation"""
        db_path = tmp_path / "test_feedback.db"
        persistence = FeedbackLoopPersistence(db_path=db_path)

        persistence.create_session("test-scan", "https://example.com")
        persistence.add_observation(scan_id="test-scan", observation_data={"vuln_count": 5})

        metrics = persistence.get_metrics("test-scan")
        assert metrics["observations_made"] == 1

    def test_add_hypothesis(self, tmp_path):
        """Test adding hypothesis"""
        db_path = tmp_path / "test_feedback.db"
        persistence = FeedbackLoopPersistence(db_path=db_path)

        persistence.create_session("test-scan", "https://example.com")
        persistence.add_hypothesis(
            scan_id="test-scan",
            vulnerability_id="CVE-2024-0001",
            hypothesis="Test hypothesis",
            confidence=0.8,
            evidence=["evidence1", "evidence2"],
            validation_plan=["step1", "step2"],
        )

        metrics = persistence.get_metrics("test-scan")
        assert metrics["hypotheses_generated"] == 1

    def test_complete_session(self, tmp_path):
        """Test completing session"""
        db_path = tmp_path / "test_feedback.db"
        persistence = FeedbackLoopPersistence(db_path=db_path)

        persistence.create_session("test-scan", "https://example.com")
        persistence.complete_session("test-scan")

        session = persistence.get_session("test-scan")
        assert session["completed_at"] is not None


class TestLLMVulnerabilityValidator:
    """Test LLM vulnerability validator"""

    @pytest.mark.asyncio
    async def test_validator_initialization(self):
        """Test validator initializes correctly"""
        validator = LLMVulnerabilityValidator(openai_api_key="test-key", model="gpt-4o-mini")

        assert validator.model == "gpt-4o-mini"
        assert validator.cache_dir.exists()

    @pytest.mark.asyncio
    async def test_validate_hypothesis_with_mock(self, tmp_path):
        """Test hypothesis validation with mocked OpenAI"""
        validator = LLMVulnerabilityValidator(
            openai_api_key="test-key", cache_dir=tmp_path / "cache"
        )

        hypothesis = ValidationHypothesis(
            vulnerability_id="CVE-2024-0001",
            hypothesis="SQL injection possible",
            confidence=0.7,
            evidence=["User input not sanitized"],
            validation_plan=["Test with payloads"],
        )

        # Mock OpenAI response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[
            0
        ].message.content = '{"is_exploitable": true, "confidence": 0.85, "reasoning": "Test reasoning", "attack_vectors": ["SQL injection"], "prerequisites": ["Database access"], "impact_assessment": "High impact", "recommended_actions": ["Use parameterized queries"]}'
        mock_response.usage.total_tokens = 100

        mock_create = AsyncMock(return_value=mock_response)
        with patch.object(validator.client.chat.completions, "create", mock_create):
            result = await validator.validate_hypothesis(
                hypothesis=hypothesis, tech_stack={}, target_url="https://example.com"
            )

        assert result["vulnerability_id"] == "CVE-2024-0001"
        assert result["is_exploitable"] is True
        assert result["confidence"] > 0.0
        assert "reasoning" in result

    @pytest.mark.asyncio
    async def test_validate_hypotheses_batch(self, tmp_path):
        """Test batch hypothesis validation"""
        validator = LLMVulnerabilityValidator(
            openai_api_key="test-key", cache_dir=tmp_path / "cache"
        )

        hypotheses = [
            ValidationHypothesis(
                vulnerability_id=f"CVE-2024-000{i}",
                hypothesis=f"Test hypothesis {i}",
                confidence=0.7,
                evidence=["test"],
                validation_plan=["test"],
            )
            for i in range(3)
        ]

        # Mock responses
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[
            0
        ].message.content = '{"is_exploitable": true, "confidence": 0.8, "reasoning": "Test", "attack_vectors": [], "prerequisites": [], "impact_assessment": "Test", "recommended_actions": []}'
        mock_response.usage.total_tokens = 50

        mock_create = AsyncMock(return_value=mock_response)
        with patch.object(validator.client.chat.completions, "create", mock_create):
            results = await validator.validate_hypotheses(
                hypotheses=hypotheses,
                tech_stack={},
                target_url="https://example.com",
                max_concurrent=2,
            )

        assert len(results) == 3
        for result in results:
            assert "vulnerability_id" in result
            assert "is_exploitable" in result

    def test_caching_mechanism(self, tmp_path):
        """Test validation result caching"""
        validator = LLMVulnerabilityValidator(
            openai_api_key="test-key", cache_dir=tmp_path / "cache"
        )

        hypothesis = ValidationHypothesis(
            vulnerability_id="CVE-2024-0001",
            hypothesis="Test",
            confidence=0.7,
            evidence=["test"],
            validation_plan=["test"],
        )

        # Save to cache
        result = {"vulnerability_id": "CVE-2024-0001", "is_exploitable": True, "confidence": 0.8}

        validator._save_to_cache(hypothesis, result)

        # Load from cache
        cached = validator._load_from_cache(hypothesis)

        assert cached is not None
        assert cached["vulnerability_id"] == "CVE-2024-0001"
        assert cached["is_exploitable"] is True


@pytest.mark.asyncio
async def test_full_integration_flow(tmp_path):
    """Test complete Phase 3 integration flow"""
    # Setup
    scan_id = "integration-test"
    db_path = tmp_path / "feedback.db"

    # Initialize components
    policy_engine = PolicyEngine()
    persistence = FeedbackLoopPersistence(db_path=db_path)
    state_machine = FeedbackLoopStateMachine(scan_id=scan_id, persistence_path=tmp_path / "state")

    # Create session
    success = persistence.create_session(scan_id=scan_id, target_url="https://example.com")
    assert success is True

    # Check permission
    context = ExecutionContext(
        target_url="https://example.com", user_id="test-user", scan_id=scan_id
    )
    allowed, _ = policy_engine.check_permission(ActionType.SCAN, context)
    assert allowed is True

    # Execute feedback loop
    vulnerabilities = [
        {
            "id": "CVE-2024-0001",
            "severity": "CRITICAL",
            "cvss_score": 9.5,
            "description": "Test vulnerability",
        }
    ]

    # OBSERVING
    state_machine.observe(vulnerabilities, {}, "https://example.com")
    persistence.add_observation(scan_id, {"vuln_count": 1})

    # ORIENTING
    analysis = state_machine.orient()
    assert analysis["total_vulnerabilities"] == 1

    # HYPOTHESIZING
    hypotheses = state_machine.hypothesize()
    assert len(hypotheses) > 0

    for h in hypotheses:
        persistence.add_hypothesis(
            scan_id, h.vulnerability_id, h.hypothesis, h.confidence, h.evidence, h.validation_plan
        )

    # DECIDING
    actions = state_machine.decide()
    for a in actions:
        persistence.add_action(
            scan_id, a.action_id, a.action_type, a.target, a.parameters, a.expected_result
        )

    # ACTING
    executed = await state_machine.act()
    for a in executed:
        persistence.update_action_result(a.action_id, a.actual_result or "", a.success or False)

    # VALIDATING
    validations = state_machine.validate()
    for vuln_id, is_valid in validations.items():
        persistence.add_validation(scan_id, vuln_id, is_valid)

    # REPORTING
    report = state_machine.report()
    assert report["scan_id"] == scan_id

    # Complete session
    persistence.complete_session(scan_id)

    # Verify metrics
    metrics = persistence.get_metrics(scan_id)
    assert metrics is not None
    assert metrics["observations_made"] == 1
    assert metrics["hypotheses_generated"] > 0
    assert metrics["actions_executed"] > 0
    assert metrics["validations_completed"] > 0

    print("\n✅ Full integration test passed!")
    print(f"   Observations: {metrics['observations_made']}")
    print(f"   Hypotheses: {metrics['hypotheses_generated']}")
    print(f"   Actions: {metrics['actions_executed']}")
    print(f"   Validations: {metrics['validations_completed']}")
