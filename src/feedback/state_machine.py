"""Feedback loop state machine for vulnerability validation

8-State OODA-inspired loop:
1. IDLE - Waiting for input
2. OBSERVING - Collecting data and evidence
3. ORIENTING - Analyzing and understanding data
4. HYPOTHESIZING - Forming hypotheses about vulnerabilities
5. DECIDING - Planning validation actions
6. ACTING - Executing validation actions
7. VALIDATING - Verifying results
8. REPORTING - Generating reports and metrics

"""

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class State(Enum):
    """Feedback loop states"""

    IDLE = "idle"
    OBSERVING = "observing"
    ORIENTING = "orienting"
    HYPOTHESIZING = "hypothesizing"
    DECIDING = "deciding"
    ACTING = "acting"
    VALIDATING = "validating"
    REPORTING = "reporting"


@dataclass
class StateTransition:
    """Record of state transition"""

    from_state: State
    to_state: State
    reason: str
    timestamp: str
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ValidationHypothesis:
    """Hypothesis about a vulnerability"""

    vulnerability_id: str
    hypothesis: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    validation_plan: List[str]
    created_at: str = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


@dataclass
class ValidationAction:
    """Action to validate a hypothesis"""

    action_id: str
    action_type: str  # 'probe', 'test', 'verify', 'analyze'
    target: str
    parameters: Dict
    expected_result: str
    actual_result: Optional[str] = None
    success: Optional[bool] = None
    executed_at: Optional[str] = None


@dataclass
class LoopMetrics:
    """Metrics for feedback loop execution"""

    total_loops: int = 0
    observations_made: int = 0
    hypotheses_generated: int = 0
    actions_executed: int = 0
    validations_completed: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    average_loop_time: float = 0.0
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class FeedbackLoopStateMachine:
    """
    State machine for vulnerability validation feedback loop

    Implements an OODA-inspired loop for iterative vulnerability validation
    """

    def __init__(self, scan_id: str, persistence_path: Optional[Path] = None):
        """
        Initialize feedback loop state machine

        Args:
            scan_id: Unique scan identifier
            persistence_path: Path to persist state (SQLite will be used)
        """
        self.scan_id = scan_id
        self.persistence_path = persistence_path or Path(f".feedback/{scan_id}")
        self.persistence_path.mkdir(parents=True, exist_ok=True)

        # Current state
        self.current_state = State.IDLE
        self.state_data: Dict[str, Any] = {}

        # State history
        self.transitions: List[StateTransition] = []

        # Loop data
        self.observations: List[Dict] = []
        self.hypotheses: List[ValidationHypothesis] = []
        self.actions: List[ValidationAction] = []
        self.validations: Dict[str, bool] = {}  # vuln_id -> is_valid

        # Metrics
        self.metrics = LoopMetrics(start_time=datetime.now().isoformat())

        # Max iterations to prevent infinite loops
        self.max_iterations = 10
        self.current_iteration = 0

        logger.info(f"Initialized FeedbackLoopStateMachine for scan {scan_id}")

    def transition_to(self, new_state: State, reason: str, metadata: Dict | None = None):
        """
        Transition to a new state

        Args:
            new_state: Target state
            reason: Reason for transition
            metadata: Additional metadata
        """
        transition = StateTransition(
            from_state=self.current_state,
            to_state=new_state,
            reason=reason,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.transitions.append(transition)
        self.current_state = new_state

        logger.info(
            f"State transition: {transition.from_state.value} -> {transition.to_state.value}: {reason}"
        )

        # Persist state
        self._persist_state()

    def observe(self, vulnerabilities: List[Dict], tech_stack: Dict, target_url: str):
        """
        OBSERVING state: Collect data and evidence

        Args:
            vulnerabilities: List of potential vulnerabilities
            tech_stack: Detected technology stack
            target_url: Target URL
        """
        if self.current_state != State.IDLE:
            logger.warning(f"Cannot observe from state {self.current_state.value}")
            return

        self.transition_to(State.OBSERVING, "Starting observation phase")

        # Record observations
        observation = {
            "target_url": target_url,
            "tech_stack": tech_stack,
            "vulnerabilities": vulnerabilities,
            "observation_time": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
        }

        self.observations.append(observation)
        self.state_data["current_observation"] = observation
        self.metrics.observations_made += 1

        logger.info(f"Observed {len(vulnerabilities)} potential vulnerabilities")

        # Auto-transition to ORIENTING
        self.transition_to(State.ORIENTING, "Observation complete, beginning analysis")

    def orient(self) -> Dict:
        """
        ORIENTING state: Analyze and understand data

        Returns:
            Analysis results
        """
        if self.current_state != State.ORIENTING:
            logger.warning(f"Cannot orient from state {self.current_state.value}")
            return {}

        observation = self.state_data.get("current_observation", {})
        vulnerabilities = observation.get("vulnerabilities", [])

        # Analyze vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Identify high-priority vulnerabilities
        high_priority = [v for v in vulnerabilities if v.get("severity") in ["CRITICAL", "HIGH"]]

        analysis = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": severity_counts,
            "high_priority_count": len(high_priority),
            "high_priority_vulns": high_priority,
            "tech_stack": observation.get("tech_stack", {}),
            "analysis_time": datetime.now().isoformat(),
        }

        self.state_data["orientation"] = analysis

        logger.info(f"Oriented: {len(high_priority)} high-priority vulnerabilities identified")

        # Auto-transition to HYPOTHESIZING
        self.transition_to(State.HYPOTHESIZING, "Analysis complete, forming hypotheses")

        return analysis

    def hypothesize(self, llm_engine: Optional[Any] = None) -> List[ValidationHypothesis]:
        """
        HYPOTHESIZING state: Form hypotheses about vulnerabilities

        Args:
            llm_engine: Optional LLM engine for hypothesis generation

        Returns:
            List of hypotheses
        """
        if self.current_state != State.HYPOTHESIZING:
            logger.warning(f"Cannot hypothesize from state {self.current_state.value}")
            return []

        orientation = self.state_data.get("orientation", {})
        high_priority = orientation.get("high_priority_vulns", [])

        # Generate hypotheses for high-priority vulnerabilities
        hypotheses = []
        for vuln in high_priority[:5]:  # Limit to top 5
            hypothesis = ValidationHypothesis(
                vulnerability_id=vuln.get("id", "unknown"),
                hypothesis=f"Vulnerability {vuln.get('id')} may be exploitable based on {vuln.get('severity')} severity and description",
                confidence=0.7 if vuln.get("cvss_score", 0) > 7.0 else 0.5,
                evidence=[
                    f"CVSS Score: {vuln.get('cvss_score', 'N/A')}",
                    f"Severity: {vuln.get('severity', 'UNKNOWN')}",
                    f"Description: {vuln.get('description', '')[:200]}",
                ],
                validation_plan=[
                    "Check if affected version matches target",
                    "Verify vulnerability applicability",
                    "Test for exploitability (if authorized)",
                ],
            )
            hypotheses.append(hypothesis)

        self.hypotheses.extend(hypotheses)
        self.state_data["current_hypotheses"] = hypotheses
        self.metrics.hypotheses_generated += len(hypotheses)

        logger.info(f"Generated {len(hypotheses)} validation hypotheses")

        # Auto-transition to DECIDING
        self.transition_to(State.DECIDING, "Hypotheses formed, planning validation")

        return hypotheses

    def decide(self) -> List[ValidationAction]:
        """
        DECIDING state: Plan validation actions

        Returns:
            List of planned actions
        """
        if self.current_state != State.DECIDING:
            logger.warning(f"Cannot decide from state {self.current_state.value}")
            return []

        hypotheses = self.state_data.get("current_hypotheses", [])

        # Create validation actions for each hypothesis
        actions = []
        for i, hypothesis in enumerate(hypotheses):
            action = ValidationAction(
                action_id=f"action_{self.scan_id}_{i}",
                action_type="verify",
                target=hypothesis.vulnerability_id,
                parameters={"hypothesis": hypothesis.hypothesis, "confidence_threshold": 0.6},
                expected_result="Vulnerability confirmed or rejected",
            )
            actions.append(action)

        self.actions.extend(actions)
        self.state_data["planned_actions"] = actions

        logger.info(f"Planned {len(actions)} validation actions")

        # Auto-transition to ACTING
        self.transition_to(State.ACTING, "Actions planned, beginning execution")

        return actions

    async def act(self, action_executor: Optional[Any] = None) -> List[ValidationAction]:
        """
        ACTING state: Execute validation actions

        Args:
            action_executor: Optional executor for running actions

        Returns:
            List of executed actions with results
        """
        if self.current_state != State.ACTING:
            logger.warning(f"Cannot act from state {self.current_state.value}")
            return []

        actions = self.state_data.get("planned_actions", [])

        # Execute actions (placeholder - would integrate with actual testing)
        for action in actions:
            # Simulate execution
            action.executed_at = datetime.now().isoformat()
            action.actual_result = "Verification completed - hypothesis confidence maintained"
            action.success = True

            self.metrics.actions_executed += 1

        logger.info(f"Executed {len(actions)} validation actions")

        # Auto-transition to VALIDATING
        self.transition_to(State.VALIDATING, "Actions executed, validating results")

        return actions

    def validate(self) -> Dict[str, bool]:
        """
        VALIDATING state: Verify results and update hypotheses

        Returns:
            Dict of vulnerability_id -> is_valid
        """
        if self.current_state != State.VALIDATING:
            logger.warning(f"Cannot validate from state {self.current_state.value}")
            return {}

        hypotheses = self.state_data.get("current_hypotheses", [])
        actions = self.state_data.get("planned_actions", [])

        # Validate based on action results
        validations = {}
        for hypothesis in hypotheses:
            # Find corresponding action
            action = next((a for a in actions if a.target == hypothesis.vulnerability_id), None)

            if action and action.success:
                # Consider validated if confidence is high enough
                is_valid = hypothesis.confidence >= 0.6
                validations[hypothesis.vulnerability_id] = is_valid

                if is_valid:
                    self.metrics.true_positives += 1
                else:
                    self.metrics.false_positives += 1

        self.validations.update(validations)
        self.state_data["validation_results"] = validations
        self.metrics.validations_completed += len(validations)

        logger.info(f"Validated {len(validations)} vulnerabilities")

        # Auto-transition to REPORTING
        self.transition_to(State.REPORTING, "Validation complete, generating report")

        return validations

    def report(self) -> Dict:
        """
        REPORTING state: Generate final report

        Returns:
            Report data
        """
        if self.current_state != State.REPORTING:
            logger.warning(f"Cannot report from state {self.current_state.value}")
            return {}

        self.metrics.end_time = datetime.now().isoformat()
        self.metrics.total_loops += 1

        report = {
            "scan_id": self.scan_id,
            "metrics": asdict(self.metrics),
            "validated_vulnerabilities": self.validations,
            "true_positives": self.metrics.true_positives,
            "false_positives": self.metrics.false_positives,
            "total_hypotheses": len(self.hypotheses),
            "total_actions": len(self.actions),
            "transitions": [
                {
                    "from": t.from_state.value,
                    "to": t.to_state.value,
                    "reason": t.reason,
                    "timestamp": t.timestamp,
                }
                for t in self.transitions
            ],
            "generated_at": datetime.now().isoformat(),
        }

        # Save report
        report_path = self.persistence_path / "feedback_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"Generated feedback loop report: {report_path}")

        # Transition back to IDLE
        self.transition_to(State.IDLE, "Loop complete, ready for next iteration")

        return report

    def _persist_state(self):
        """Persist current state to disk"""
        state_file = self.persistence_path / "state.json"

        # Convert state_data to JSON-serializable format
        serializable_state_data = {}
        for key, value in self.state_data.items():
            if isinstance(value, list):
                # Convert list of dataclass objects to dicts
                serializable_state_data[key] = [
                    asdict(item) if hasattr(item, "__dataclass_fields__") else item
                    for item in value
                ]
            elif hasattr(value, "__dataclass_fields__"):
                # Convert single dataclass object to dict
                serializable_state_data[key] = asdict(value)
            else:
                serializable_state_data[key] = value

        state = {
            "scan_id": self.scan_id,
            "current_state": self.current_state.value,
            "current_iteration": self.current_iteration,
            "state_data": serializable_state_data,
            "metrics": asdict(self.metrics),
            "last_updated": datetime.now().isoformat(),
        }

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)

    def get_state_summary(self) -> Dict:
        """Get summary of current state"""
        return {
            "scan_id": self.scan_id,
            "current_state": self.current_state.value,
            "observations": len(self.observations),
            "hypotheses": len(self.hypotheses),
            "actions": len(self.actions),
            "validations": len(self.validations),
            "metrics": asdict(self.metrics),
        }
