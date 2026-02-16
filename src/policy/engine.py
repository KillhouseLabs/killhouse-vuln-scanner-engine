"""Policy engine for controlling execution permissions"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

import jwt

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of actions that can be controlled"""

    SCAN = "scan"
    EXPLOIT = "exploit"
    MODIFY = "modify"
    DELETE = "delete"
    NETWORK_REQUEST = "network_request"
    FILE_ACCESS = "file_access"


@dataclass
class PolicyRule:
    """A single policy rule"""

    action: ActionType
    allowed: bool
    conditions: Dict = None
    reason: str = ""

    def __post_init__(self):
        if self.conditions is None:
            self.conditions = {}


@dataclass
class ExecutionContext:
    """Context for policy evaluation"""

    target_url: str
    user_id: str
    authorization_token: Optional[str] = None
    scan_id: Optional[str] = None
    risk_level: str = "UNKNOWN"
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class PolicyEngine:
    """
    Policy engine for controlling execution permissions

    Validates JWT tokens and enforces security policies
    """

    def __init__(self, jwt_secret: Optional[str] = None, require_authorization: bool = False):
        """
        Initialize policy engine

        Args:
            jwt_secret: Secret key for JWT validation
            require_authorization: Whether to require JWT for all actions
        """
        self.jwt_secret = jwt_secret or "vulner-default-secret-change-in-production"
        self.require_authorization = require_authorization

        # Default policies
        self.policies: Dict[ActionType, List[PolicyRule]] = {
            ActionType.SCAN: [
                PolicyRule(
                    action=ActionType.SCAN, allowed=True, reason="Scanning is always allowed"
                )
            ],
            ActionType.EXPLOIT: [
                PolicyRule(
                    action=ActionType.EXPLOIT,
                    allowed=False,
                    conditions={"requires_token": True},
                    reason="Exploit execution requires valid authorization token",
                )
            ],
            ActionType.MODIFY: [
                PolicyRule(
                    action=ActionType.MODIFY,
                    allowed=False,
                    conditions={"requires_token": True, "max_risk": "MEDIUM"},
                    reason="Modification requires authorization and low/medium risk",
                )
            ],
            ActionType.DELETE: [
                PolicyRule(
                    action=ActionType.DELETE, allowed=False, reason="Deletion is never allowed"
                )
            ],
            ActionType.NETWORK_REQUEST: [
                PolicyRule(
                    action=ActionType.NETWORK_REQUEST,
                    allowed=True,
                    conditions={"rate_limit": 100},
                    reason="Network requests allowed with rate limiting",
                )
            ],
        }

        # Denied actions log
        self.denied_actions: List[Dict] = []

        logger.info(f"Initialized PolicyEngine (require_auth={require_authorization})")

    def validate_token(self, token: str) -> Dict:
        """
        Validate JWT token

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])

            # Check expiration
            if "exp" in payload:
                exp_timestamp = payload["exp"]
                if datetime.utcnow().timestamp() > exp_timestamp:
                    raise jwt.ExpiredSignatureError("Token has expired")

            logger.debug(f"Token validated for user: {payload.get('user_id')}")
            return payload

        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {e}")
            raise

    def generate_token(
        self, user_id: str, permissions: List[str], expires_in_hours: int = 24
    ) -> str:
        """
        Generate JWT token for testing

        Args:
            user_id: User identifier
            permissions: List of allowed actions
            expires_in_hours: Token expiration time

        Returns:
            JWT token string
        """
        payload = {
            "user_id": user_id,
            "permissions": permissions,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=expires_in_hours),
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        logger.info(f"Generated token for user {user_id}")
        return token

    def check_permission(self, action: ActionType, context: ExecutionContext) -> tuple[bool, str]:
        """
        Check if action is permitted

        Args:
            action: Action type to check
            context: Execution context

        Returns:
            Tuple of (allowed, reason)
        """
        rules = self.policies.get(action, [])

        for rule in rules:
            # Check basic permission
            if not rule.allowed:
                # Check if token can override
                if rule.conditions.get("requires_token"):
                    if not context.authorization_token:
                        reason = f"Action {action.value} denied: {rule.reason}"
                        self._log_denied_action(action, context, reason)
                        return False, reason

                    # Validate token
                    try:
                        token_data = self.validate_token(context.authorization_token)

                        # Check permissions in token
                        token_permissions = token_data.get("permissions", [])
                        if action.value not in token_permissions:
                            reason = f"Token missing permission for {action.value}"
                            self._log_denied_action(action, context, reason)
                            return False, reason

                        # Check risk level conditions
                        max_risk = rule.conditions.get("max_risk")
                        if max_risk:
                            risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                            if risk_order.index(context.risk_level) > risk_order.index(max_risk):
                                reason = (
                                    f"Risk level {context.risk_level} exceeds maximum {max_risk}"
                                )
                                self._log_denied_action(action, context, reason)
                                return False, reason

                        # Token validated, action allowed
                        logger.info(
                            f"Action {action.value} allowed via token for user {token_data.get('user_id')}"
                        )
                        return True, "Authorized via valid token"

                    except jwt.InvalidTokenError as e:
                        reason = f"Invalid authorization token: {e!s}"
                        self._log_denied_action(action, context, reason)
                        return False, reason
                else:
                    # No token can override, deny
                    reason = f"Action {action.value} denied: {rule.reason}"
                    self._log_denied_action(action, context, reason)
                    return False, reason

            # Action allowed by default
            logger.debug(f"Action {action.value} allowed: {rule.reason}")
            return True, rule.reason

        # No rules found, deny by default
        reason = f"No policy rule found for {action.value}"
        self._log_denied_action(action, context, reason)
        return False, reason

    def _log_denied_action(self, action: ActionType, context: ExecutionContext, reason: str):
        """Log denied action"""
        self.denied_actions.append(
            {
                "action": action.value,
                "context": {
                    "target_url": context.target_url,
                    "user_id": context.user_id,
                    "scan_id": context.scan_id,
                    "risk_level": context.risk_level,
                },
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
            }
        )
        logger.warning(f"Denied action: {action.value} - {reason}")

    def get_denied_actions(self) -> List[Dict]:
        """Get list of denied actions"""
        return self.denied_actions

    def add_policy_rule(self, rule: PolicyRule):
        """Add a custom policy rule"""
        if rule.action not in self.policies:
            self.policies[rule.action] = []
        self.policies[rule.action].append(rule)
        logger.info(f"Added policy rule for {rule.action.value}")

    def get_policies(self) -> Dict[ActionType, List[PolicyRule]]:
        """Get all policy rules"""
        return self.policies
