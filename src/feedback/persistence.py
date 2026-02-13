"""SQLite-based state persistence for feedback loop"""

import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class FeedbackLoopPersistence:
    """
    SQLite-based persistence layer for feedback loop state
    """

    def __init__(self, db_path: Path = Path(".feedback/feedback_loop.db")):
        """
        Initialize persistence layer

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

        logger.info(f"Initialized FeedbackLoopPersistence at {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """Get database connection context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scan sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    current_state TEXT NOT NULL,
                    current_iteration INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    metadata TEXT
                )
            """)

            # State transitions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS state_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    reason TEXT,
                    timestamp TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Observations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    observation_data TEXT NOT NULL,
                    observation_time TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Hypotheses table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vulnerability_id TEXT NOT NULL,
                    hypothesis TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evidence TEXT NOT NULL,
                    validation_plan TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    action_id TEXT NOT NULL UNIQUE,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    expected_result TEXT,
                    actual_result TEXT,
                    success INTEGER,
                    executed_at TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Validations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS validations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vulnerability_id TEXT NOT NULL,
                    is_valid INTEGER NOT NULL,
                    validation_time TEXT NOT NULL,
                    details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    scan_id TEXT PRIMARY KEY,
                    total_loops INTEGER DEFAULT 0,
                    observations_made INTEGER DEFAULT 0,
                    hypotheses_generated INTEGER DEFAULT 0,
                    actions_executed INTEGER DEFAULT 0,
                    validations_completed INTEGER DEFAULT 0,
                    true_positives INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    average_loop_time REAL DEFAULT 0.0,
                    start_time TEXT,
                    end_time TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
                )
            """)

            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_transitions_scan ON state_transitions(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_observations_scan ON observations(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hypotheses_scan ON hypotheses(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_actions_scan ON actions(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_validations_scan ON validations(scan_id)")

            logger.info("Database schema initialized")

    def create_session(
        self,
        scan_id: str,
        target_url: str,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Create a new scan session

        Args:
            scan_id: Unique scan identifier
            target_url: Target URL
            metadata: Additional metadata

        Returns:
            True if created successfully
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO scan_sessions
                    (scan_id, target_url, current_state, created_at, updated_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    target_url,
                    "idle",
                    now,
                    now,
                    json.dumps(metadata or {})
                ))

                # Initialize metrics
                cursor.execute("""
                    INSERT INTO metrics (scan_id, start_time)
                    VALUES (?, ?)
                """, (scan_id, now))

                logger.info(f"Created scan session: {scan_id}")
                return True

        except sqlite3.IntegrityError:
            logger.warning(f"Scan session already exists: {scan_id}")
            return False

    def update_state(
        self,
        scan_id: str,
        new_state: str,
        iteration: Optional[int] = None
    ):
        """Update current state of scan session"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            sql = "UPDATE scan_sessions SET current_state = ?, updated_at = ?"
            params = [new_state, datetime.now().isoformat()]

            if iteration is not None:
                sql += ", current_iteration = ?"
                params.append(iteration)

            sql += " WHERE scan_id = ?"
            params.append(scan_id)

            cursor.execute(sql, params)

    def add_transition(
        self,
        scan_id: str,
        from_state: str,
        to_state: str,
        reason: str,
        metadata: Optional[Dict] = None
    ):
        """Record a state transition"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO state_transitions
                (scan_id, from_state, to_state, reason, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                from_state,
                to_state,
                reason,
                datetime.now().isoformat(),
                json.dumps(metadata or {})
            ))

    def add_observation(
        self,
        scan_id: str,
        observation_data: Dict
    ):
        """Record an observation"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO observations
                (scan_id, observation_data, observation_time)
                VALUES (?, ?, ?)
            """, (
                scan_id,
                json.dumps(observation_data),
                datetime.now().isoformat()
            ))

            # Update metrics
            cursor.execute("""
                UPDATE metrics
                SET observations_made = observations_made + 1
                WHERE scan_id = ?
            """, (scan_id,))

    def add_hypothesis(
        self,
        scan_id: str,
        vulnerability_id: str,
        hypothesis: str,
        confidence: float,
        evidence: List[str],
        validation_plan: List[str]
    ):
        """Record a hypothesis"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO hypotheses
                (scan_id, vulnerability_id, hypothesis, confidence, evidence, validation_plan, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                vulnerability_id,
                hypothesis,
                confidence,
                json.dumps(evidence),
                json.dumps(validation_plan),
                datetime.now().isoformat()
            ))

            # Update metrics
            cursor.execute("""
                UPDATE metrics
                SET hypotheses_generated = hypotheses_generated + 1
                WHERE scan_id = ?
            """, (scan_id,))

    def add_action(
        self,
        scan_id: str,
        action_id: str,
        action_type: str,
        target: str,
        parameters: Dict,
        expected_result: str
    ):
        """Record a planned action"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO actions
                (scan_id, action_id, action_type, target, parameters, expected_result)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                action_id,
                action_type,
                target,
                json.dumps(parameters),
                expected_result
            ))

    def update_action_result(
        self,
        action_id: str,
        actual_result: str,
        success: bool
    ):
        """Update action with execution result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE actions
                SET actual_result = ?, success = ?, executed_at = ?
                WHERE action_id = ?
            """, (
                actual_result,
                1 if success else 0,
                datetime.now().isoformat(),
                action_id
            ))

            # Update metrics
            cursor.execute("""
                UPDATE metrics
                SET actions_executed = actions_executed + 1
                WHERE scan_id = (SELECT scan_id FROM actions WHERE action_id = ?)
            """, (action_id,))

    def add_validation(
        self,
        scan_id: str,
        vulnerability_id: str,
        is_valid: bool,
        details: Optional[Dict] = None
    ):
        """Record a validation result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO validations
                (scan_id, vulnerability_id, is_valid, validation_time, details)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                vulnerability_id,
                1 if is_valid else 0,
                datetime.now().isoformat(),
                json.dumps(details or {})
            ))

            # Update metrics
            if is_valid:
                cursor.execute("""
                    UPDATE metrics
                    SET validations_completed = validations_completed + 1,
                        true_positives = true_positives + 1
                    WHERE scan_id = ?
                """, (scan_id,))
            else:
                cursor.execute("""
                    UPDATE metrics
                    SET validations_completed = validations_completed + 1,
                        false_positives = false_positives + 1
                    WHERE scan_id = ?
                """, (scan_id,))

    def get_session(self, scan_id: str) -> Optional[Dict]:
        """Get scan session by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM scan_sessions WHERE scan_id = ?
            """, (scan_id,))

            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_transitions(self, scan_id: str) -> List[Dict]:
        """Get all transitions for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM state_transitions
                WHERE scan_id = ?
                ORDER BY timestamp ASC
            """, (scan_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_metrics(self, scan_id: str) -> Optional[Dict]:
        """Get metrics for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM metrics WHERE scan_id = ?
            """, (scan_id,))

            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def complete_session(self, scan_id: str):
        """Mark session as completed"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            now = datetime.now().isoformat()

            cursor.execute("""
                UPDATE scan_sessions
                SET completed_at = ?, updated_at = ?
                WHERE scan_id = ?
            """, (now, now, scan_id))

            cursor.execute("""
                UPDATE metrics
                SET end_time = ?, total_loops = total_loops + 1
                WHERE scan_id = ?
            """, (now, scan_id))

    def get_all_sessions(self, limit: int = 100) -> List[Dict]:
        """Get all scan sessions"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM scan_sessions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]
