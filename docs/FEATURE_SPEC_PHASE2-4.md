# Vulner 기능정의서: Phase 2~4

**작성일:** 2026-02-12
**버전:** 1.0
**상태:** Phase 2, 3 구현 완료 / Phase 4 설계 단계

---

## 목차
1. [Phase 2: 기술 스택 탐지 및 취약점 조회](#phase-2)
2. [Phase 3: Feedback Loop 및 AI 검증](#phase-3)
3. [Phase 4: 자동화된 모의 공격 (설계)](#phase-4)

---

## Phase 2: 기술 스택 탐지 및 취약점 조회

### 2.1 개요
대상 웹사이트의 기술 스택을 자동으로 탐지하고, 탐지된 기술에 대한 알려진 취약점을 조회하는 단계입니다.

### 2.2 주요 기능

#### 2.2.1 기술 스택 탐지 (TechStackDetector)

**파일:** `src/detection/tech_stack_detector.py`

**기능 설명:**
- 다중 탐지 방법을 병렬로 실행하여 정확도 향상
- 4가지 탐지 방법:
  1. **Wappalyzer**: 시그니처 기반 기술 식별
  2. **HTTP 헤더 분석**: Server, X-Powered-By 등 분석
  3. **HTML 콘텐츠 분석**: 특정 패턴 및 라이브러리 탐지
  4. **메타 태그 분석**: generator, application-name 등 분석

**입력:**
```python
url: str  # 대상 웹사이트 URL
```

**출력:**
```python
List[TechStackInfo]
# TechStackInfo:
# - name: str           # 기술 이름 (예: "React", "nginx")
# - version: str        # 버전 정보
# - category: str       # 카테고리 (예: "Web Framework", "Web Server")
# - confidence: float   # 탐지 신뢰도 (0.0~1.0)
# - detection_method: str  # 탐지 방법
```

**특징:**
- 비동기 처리로 빠른 탐지
- 중복 제거: 동일 기술이 여러 방법으로 탐지되면 신뢰도가 높은 것 선택
- 타임아웃: 30초
- 에러 핸들링: 개별 탐지 방법 실패해도 다른 방법 계속 실행

**예시:**
```python
detector = TechStackDetector()
techs = await detector.detect("https://example.com")

# 결과:
# [
#   TechStackInfo(name="Amazon S3", version="", confidence=0.9, detection_method="wappalyzer"),
#   TechStackInfo(name="Amazon Cloudfront", version="", confidence=0.9, detection_method="wappalyzer")
# ]
```

---

#### 2.2.2 취약점 데이터베이스 조회 (VulnerabilityDatabase)

**파일:** `src/vulnerability/vuln_database.py`

**기능 설명:**
- OSV.dev와 NVD(National Vulnerability Database)를 병렬로 조회
- 패키지별 알려진 취약점 검색
- 24시간 캐싱으로 API 호출 최소화

**지원 생태계:**
- npm (Node.js)
- PyPI (Python)
- Maven (Java)
- Go
- RubyGems
- 기타 OSV.dev 지원 생태계

**입력:**
```python
package_name: str      # 패키지 이름
version: Optional[str] # 특정 버전 (없으면 전체)
ecosystem: str         # 생태계 (기본값: "npm")
```

**출력:**
```python
List[Vulnerability]
# Vulnerability:
# - id: str                    # CVE-2023-1234 또는 GHSA-xxxx
# - title: str                 # 취약점 제목
# - description: str           # 상세 설명
# - severity: str              # CRITICAL, HIGH, MEDIUM, LOW
# - cvss_score: float          # CVSS 점수 (0.0~10.0)
# - affected_versions: List[str]  # 영향받는 버전
# - fixed_versions: List[str]     # 수정된 버전
# - published_date: str        # 공개 날짜
# - references: List[str]      # 참조 URL
# - source: str                # 출처 (osv, nvd)
```

**OSV.dev API:**
- 엔드포인트: `https://api.osv.dev/v1/query`
- 요청 형식:
  ```json
  {
    "package": {
      "name": "react",
      "ecosystem": "npm"
    },
    "version": "16.8.0"  // optional
  }
  ```

**NVD API:**
- nvdlib 라이브러리 사용
- CPE(Common Platform Enumeration) 기반 검색
- API 키 사용 시 더 높은 속도 제한

**심각도 매핑:**
```python
CVSS Score → Severity
9.0 ~ 10.0 → CRITICAL
7.0 ~ 8.9  → HIGH
4.0 ~ 6.9  → MEDIUM
0.1 ~ 3.9  → LOW
```

**캐싱:**
- 캐시 키: `{ecosystem}:{package_name}:{version}`
- TTL: 24시간
- 메모리 기반 캐시

**예시:**
```python
db = VulnerabilityDatabase()
vulns = await db.query_vulnerabilities(
    package_name="Amazon S3",
    ecosystem="npm"
)

# 결과:
# [
#   Vulnerability(
#     id="CVE-2022-24840",
#     severity="CRITICAL",
#     cvss_score=9.1,
#     description="Path traversal in django-s3file..."
#   ),
#   ...
# ]
```

---

#### 2.2.3 벡터 데이터베이스 (VectorStore)

**파일:** `src/database/vector_store.py`

**기능 설명:**
- Supabase pgvector를 사용한 취약점 유사도 검색
- 임베딩 기반 의미론적 검색
- 취약점 설명의 의미적 유사성 파악

**주요 기능:**
1. **임베딩 생성:** OpenAI text-embedding-3-small 모델 사용
2. **유사도 검색:** 코사인 유사도 기반
3. **캐싱:** 동일 쿼리 재사용

**스키마:**
```sql
CREATE TABLE vulnerabilities (
  id TEXT PRIMARY KEY,
  package_name TEXT,
  ecosystem TEXT,
  severity TEXT,
  cvss_score FLOAT,
  description TEXT,
  metadata JSONB,
  embedding VECTOR(1536),
  created_at TIMESTAMP
);
```

**예시:**
```python
vector_store = VectorStore(supabase_url, supabase_key)

# 취약점 저장
await vector_store.upsert_vulnerability(vulnerability)

# 유사 취약점 검색
similar = await vector_store.search_similar(
    query="SQL injection vulnerability",
    limit=10,
    threshold=0.7
)
```

---

### 2.3 Phase 2 워크플로우

```
┌─────────────────┐
│  URL 입력       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 기술 스택 탐지  │ ← Wappalyzer, HTTP 헤더, HTML 분석
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 취약점 데이터   │
│ 베이스 조회     │ ← OSV.dev + NVD (병렬)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 벡터 DB 저장    │ ← 임베딩 생성 및 저장 (선택)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 취약점 목록     │
│ 반환            │
└─────────────────┘
```

---

## Phase 3: Feedback Loop 및 AI 검증

### 3.1 개요
발견된 취약점이 실제로 대상 시스템에서 악용 가능한지 AI를 활용하여 검증하는 지능형 필터링 시스템입니다. OODA Loop(Observe-Orient-Decide-Act) 프레임워크를 기반으로 설계되었습니다.

### 3.2 주요 컴포넌트

#### 3.2.1 Policy Engine

**파일:** `src/policy/engine.py`

**목적:** 모의 공격 실행에 대한 권한 제어 및 책임 소재 명확화

**액션 타입:**
```python
class ActionType(Enum):
    SCAN = "scan"              # 취약점 스캔 (항상 허용)
    EXPLOIT = "exploit"        # 취약점 악용 시도 (토큰 필요)
    MODIFY = "modify"          # 데이터 수정 (토큰 + 위험도 제한)
    DELETE = "delete"          # 데이터 삭제 (토큰 + 높은 권한)
    NETWORK_REQUEST = "network_request"  # 외부 네트워크 요청
    FILE_ACCESS = "file_access"          # 파일 시스템 접근
```

**JWT 토큰 구조:**
```json
{
  "user_id": "user-123",
  "permissions": ["scan", "exploit"],
  "exp": 1739384800,
  "iat": 1739298400
}
```

**정책 규칙:**
```python
PolicyRule(
    action=ActionType.EXPLOIT,
    allowed=False,  # 기본적으로 거부
    conditions={
        "requires_token": True,     # JWT 필요
        "max_risk": "MEDIUM"       # 위험도 제한
    },
    reason="Exploit execution requires valid authorization token"
)
```

**사용 예시:**
```python
engine = PolicyEngine(jwt_secret="your-secret")

# 토큰 생성
token = engine.generate_token(
    user_id="user-123",
    permissions=["scan", "exploit"],
    expires_in_hours=24
)

# 권한 확인
context = ExecutionContext(
    target_url="https://example.com",
    user_id="user-123",
    authorization_token=token
)

allowed, reason = engine.check_permission(ActionType.EXPLOIT, context)
# allowed=True if token is valid
```

**책임 소재:**
- 모든 위험한 액션은 JWT 토큰으로 추적
- 거부된 액션은 로그에 기록
- 사용자가 명시적으로 권한을 부여한 경우에만 실행

---

#### 3.2.2 Feedback Loop State Machine

**파일:** `src/feedback/state_machine.py`

**개요:** OODA Loop 기반 8단계 상태 머신

**상태 다이어그램:**
```
┌──────┐
│ IDLE │ ◄────────────────────────┐
└───┬──┘                          │
    │                             │
    ▼                             │
┌──────────┐                      │
│OBSERVING │ 데이터 수집           │
└─────┬────┘                      │
      │                           │
      ▼                           │
┌──────────┐                      │
│ORIENTING │ 데이터 분석           │
└─────┬────┘                      │
      │                           │
      ▼                           │
┌──────────────┐                  │
│HYPOTHESIZING │ 가설 생성         │
└─────┬────────┘                  │
      │                           │
      ▼                           │
┌──────────┐                      │
│ DECIDING │ 액션 계획             │
└─────┬────┘                      │
      │                           │
      ▼                           │
┌──────────┐                      │
│  ACTING  │ 액션 실행             │
└─────┬────┘                      │
      │                           │
      ▼                           │
┌────────────┐                    │
│VALIDATING  │ 결과 검증           │
└─────┬──────┘                    │
      │                           │
      ▼                           │
┌──────────┐                      │
│REPORTING │ 리포트 생성           │
└─────┬────┘                      │
      │                           │
      └───────────────────────────┘
```

**각 단계 상세:**

**1. OBSERVING (관찰)**
- 입력: 취약점 목록, 기술 스택, 대상 URL
- 출력: 관찰 데이터 기록
- 메트릭: `observations_made++`

**2. ORIENTING (방향 설정)**
- 입력: 관찰 데이터
- 처리:
  - 심각도별 분류
  - CRITICAL/HIGH 우선순위 지정
  - 기술 스택과 취약점 매칭 분석
- 출력: 분석 결과 + 고위험 취약점 목록

**3. HYPOTHESIZING (가설 생성)**
- 입력: 고위험 취약점 목록
- 처리:
  - 각 취약점에 대한 가설 생성
  - 신뢰도 계산 (버전 일치도, 환경 적합성)
  - 증거 수집 (affected_versions, 환경 정보)
  - 검증 계획 수립
- 출력: `List[ValidationHypothesis]`
- 메트릭: `hypotheses_generated += len(hypotheses)`

**ValidationHypothesis 구조:**
```python
@dataclass
class ValidationHypothesis:
    vulnerability_id: str         # CVE-2024-0001
    hypothesis: str               # "이 취약점은 현재 환경에서 악용 가능함"
    confidence: float             # 0.0 ~ 1.0
    evidence: List[str]           # ["버전 일치", "환경 조건 만족"]
    validation_plan: List[str]    # ["페이로드 테스트", "응답 분석"]
    created_at: str
```

**4. DECIDING (결정)**
- 입력: 가설 목록
- 처리:
  - 각 가설에 대한 검증 액션 생성
  - 액션 우선순위 결정
  - 리소스 할당 계획
- 출력: `List[ValidationAction]`

**ValidationAction 구조:**
```python
@dataclass
class ValidationAction:
    action_id: str               # "action-001"
    action_type: str             # 'probe', 'test', 'verify', 'analyze'
    target: str                  # CVE ID 또는 엔드포인트
    parameters: Dict             # 액션별 파라미터
    expected_result: str         # 예상 결과
    actual_result: Optional[str] # 실제 결과 (실행 후)
    success: Optional[bool]      # 성공 여부
    executed_at: Optional[str]   # 실행 시각
```

**5. ACTING (실행)**
- 입력: 액션 목록
- 처리:
  - 각 액션 실행 (Policy Engine 권한 확인)
  - 결과 기록
  - 실패 시 재시도 로직
- 출력: 실행된 액션 목록
- 메트릭: `actions_executed += len(actions)`

**6. VALIDATING (검증)**
- 입력: 실행 결과
- 처리:
  - **LLM 기반 검증** (LLMVulnerabilityValidator 사용)
  - 각 가설의 실제 악용 가능성 평가
  - 신뢰도 재계산
- 출력: `Dict[vuln_id, is_valid]`
- 메트릭:
  - `validations_completed++`
  - `true_positives++` (is_valid=True인 경우)
  - `false_positives++` (is_valid=False인 경우)

**7. REPORTING (보고)**
- 입력: 검증 결과
- 처리:
  - 메트릭 집계
  - 리포트 생성
  - JSON 파일 저장
- 출력: Feedback Loop 리포트

**LoopMetrics 구조:**
```python
@dataclass
class LoopMetrics:
    total_loops: int = 0
    observations_made: int = 0
    hypotheses_generated: int = 0
    actions_executed: int = 0
    validations_completed: int = 0
    true_positives: int = 0        # 실제 취약점
    false_positives: int = 0       # 오탐지
    false_negatives: int = 0       # 놓친 취약점
    average_loop_time: float = 0.0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
```

**상태 전환 규칙:**
- IDLE → OBSERVING: 데이터 입력 시
- OBSERVING → ORIENTING: 관찰 완료
- ORIENTING → HYPOTHESIZING: 분석 완료
- HYPOTHESIZING → DECIDING: 가설 생성 완료
- DECIDING → ACTING: 액션 계획 완료
- ACTING → VALIDATING: 액션 실행 완료
- VALIDATING → REPORTING: 검증 완료
- REPORTING → IDLE: 리포트 생성 완료 (루프 완료)

---

#### 3.2.3 LLM Vulnerability Validator

**파일:** `src/feedback/llm_validator.py`

**목적:** 취약점이 실제로 대상 시스템에서 악용 가능한지 AI로 판단

**모델:** GPT-4o-mini (비용 효율적, 빠른 응답)

**입력:**
```python
hypothesis: ValidationHypothesis  # 검증할 가설
tech_stack: Dict                  # 기술 스택 정보
target_url: str                   # 대상 URL
```

**프롬프트 구조:**
```python
system_prompt = """
You are a cybersecurity expert specializing in vulnerability assessment.

Analyze whether the given vulnerability is actually exploitable in the specific target context.
Consider:
1. Technology stack compatibility
2. Version matching
3. Environmental requirements
4. Actual attack feasibility

Respond in JSON format.
"""

user_prompt = f"""
Vulnerability: {hypothesis.vulnerability_id}
Hypothesis: {hypothesis.hypothesis}
Evidence: {hypothesis.evidence}
Target Tech Stack: {tech_stack}
Target URL: {target_url}

Assess exploitability and provide structured analysis.
"""
```

**출력:**
```python
{
    "vulnerability_id": "CVE-2024-0001",
    "is_exploitable": bool,       # 악용 가능 여부
    "confidence": float,          # 0.0 ~ 1.0
    "reasoning": str,             # 판단 근거
    "attack_vectors": List[str],  # 공격 경로
    "prerequisites": List[str],   # 전제 조건
    "impact_assessment": str,     # 영향 평가
    "recommended_actions": List[str],  # 권장 조치
    "false_positive_indicators": List[str],  # 오탐 지표
    "validation_metadata": {
        "model": "gpt-4o-mini",
        "tokens_used": 150,
        "timestamp": "2024-02-12T10:00:00"
    }
}
```

**검증 로직:**
```python
async def validate_hypothesis(
    self,
    hypothesis: ValidationHypothesis,
    tech_stack: Dict,
    target_url: str
) -> Dict:
    # 1. 캐시 확인
    cached = self._load_from_cache(hypothesis)
    if cached:
        return cached

    # 2. LLM 호출
    response = await self.client.chat.completions.create(
        model=self.model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.3,  # 일관성을 위해 낮은 temperature
        response_format={"type": "json_object"}
    )

    # 3. 결과 파싱
    result = json.loads(response.choices[0].message.content)

    # 4. 캐시 저장
    self._save_to_cache(hypothesis, result)

    return result
```

**배치 검증:**
```python
async def validate_hypotheses(
    self,
    hypotheses: List[ValidationHypothesis],
    tech_stack: Dict,
    target_url: str,
    max_concurrent: int = 3  # 병렬 처리 제한
) -> List[Dict]:
    results = []

    for i in range(0, len(hypotheses), max_concurrent):
        batch = hypotheses[i:i + max_concurrent]

        tasks = [
            self.validate_hypothesis(h, tech_stack, target_url)
            for h in batch
        ]

        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)

    return results
```

**캐싱:**
- 캐시 키: `{vulnerability_id}_{hash(hypothesis)}`
- 저장 위치: `.cache/llm_validation/`
- 형식: JSON 파일
- 이유: 동일한 취약점에 대한 중복 API 호출 방지 (비용 절감)

**예시 시나리오:**

**시나리오 1: 오탐 필터링**
```python
# 입력
hypothesis = ValidationHypothesis(
    vulnerability_id="CVE-2022-24840",
    hypothesis="django-s3file path traversal 취약점",
    confidence=0.7,
    evidence=["Amazon S3 탐지됨"],
    validation_plan=["환경 확인", "Django 사용 여부 확인"]
)

tech_stack = {
    "Amazon S3": {"version": "", "category": "Cloud Storage"},
    "Amazon Cloudfront": {"version": "", "category": "CDN"}
}

# LLM 검증
result = await validator.validate_hypothesis(hypothesis, tech_stack, "https://hamalab.io")

# 출력
{
    "is_exploitable": False,
    "confidence": 0.80,
    "reasoning": "이 취약점은 django-s3file 라이브러리에 특정되며,
                 대상 사이트는 정적 S3 호스팅을 사용하고 있어 Django를
                 사용하지 않습니다. 따라서 이 취약점은 적용되지 않습니다.",
    "false_positive_indicators": [
        "Django 프레임워크 미사용",
        "정적 웹사이트 호스팅",
        "Python 서버 없음"
    ]
}
```

**시나리오 2: 실제 취약점 확인**
```python
# 입력
hypothesis = ValidationHypothesis(
    vulnerability_id="CVE-2024-1234",
    hypothesis="Express.js SQL injection 취약점",
    confidence=0.9,
    evidence=[
        "Express.js 4.17.0 탐지됨",
        "영향받는 버전: 4.0.0 - 4.17.3",
        "MySQL 연결 확인됨"
    ]
)

tech_stack = {
    "Express.js": {"version": "4.17.0"},
    "Node.js": {"version": "16.0.0"},
    "MySQL": {"version": "8.0"}
}

# LLM 검증
result = await validator.validate_hypothesis(hypothesis, tech_stack, "https://api.example.com")

# 출력
{
    "is_exploitable": True,
    "confidence": 0.95,
    "reasoning": "대상 시스템은 영향받는 버전의 Express.js를 사용하고 있으며,
                 MySQL 데이터베이스와 연결되어 있습니다.
                 이 취약점은 실제로 악용 가능할 가능성이 매우 높습니다.",
    "attack_vectors": [
        "Prepared statement 미사용 시 SQL injection",
        "사용자 입력이 직접 쿼리에 포함되는 엔드포인트"
    ],
    "prerequisites": [
        "인증되지 않은 API 엔드포인트 존재",
        "사용자 입력을 받는 쿼리 파라미터"
    ],
    "impact_assessment": "데이터베이스 전체 접근, 데이터 유출/변조 가능",
    "recommended_actions": [
        "Express.js를 4.18.0 이상으로 즉시 업데이트",
        "모든 SQL 쿼리에 Prepared Statement 사용",
        "입력 검증 및 sanitization 강화"
    ]
}
```

---

#### 3.2.4 Feedback Loop Persistence

**파일:** `src/feedback/persistence.py`

**목적:** Feedback Loop 상태 및 메트릭을 SQLite에 영속화

**데이터베이스 스키마:**

```sql
-- 스캔 세션
CREATE TABLE scan_sessions (
    scan_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    current_state TEXT NOT NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- 관찰 데이터
CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    observation_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
);

-- 가설
CREATE TABLE hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence JSON,
    validation_plan JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
);

-- 액션
CREATE TABLE actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    action_id TEXT UNIQUE NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters JSON,
    expected_result TEXT,
    actual_result TEXT,
    success BOOLEAN,
    executed_at TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
);

-- 검증 결과
CREATE TABLE validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    is_valid BOOLEAN NOT NULL,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
);

-- 상태 전환 이력
CREATE TABLE state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_sessions(scan_id)
);
```

**주요 메서드:**

```python
class FeedbackLoopPersistence:
    def __init__(self, db_path: Path = Path(".feedback/feedback_loop.db")):
        self.db_path = db_path
        self._init_db()

    # 세션 관리
    def create_session(self, scan_id: str, target_url: str, metadata: Dict) -> bool
    def complete_session(self, scan_id: str) -> bool
    def get_session(self, scan_id: str) -> Optional[Dict]

    # 데이터 기록
    def add_observation(self, scan_id: str, observation_data: Dict) -> bool
    def add_hypothesis(self, scan_id: str, vulnerability_id: str,
                      hypothesis: str, confidence: float,
                      evidence: List[str], validation_plan: List[str]) -> bool
    def add_action(self, scan_id: str, action: ValidationAction) -> bool
    def add_validation(self, scan_id: str, vulnerability_id: str,
                      is_valid: bool, details: Dict) -> bool
    def add_state_transition(self, scan_id: str, from_state: str,
                            to_state: str, reason: str, metadata: Dict) -> bool

    # 조회
    def get_hypotheses(self, scan_id: str) -> List[Dict]
    def get_actions(self, scan_id: str) -> List[Dict]
    def get_validations(self, scan_id: str) -> List[Dict]
    def get_metrics(self, scan_id: str) -> Dict
```

**저장 위치:**
- 데이터베이스: `.feedback/feedback_loop.db`
- 상태 파일: `.feedback/{scan_id}/state.json`
- 리포트: `.feedback/{scan_id}/feedback_report.json`

---

#### 3.2.5 Vulnerability Analyzer (AI 분석)

**파일:** `src/analysis/vulnerability_analyzer.py`

**목적:** 검증된 취약점을 이해하기 쉬운 언어로 요약하고 경영진 보고서 생성

**주요 기능:**

**1. 취약점 요약 (summarize_vulnerability)**

**입력:**
```python
vulnerability: Dict  # 취약점 정보
language: str = "Korean"  # 출력 언어
```

**프롬프트:**
```python
system_prompt = f"""
You are a cybersecurity expert that explains vulnerabilities in clear,
easy-to-understand {language}.

Your task is to analyze the vulnerability and provide:
1. A brief summary (2-3 sentences) explaining what the vulnerability is
2. Why it's dangerous and what can happen if exploited
3. Who is at risk (what types of systems/applications)
4. Recommended actions to fix or mitigate it

Be conversational and avoid overly technical jargon.
Focus on practical understanding.
"""

user_prompt = f"""
Analyze this vulnerability:

ID: {vulnerability['id']}
Title: {vulnerability['title']}
Severity: {vulnerability['severity']}
CVSS Score: {vulnerability['cvss_score']}
Description: {vulnerability['description']}
Affected Versions: {vulnerability['affected_versions'][:5]}
Fixed Versions: {vulnerability['fixed_versions'][:5]}

Provide your analysis in JSON format with these fields:
- summary: Brief explanation
- risk: Why it's dangerous
- affected: Who is at risk
- action: What to do about it
- severity_explanation: Explain the severity level in simple terms
"""
```

**출력:**
```python
{
    "vulnerability_id": "CVE-2024-0001",
    "analysis": {
        "summary": "이 취약점은 웹 프레임워크에서 발생하는 원격 코드 실행
                   취약점입니다. 공격자가 특수하게 조작된 요청을 보내면
                   서버에서 임의의 코드를 실행할 수 있습니다.",
        "risk": "공격자가 서버를 완전히 장악할 수 있으며, 데이터 유출,
                서비스 중단, 추가 공격을 위한 발판으로 사용될 수 있습니다.",
        "affected": "해당 프레임워크의 1.0.0~2.4.5 버전을 사용하는
                    모든 웹 애플리케이션이 위험에 노출되어 있습니다.",
        "action": "즉시 2.4.6 버전 이상으로 업데이트하고, 업데이트가
                  불가능한 경우 WAF(웹 방화벽)를 통해 의심스러운
                  요청을 차단하세요.",
        "severity_explanation": "CRITICAL 등급은 가장 높은 위험도를
                               의미하며, 즉각적인 조치가 필요합니다."
    },
    "model": "gpt-4o-mini",
    "timestamp": "2024-02-12T10:00:00",
    "tokens_used": 250
}
```

**캐싱:**
- 캐시 키: `{vulnerability_id}.json`
- 위치: `.cache/analysis/`
- 이유: 동일 취약점 재분석 방지

**2. 경영진 요약 (generate_executive_summary)**

**입력:**
```python
scan_result: Dict  # 전체 스캔 결과
language: str = "Korean"
```

**프롬프트:**
```python
system_prompt = f"""
You are a cybersecurity expert creating executive summaries for
non-technical stakeholders.

Create a clear, actionable summary in {language} that:
1. Explains what was scanned and what was found
2. Highlights the most critical issues
3. Provides prioritized recommendations
4. Uses business-friendly language (avoid technical jargon)
"""

user_prompt = f"""
Generate an executive summary for this security scan:

Target: {scan_result['url']}
Scan Date: {scan_result['timestamp']}
Technologies Detected: {technologies}

Scan Results:
- 총 발견된 취약점: {total_found}개
- AI 검증 후 실제 취약점: {validated_count}개
- 필터링된 취약점: {filtered_count}개 (현재 환경과 무관하거나 악용 불가능)

검증된 취약점 분포:
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Most Critical Validated Issues: {top_3_critical}

IMPORTANT:
- If validated_count is 0, explain that while {total_found} potential
  vulnerabilities were found in the database, AI analysis determined
  they are not applicable to this specific system configuration.
- Focus on the validated vulnerabilities count, not the initial discovery count.

Provide your summary in JSON format with these fields:
- overview: What was scanned, how many were found vs validated, and overall status
- key_findings: 3-5 main findings in bullet points (mention validation results)
- critical_risks: Explanation of validated risks (or "no critical risks" if count is 0)
- recommendations: Prioritized action items based on validated vulnerabilities
- timeline: Suggested timeline for addressing validated issues
"""
```

**출력:**
```python
{
    "scan_id": "abc123",
    "executive_summary": {
        "overview": "https://example.com 웹사이트에 대한 보안 스캔이
                    수행되었습니다. 총 41개의 잠재적 취약점이 발견되었으나,
                    AI 분석을 통해 현재 시스템 구성에 실제로 적용 가능한
                    취약점은 0개로 확인되었습니다.",
        "key_findings": [
            "총 41개의 잠재적 취약점이 데이터베이스에서 발견됨",
            "AI 검증 결과 모든 취약점이 현재 환경과 무관함을 확인",
            "정적 S3 호스팅 환경으로 대부분의 웹 프레임워크 취약점 해당 없음"
        ],
        "critical_risks": "검증된 위험 요소는 없습니다. 모든 잠재적 취약점이
                         현재 시스템에 적용되지 않습니다.",
        "recommendations": [
            "정기적인 보안 스캔을 통해 시스템의 보안 상태를 지속적으로 모니터링",
            "시스템 구성 변경 시 새로운 취약점 검증 절차 마련",
            "보안 교육을 통해 직원들이 잠재적 위험을 인지하고 대응할 수 있도록 함"
        ],
        "timeline": "향후 6개월 이내에 정기 보안 스캔을 실시하고,
                   시스템 구성 변경 시 즉시 검증 절차를 적용할 것"
    },
    "model": "gpt-4o-mini",
    "timestamp": "2024-02-12T10:05:00",
    "tokens_used": 2026
}
```

**통계:**
```python
{
    "api_calls": 11,           # 총 API 호출 횟수
    "cache_hits": 10,          # 캐시 히트 횟수
    "total_tokens": 3500,      # 총 사용 토큰
    "cache_hit_rate": 90.9     # 캐시 히트율 (%)
}
```

---

### 3.3 Phase 3 전체 워크플로우

```
┌────────────────────────┐
│ 취약점 목록 입력        │ (Phase 2 출력)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ OBSERVING              │
│ - 취약점 데이터 수집    │
│ - 기술 스택 매칭       │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ ORIENTING              │
│ - 심각도별 분류         │
│ - 고위험 필터링         │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ HYPOTHESIZING          │
│ - 가설 생성 (5~10개)   │
│ - 신뢰도 계산          │
│ - 증거 수집            │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ DECIDING               │
│ - 검증 액션 계획        │
│ - 우선순위 결정         │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ ACTING                 │
│ - 액션 실행             │
│ - 결과 기록             │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ VALIDATING             │
│ ┌────────────────────┐ │
│ │ LLM Validator      │ │
│ │ (GPT-4o-mini)      │ │
│ │                    │ │
│ │ • 환경 적합성 분석  │ │
│ │ • 악용 가능성 평가  │ │
│ │ • 오탐 필터링       │ │
│ └────────────────────┘ │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ REPORTING              │
│ - 메트릭 집계           │
│ - 리포트 생성           │
│ - SQLite 저장          │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ AI Analysis            │
│ ┌────────────────────┐ │
│ │ 취약점 상세 분석    │ │
│ │ (한국어)           │ │
│ └────────────────────┘ │
│ ┌────────────────────┐ │
│ │ 경영진 요약         │ │
│ │ (비즈니스 관점)     │ │
│ └────────────────────┘ │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ 최종 리포트             │
│ - JSON 파일            │
│ - SQLite DB            │
│ - 콘솔 출력            │
└────────────────────────┘
```

---

### 3.4 Phase 3 출력 예시

**콘솔 출력:**
```
================================================================================
📊 스캔 결과
================================================================================

Scan ID: 47a2259c
Target URL: https://hamalab.io
Status: completed

================================================================================
DETECTED TECHNOLOGIES
================================================================================

  • Amazon S3 (Confidence: 90%)
  • Amazon Web Services (Confidence: 90%)
  • Amazon Cloudfront (Confidence: 90%)

================================================================================
VULNERABILITIES
================================================================================

📊 검증 결과:
   총 발견: 41개
   검증 완료: 0개
   필터링됨: 41개 (악용 불가능 또는 낮은 신뢰도)

================================================================================
🤖 AI 분석: 경영진 요약
================================================================================

📋 개요:
  https://hamalab.io 웹사이트에 대한 보안 스캔이 수행되었습니다.
  총 41개의 잠재적 취약점이 발견되었으나, AI 분석 결과 현재 시스템
  구성에 적용 가능한 실제 취약점은 0개입니다.

🔍 주요 발견사항:
  • 총 41개의 잠재적 취약점이 데이터베이스에서 발견됨
  • AI 검증 후 실제 취약점은 0개로 확인됨
  • 모든 발견된 취약점은 현재 환경과 무관하거나 악용이 불가능함

⚠️  중요 위험:
  검증된 위험 요소는 없습니다. 모든 잠재적 취약점이 현재 시스템에
  적용되지 않습니다.

✅ 권장 조치사항:
  1. 정기적인 보안 스캔을 통해 시스템의 보안 상태를 지속적으로 모니터링
  2. 시스템 구성 변경 시 새로운 취약점 검증 절차를 마련
  3. 보안 교육을 통해 직원들이 잠재적 위험을 인지하고 대응할 수 있도록 함

⏱️  권장 일정:
  향후 6개월 이내에 정기 보안 스캔을 실시하고, 시스템 구성 변경 시
  즉시 검증 절차를 적용할 것

================================================================================
🔄 피드백 루프 검증 리포트
================================================================================

  📊 검증 통계:
     총 루프 반복: 1
     관찰 수행: 1
     가설 생성: 5
     액션 실행: 5
     검증 완료: 5
     실제 취약점: 0
     오탐지: 5

  ✅ 검증된 취약점: 0개

  🔄 상태 전환 과정:
     idle → observing: Starting observation phase
     observing → orienting: Observation complete, beginning analysis
     orienting → hypothesizing: Analysis complete, forming hypotheses
     hypothesizing → deciding: Hypotheses formed, planning validation
     deciding → acting: Actions planned, beginning execution
     acting → validating: Actions executed, validating results
     validating → reporting: LLM validation complete, generating report
```

**JSON 파일 (scan_results/scan_*.json):**
```json
{
  "scan_id": "47a2259c",
  "url": "https://hamalab.io",
  "tech_stack": {
    "technologies": {
      "Amazon S3": {"confidence": 0.9},
      "Amazon Web Services": {"confidence": 0.9}
    }
  },
  "vulnerabilities": [],
  "feedback_loop_report": {
    "scan_id": "47a2259c",
    "metrics": {
      "total_loops": 1,
      "observations_made": 1,
      "hypotheses_generated": 5,
      "actions_executed": 5,
      "validations_completed": 5,
      "true_positives": 0,
      "false_positives": 5
    },
    "validated_vulnerabilities": {},
    "transitions": [
      {
        "from": "idle",
        "to": "observing",
        "reason": "Starting observation phase",
        "timestamp": "2024-02-12T10:00:00"
      }
    ]
  },
  "executive_summary": {
    "executive_summary": {
      "overview": "...",
      "key_findings": [...],
      "recommendations": [...]
    }
  },
  "status": "completed",
  "timestamp": "2024-02-12T10:05:00"
}
```

---

## Phase 4: 자동화된 모의 공격 (설계)

### 4.1 개요
**현재 상태:** 설계 단계 (미구현)

Phase 3에서 검증된 취약점을 실제로 안전하게 악용하여 영향도를 측정하는 자동화된 모의 공격 시스템입니다.

### 4.2 설계 원칙

**1. 안전성 최우선**
- 샌드박스 환경에서만 실행
- 자동 롤백 메커니즘
- 데이터 손상 방지
- 격리된 네트워크

**2. 책임 소재 명확화**
- JWT 토큰 기반 명시적 권한 부여
- 모든 액션 로깅
- 사용자 동의 필수
- Policy Engine 권한 제어

**3. 점진적 실행**
- 비파괴적 테스트부터 시작
- 위험도에 따른 단계적 접근
- 각 단계마다 사용자 확인

### 4.3 주요 컴포넌트 (설계)

#### 4.3.1 Exploit Orchestrator

**목적:** 모의 공격 실행 오케스트레이션

**구조:**
```python
class ExploitOrchestrator:
    """
    모의 공격 실행 관리자
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        sandbox_manager: SandboxManager
    ):
        self.policy_engine = policy_engine
        self.sandbox = sandbox_manager
        self.exploits: Dict[str, ExploitModule] = {}

    async def execute_exploit(
        self,
        vulnerability: Dict,
        context: ExecutionContext,
        safety_level: str = "passive"  # passive, active-safe, active-risky
    ) -> ExploitResult:
        """
        취약점에 대한 모의 공격 실행

        Args:
            vulnerability: 취약점 정보
            context: 실행 컨텍스트 (JWT 토큰 포함)
            safety_level: 안전성 수준

        Returns:
            ExploitResult: 실행 결과
        """
        # 1. 권한 확인
        allowed, reason = self.policy_engine.check_permission(
            ActionType.EXPLOIT,
            context
        )

        if not allowed:
            return ExploitResult(
                success=False,
                message=f"Permission denied: {reason}"
            )

        # 2. 샌드박스 생성
        sandbox = await self.sandbox.create(
            vulnerability_id=vulnerability['id'],
            isolation_level="high"
        )

        try:
            # 3. Exploit 모듈 로드
            exploit = self._load_exploit_module(vulnerability['id'])

            # 4. 실행
            result = await exploit.execute(
                target=context.target_url,
                parameters=vulnerability,
                safety_level=safety_level,
                sandbox=sandbox
            )

            # 5. 영향도 측정
            impact = await self._measure_impact(result, sandbox)

            return ExploitResult(
                success=True,
                vulnerability_id=vulnerability['id'],
                exploit_successful=result.exploitable,
                impact=impact,
                evidence=result.evidence,
                logs=result.logs
            )

        finally:
            # 6. 샌드박스 정리 및 롤백
            await sandbox.cleanup()
```

#### 4.3.2 Exploit Modules

**구조:**
```python
class ExploitModule(ABC):
    """
    개별 취약점 Exploit 모듈 베이스 클래스
    """

    @abstractmethod
    async def check_prerequisites(self, target: str) -> bool:
        """전제 조건 확인"""
        pass

    @abstractmethod
    async def execute_passive(self, target: str, params: Dict) -> ExploitResult:
        """비파괴적 테스트 (읽기 전용)"""
        pass

    @abstractmethod
    async def execute_active_safe(self, target: str, params: Dict) -> ExploitResult:
        """안전한 액티브 테스트 (임시 데이터 생성)"""
        pass

    @abstractmethod
    async def execute_active_risky(self, target: str, params: Dict) -> ExploitResult:
        """위험한 액티브 테스트 (데이터 수정)"""
        pass

    @abstractmethod
    async def rollback(self, evidence: Dict) -> bool:
        """변경 사항 롤백"""
        pass


# 예시: SQL Injection Exploit
class SQLInjectionExploit(ExploitModule):
    """
    SQL Injection 모의 공격 모듈
    """

    async def check_prerequisites(self, target: str) -> bool:
        # 데이터베이스 연결 확인
        # 파라미터 발견
        return True

    async def execute_passive(self, target: str, params: Dict) -> ExploitResult:
        """
        단계 1: 비파괴적 테스트
        - Boolean-based blind SQL injection 탐지
        - Error-based SQL injection 탐지
        - 데이터베이스 타입 식별
        """
        payloads = [
            "1' OR '1'='1",
            "1' AND '1'='2",
            "1' UNION SELECT NULL--"
        ]

        for payload in payloads:
            response = await self._send_payload(target, payload)

            if self._is_vulnerable(response):
                return ExploitResult(
                    exploitable=True,
                    method="passive_scan",
                    evidence={
                        "payload": payload,
                        "response_diff": response.diff,
                        "database_type": self._detect_db_type(response)
                    }
                )

        return ExploitResult(exploitable=False)

    async def execute_active_safe(self, target: str, params: Dict) -> ExploitResult:
        """
        단계 2: 안전한 액티브 테스트
        - 임시 테이블 생성
        - 데이터 추출 시도 (읽기 전용)
        """
        # CREATE TEMPORARY TABLE test_table ...
        # SELECT * FROM test_table
        pass

    async def execute_active_risky(self, target: str, params: Dict) -> ExploitResult:
        """
        단계 3: 위험한 액티브 테스트
        - 실제 데이터 수정 시도 (롤백 가능한 경우만)
        - 권한 상승 시도

        ⚠️ 이 단계는 사용자의 명시적 동의와 높은 권한 필요
        """
        # BEGIN TRANSACTION
        # UPDATE test_data SET ...
        # ROLLBACK
        pass
```

**Exploit 모듈 예시:**
```
exploits/
├── sql_injection.py          # SQL Injection
├── xss.py                    # Cross-Site Scripting
├── csrf.py                   # CSRF
├── path_traversal.py         # Path Traversal
├── rce.py                    # Remote Code Execution
├── ssrf.py                   # Server-Side Request Forgery
├── authentication_bypass.py  # 인증 우회
└── ...
```

#### 4.3.3 Sandbox Manager

**목적:** 격리된 실행 환경 제공

**구조:**
```python
class SandboxManager:
    """
    샌드박스 환경 관리자

    컨테이너 기반 격리:
    - Podman/Docker를 사용한 네트워크 격리
    - 리소스 제한 (CPU, 메모리, 디스크)
    - 타임아웃 자동 종료
    """

    async def create(
        self,
        vulnerability_id: str,
        isolation_level: str = "high"
    ) -> Sandbox:
        """
        새로운 샌드박스 생성

        isolation_level:
        - "low": 네트워크 제한만
        - "medium": + 파일시스템 격리
        - "high": + 프로세스 격리
        """
        container_config = {
            "image": "vulner-sandbox:latest",
            "network": "none" if isolation_level == "high" else "restricted",
            "cpu_limit": "0.5",
            "memory_limit": "512m",
            "read_only_rootfs": True,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "timeout": 300  # 5 minutes
        }

        container = await self.container_orch.create_pod(
            pod_name=f"sandbox-{vulnerability_id}",
            **container_config
        )

        return Sandbox(
            container_id=container.id,
            vulnerability_id=vulnerability_id,
            created_at=datetime.now()
        )

    async def cleanup(self, sandbox: Sandbox):
        """샌드박스 정리 및 로그 수집"""
        # 로그 추출
        logs = await self.container_orch.get_logs(sandbox.container_id)

        # 컨테이너 종료
        await self.container_orch.stop_pod(sandbox.container_id)

        # 로그 저장
        await self._save_logs(sandbox.vulnerability_id, logs)
```

#### 4.3.4 Impact Analyzer

**목적:** 모의 공격의 실제 영향도 측정

**구조:**
```python
class ImpactAnalyzer:
    """
    모의 공격 영향도 분석기
    """

    async def analyze_impact(
        self,
        exploit_result: ExploitResult,
        sandbox: Sandbox
    ) -> ImpactReport:
        """
        영향도 분석

        Returns:
            ImpactReport:
            - confidentiality: 기밀성 영향 (0~10)
            - integrity: 무결성 영향 (0~10)
            - availability: 가용성 영향 (0~10)
            - scope: 영향 범위 (local, network, global)
            - severity: 최종 심각도
        """
        # 1. 데이터 접근 분석
        data_access = await self._analyze_data_access(exploit_result)

        # 2. 시스템 변경 분석
        system_changes = await self._analyze_system_changes(sandbox)

        # 3. 네트워크 영향 분석
        network_impact = await self._analyze_network_impact(sandbox)

        # 4. CIA Triad 계산
        confidentiality = self._calculate_confidentiality(data_access)
        integrity = self._calculate_integrity(system_changes)
        availability = self._calculate_availability(network_impact)

        # 5. 최종 점수
        impact_score = (confidentiality + integrity + availability) / 3

        return ImpactReport(
            vulnerability_id=exploit_result.vulnerability_id,
            confidentiality_impact=confidentiality,
            integrity_impact=integrity,
            availability_impact=availability,
            impact_score=impact_score,
            severity=self._calculate_severity(impact_score),
            scope=self._determine_scope(data_access, system_changes),
            evidence=exploit_result.evidence,
            recommendations=self._generate_recommendations(impact_score)
        )
```

### 4.4 실행 시나리오

**시나리오 1: SQL Injection 모의 공격**

```python
# 1. 사용자가 취약점 선택
vulnerability = {
    "id": "CVE-2024-1234",
    "type": "SQL Injection",
    "severity": "HIGH"
}

# 2. 권한 토큰 생성 (사용자 동의 필요)
token = policy_engine.generate_token(
    user_id="user-123",
    permissions=["scan", "exploit"],
    expires_in_hours=1
)

context = ExecutionContext(
    target_url="https://vulnerable-app.example.com",
    user_id="user-123",
    authorization_token=token
)

# 3. 모의 공격 실행 (3단계)
orchestrator = ExploitOrchestrator(policy_engine, sandbox_manager)

# 3.1. Passive 스캔 (비파괴적)
result_passive = await orchestrator.execute_exploit(
    vulnerability=vulnerability,
    context=context,
    safety_level="passive"
)

if result_passive.exploitable:
    print(f"✅ Passive 스캔: 취약점 확인됨")
    print(f"   Database Type: {result_passive.evidence['database_type']}")

    # 3.2. Active Safe 테스트 (임시 데이터)
    result_safe = await orchestrator.execute_exploit(
        vulnerability=vulnerability,
        context=context,
        safety_level="active-safe"
    )

    if result_safe.exploitable:
        print(f"✅ Active Safe 테스트: 데이터 추출 가능")
        print(f"   Extracted Records: {result_safe.evidence['record_count']}")

        # 3.3. Active Risky 테스트 (사용자 재확인 필요)
        user_confirmed = ask_user_confirmation(
            "⚠️ 위험한 테스트를 진행하시겠습니까? (데이터 수정 시도)"
        )

        if user_confirmed:
            result_risky = await orchestrator.execute_exploit(
                vulnerability=vulnerability,
                context=context,
                safety_level="active-risky"
            )

            if result_risky.exploitable:
                print(f"⚠️ Active Risky 테스트: 데이터 수정 가능")
                print(f"   Impact: {result_risky.impact}")

# 4. 영향도 분석
impact_analyzer = ImpactAnalyzer()
impact_report = await impact_analyzer.analyze_impact(
    result_risky,
    sandbox
)

print(f"\n📊 영향도 분석:")
print(f"   기밀성: {impact_report.confidentiality_impact}/10")
print(f"   무결성: {impact_report.integrity_impact}/10")
print(f"   가용성: {impact_report.availability_impact}/10")
print(f"   최종 점수: {impact_report.impact_score}/10")
print(f"   심각도: {impact_report.severity}")
```

**출력 예시:**
```
✅ Passive 스캔: 취약점 확인됨
   Database Type: PostgreSQL 13.0
   Method: Boolean-based blind SQL injection
   Payload: ' OR '1'='1'--

✅ Active Safe 테스트: 데이터 추출 가능
   Extracted Records: 1,234
   Tables Accessed: users, sessions
   Sensitive Data Found: email addresses, user IDs

⚠️ Active Risky 테스트 실행 중...
   Transaction Started: YES
   Data Modified: 1 record (test entry)
   Rollback Successful: YES

📊 영향도 분석:
   기밀성: 9/10 (전체 사용자 데이터 접근 가능)
   무결성: 7/10 (데이터 수정 가능, 롤백 가능)
   가용성: 3/10 (서비스 중단 가능성 낮음)

   최종 점수: 6.3/10
   심각도: HIGH
   영향 범위: Network (동일 네트워크 내 모든 사용자)

✅ 권장 조치사항:
   1. 즉시 Prepared Statement로 모든 SQL 쿼리 변경
   2. 입력 검증 및 sanitization 강화
   3. 최소 권한 원칙 적용 (DB 사용자 권한 제한)
   4. WAF 규칙 추가 (SQL injection 패턴 차단)
```

### 4.5 안전장치

**1. 다중 권한 확인**
```python
# Level 1: JWT 토큰 확인
allowed = policy_engine.check_permission(ActionType.EXPLOIT, context)

# Level 2: Safety Level 확인
if safety_level == "active-risky":
    require_high_privilege_token()

# Level 3: 사용자 재확인
if destructive_action:
    user_confirmation = await ask_user_confirmation()
```

**2. 자동 롤백**
```python
try:
    result = await execute_exploit()
except Exception as e:
    await automatic_rollback()
    raise
finally:
    await cleanup_sandbox()
```

**3. 타임아웃**
```python
# 모든 exploit 실행은 5분 제한
async with timeout(300):
    result = await exploit.execute()
```

**4. 감사 로깅**
```python
audit_log.record({
    "action": "exploit_execution",
    "user_id": context.user_id,
    "vulnerability_id": vulnerability['id'],
    "safety_level": safety_level,
    "timestamp": datetime.now(),
    "result": result.to_dict()
})
```

### 4.6 Phase 4 구현 우선순위

**Phase 4.1 (우선순위 1):**
- [ ] Exploit Orchestrator 기본 구조
- [ ] Sandbox Manager (Podman 통합)
- [ ] SQL Injection Exploit 모듈
- [ ] XSS Exploit 모듈
- [ ] Impact Analyzer 기본 기능

**Phase 4.2 (우선순위 2):**
- [ ] CSRF Exploit 모듈
- [ ] Path Traversal Exploit 모듈
- [ ] Authentication Bypass Exploit 모듈
- [ ] 자동 롤백 메커니즘
- [ ] 상세 리포팅

**Phase 4.3 (우선순위 3):**
- [ ] RCE Exploit 모듈
- [ ] SSRF Exploit 모듈
- [ ] 고급 Impact Analysis
- [ ] 웹 UI 대시보드
- [ ] 자동화된 remediation 제안

---

## 부록

### A. 데이터 흐름도

```
┌─────────────┐
│   사용자    │
└──────┬──────┘
       │ URL 입력
       ▼
┌─────────────────────────────────────────┐
│          Phase 2: 탐지 & 조회            │
├─────────────────────────────────────────┤
│ 1. TechStackDetector                    │
│    - Wappalyzer, HTTP 헤더, HTML 분석   │
│    ↓                                    │
│ 2. VulnerabilityDatabase                │
│    - OSV.dev + NVD 병렬 조회            │
│    ↓                                    │
│ 3. VectorStore (선택)                   │
│    - 임베딩 생성 및 저장                 │
└──────────────┬──────────────────────────┘
               │ 취약점 목록
               ▼
┌─────────────────────────────────────────┐
│       Phase 3: AI 검증 & 필터링          │
├─────────────────────────────────────────┤
│ 1. FeedbackLoopStateMachine             │
│    - OBSERVING → ORIENTING              │
│    - HYPOTHESIZING → DECIDING           │
│    - ACTING → VALIDATING                │
│    ↓                                    │
│ 2. LLMVulnerabilityValidator            │
│    - GPT-4o-mini 기반 검증              │
│    - 오탐 필터링                         │
│    ↓                                    │
│ 3. VulnerabilityAnalyzer                │
│    - 취약점 요약 (한국어)                │
│    - 경영진 리포트 생성                  │
│    ↓                                    │
│ 4. FeedbackLoopPersistence              │
│    - SQLite에 상태 저장                 │
└──────────────┬──────────────────────────┘
               │ 검증된 취약점
               ▼
┌─────────────────────────────────────────┐
│       Phase 4: 모의 공격 (설계)          │
├─────────────────────────────────────────┤
│ 1. PolicyEngine                         │
│    - JWT 권한 확인                      │
│    ↓                                    │
│ 2. ExploitOrchestrator                  │
│    - Exploit 모듈 실행                  │
│    ↓                                    │
│ 3. SandboxManager                       │
│    - 격리된 환경에서 실행                │
│    ↓                                    │
│ 4. ImpactAnalyzer                       │
│    - 영향도 측정                         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│           최종 리포트                    │
├─────────────────────────────────────────┤
│ • JSON 파일                             │
│ • SQLite 데이터베이스                    │
│ • 콘솔 출력                             │
│ • AI 요약 (한국어)                      │
│ • 경영진 보고서                          │
└─────────────────────────────────────────┘
```

### B. 파일 구조

```
vulner/
├── src/
│   ├── detection/
│   │   └── tech_stack_detector.py      # Phase 2: 기술 스택 탐지
│   ├── vulnerability/
│   │   └── vuln_database.py            # Phase 2: 취약점 조회
│   ├── database/
│   │   ├── vector_store.py             # Phase 2: 벡터 DB
│   │   └── embedding_cache.py          # Phase 2: 임베딩 캐시
│   ├── policy/
│   │   └── engine.py                   # Phase 3: 권한 제어
│   ├── feedback/
│   │   ├── state_machine.py            # Phase 3: OODA Loop
│   │   ├── llm_validator.py            # Phase 3: LLM 검증
│   │   └── persistence.py              # Phase 3: SQLite 저장
│   ├── analysis/
│   │   └── vulnerability_analyzer.py   # Phase 3: AI 분석
│   └── exploit/                        # Phase 4 (설계)
│       ├── orchestrator.py
│       ├── sandbox_manager.py
│       ├── impact_analyzer.py
│       └── modules/
│           ├── sql_injection.py
│           ├── xss.py
│           └── ...
├── .feedback/
│   ├── feedback_loop.db                # SQLite 데이터베이스
│   └── {scan_id}/
│       ├── state.json                  # 상태 파일
│       └── feedback_report.json        # 리포트
├── .cache/
│   ├── llm_validation/                 # LLM 검증 캐시
│   └── analysis/                       # AI 분석 캐시
└── scan_results/
    └── scan_*.json                     # 최종 스캔 결과
```

### C. 환경 변수

```bash
# .env 파일

# OpenAI API (Phase 3 필수)
OPENAI_API_KEY=sk-...

# Supabase (벡터 DB, 선택)
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=eyJ...

# NVD API (선택, 더 높은 속도 제한)
NVD_API_KEY=xxx

# 컨테이너 런타임
CONTAINER_RUNTIME=podman  # 또는 docker

# Policy Engine
JWT_SECRET=your-secret-key-change-in-production
REQUIRE_AUTHORIZATION=false  # Phase 4에서 true로 변경

# LLM 모델
LLM_MODEL=gpt-4o-mini  # 또는 gpt-4o

# 캐시 설정
CACHE_TTL_HOURS=24
```

---

## 버전 히스토리

| 버전 | 날짜 | 변경 사항 |
|------|------|----------|
| 1.0 | 2026-02-12 | 초안 작성 (Phase 2~4 기능 정의) |

---

## 연락처

**프로젝트:** Vulner - 지능형 취약점 평가 플랫폼
**저장소:** /Users/edith/Projects/vulner
**문서 위치:** docs/FEATURE_SPEC_PHASE2-4.md
