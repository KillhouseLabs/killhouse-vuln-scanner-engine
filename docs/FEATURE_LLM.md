OpenAI API는 마지막 요약뿐만 아니라 전체 파이프라인의 핵심 의사결정 지점에서 활용됩니다.
현재 코드베이스에서도 이미 여러 곳에서 사용 중이고, SAST+DAST 통합 시 더 많은 곳에서 활용됩니다.

## 1. 현재 코드베이스의 LLM 사용 (Phase 3)

### 1.1 취약점 검증 (가장 중요)

```python
# src/feedback/feedback_loop.py:245-280
async def _validate_with_llm(self, hypothesis: ValidationHypothesis) -> bool:
   """
   LLM을 사용한 취약점 검증

   역할: 발견된 취약점이 실제로 악용 가능한지 판단
   """
   prompt = f"""
   Vulnerability: {hypothesis.cve_id}
   Technology: {hypothesis.tech_stack}
   Environment: {hypothesis.context}

   Question: Is this vulnerability actually exploitable in this context?
   Consider:
   1. Is the vulnerable version actually in use?
   2. Is the vulnerable function/module actually called?
   3. Are there mitigating controls?
   4. Is the attack vector accessible?

   Answer: exploitable (true/false) with reasoning
   """
```
실제 사례 (hamalab.io):
- 발견: 41개 CVE (django-s3file, aws-s3-form 등)
- LLM 판단: "S3 호스팅 서비스 사용, 클라이언트 라이브러리 CVE는 무관" → exploitable=false
- 결과: 0개 검증됨 (정확한 필터링)

### 1.2 Executive Summary 생성
```python
# src/analysis/vulnerability_analyzer.py:241-290
async def _generate_executive_summary(
   self,
   vulnerabilities: List[dict],
   total_found: int,
   validated_count: int
) -> dict:
   """
   비기술 이해관계자를 위한 요약 생성 (한국어)
   """
   prompt = f"""
   총 발견: {total_found}개
   검증됨: {validated_count}개

   Generate executive summary in Korean:
   1. 개요 (비기술적 언어)
   2. 주요 발견사항
   3. 핵심 위험 요소
   4. 권장 조치사항
   5. 타임라인
   """
```
---
## 2. SAST+DAST 통합 시 LLM 활용 확대

### Phase 1: SAST 결과 분석 (신규)

```python
# src/sast/code_analyzer.py
async def analyze_sast_finding(self, finding: dict) -> dict:
   """
   SAST 도구의 오탐 필터링

   문제: Semgrep/Bandit은 패턴 매칭만 하므로 False Positive 많음
   해결: LLM이 실제 코드 컨텍스트 분석
   """

   prompt = f"""
   SAST Tool: {finding['tool']}
   File: {finding['file']}
   Line: {finding['line']}
   Code:
   \`\`\`python
   {finding['code_snippet']}
   \`\`\`

   Surrounding context:
   {get_surrounding_code(finding['file'], finding['line'], context=10)}

   Finding: {finding['message']}
   Severity: {finding['severity']}

   Questions:
   1. Is this a true positive or false positive?
   2. If true positive, what is the actual risk level?
   3. Is there input validation elsewhere that mitigates this?
   4. What is the attack vector and exploitability?

   Respond in JSON:
   {{
     "is_true_positive": true/false,
     "actual_severity": "CRITICAL/HIGH/MEDIUM/LOW",
     "reasoning": "...",
     "exploitability": "CONFIRMED/LIKELY/UNLIKELY/IMPOSSIBLE",
     "mitigations_present": ["..."],
     "attack_vector": "..."
   }}
   """

   response = await openai.chat.completions.create(
       model="gpt-4o",
       messages=[{"role": "user", "content": prompt}],
       response_format={"type": "json_object"}
   )
```
예시:
```python
# SAST 발견
finding = {
   "tool": "semgrep",
   "message": "Potential SQL Injection",
   "code": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
   "severity": "CRITICAL"
}

# LLM 분석 결과
llm_analysis = {
   "is_true_positive": True,
   "actual_severity": "CRITICAL",
   "reasoning": """
   직접적인 SQL Injection 취약점.
   req.params.id가 사용자 입력이고 아무런 검증 없이 쿼리에 삽입됨.
   parameterized query나 ORM 사용 필요.
   """,
   "exploitability": "CONFIRMED",
   "mitigations_present": [],
   "attack_vector": "GET /api/users/:id?id=1' OR '1'='1"
}
```
반대 예시 (False Positive):
```python
# SAST 발견
finding = {
   "tool": "bandit",
   "message": "Use of exec() detected",
   "code": "exec(code)",
   "severity": "HIGH"
}

# 전체 코드 컨텍스트
context = """
def safe_calculator(expression: str):
   # Whitelist validation
   if not re.match(r'^[0-9+\-*/() ]+$', expression):
       raise ValueError("Invalid expression")

   # Additional safety: evaluate in restricted namespace
   exec(f"result = {expression}", {"__builtins__": {}}, local_vars)
   return local_vars['result']
"""

# LLM 분석
llm_analysis = {
   "is_true_positive": False,
   "actual_severity": "LOW",
   "reasoning": """
   exec() 사용되지만 강력한 완화 조치 존재:
   1. 정규식으로 숫자와 연산자만 허용
   2. __builtins__ 비활성화로 위험한 함수 호출 불가
   실제 공격 벡터 없음.
   """,
   "exploitability": "IMPOSSIBLE",
   "mitigations_present": ["input_validation", "restricted_namespace"]
}
```

---
## Phase 2: CVE 적용 가능성 판단 (현재 + 강화)

```python
# src/sca/cve_validator.py
async def validate_cve_applicability(
   self,
   cve: dict,
   dependency: dict,
   codebase_analysis: dict
) -> dict:
   """
   CVE가 실제 코드베이스에 적용되는지 판단

   기존: 단순 버전 체크
   개선: LLM이 실제 사용 여부 분석
   """

   prompt = f"""
   CVE Information:
   - ID: {cve['id']}
   - Affected Package: {cve['package']}
   - Vulnerable Versions: {cve['affected_versions']}
   - Vulnerability Type: {cve['type']}
   - Affected Functions: {cve['affected_functions']}

   Project Information:
   - Package Version: {dependency['version']}
   - Import Statements: {codebase_analysis['imports']}
   - Function Calls: {codebase_analysis['function_calls']}

   Code Usage Examples:
   \`\`\`python
   {codebase_analysis['usage_examples']}
   \`\`\`

   Questions:
   1. Is the vulnerable version in use? (consider version ranges)
   2. Are the affected functions actually called in the code?
   3. Is the vulnerable code path reachable?
   4. Are there framework-level mitigations?

   Respond in JSON:
   {{
     "is_applicable": true/false,
     "confidence": 0.0-1.0,
     "reasoning": "...",
     "affected_code_locations": ["file:line", ...],
     "risk_level": "CRITICAL/HIGH/MEDIUM/LOW"
   }}
   """
```
실제 예시 (lodash Prototype Pollution):
```python
# CVE 정보
cve = {
   "id": "CVE-2021-23337",
   "package": "lodash",
   "affected_versions": "< 4.17.21",
   "affected_functions": ["merge", "mergeWith", "defaultsDeep"]
}

# 프로젝트 분석
codebase_analysis = {
   "version": "4.17.20",  # 취약 버전!
   "imports": [
       "import _ from 'lodash'",
       "import { merge } from 'lodash'"
   ],
   "function_calls": [
       "_.merge(config, userInput)",  # 위험!
       "_.map(array, fn)",             # 안전
       "_.debounce(callback, 300)"     # 안전
   ]
}

# LLM 판단
validation = {
   "is_applicable": True,
   "confidence": 0.95,
   "reasoning": """
   1. 취약 버전 사용 중 (4.17.20 < 4.17.21) ✓
   2. 취약 함수 merge() 직접 사용 중 ✓
   3. 사용자 입력(userInput)을 merge에 전달 ✓
   4. Prototype Pollution 공격 가능

   공격 시나리오:
   userInput = {"__proto__": {"isAdmin": true}}
   _.merge(config, userInput)
   → 모든 객체에 isAdmin=true 주입 가능
   """,
   "affected_code_locations": [
       "src/config/loader.js:42"
   ],
   "risk_level": "CRITICAL"
}
```
---
## Phase 3: DAST 결과 해석 (신규)

```python
# src/dast/result_interpreter.py
async def interpret_dast_response(
   self,
   test: dict,
   response: dict
) -> dict:
   """
   DAST 도구의 HTTP 응답이 실제 취약점인지 판단

   문제: DAST 도구는 HTTP 상태 코드/응답만 보고 판단
   해결: LLM이 응답 내용의 의미 분석
   """

   prompt = f"""
   DAST Test:
   URL: {test['url']}
   Method: {test['method']}
   Payload: {test['payload']}
   Expected Vulnerability: {test['vulnerability_type']}

   Response:
   Status Code: {response['status_code']}
   Headers:
   {json.dumps(response['headers'], indent=2)}

   Body:
   {response['body'][:1000]}  # 처음 1000자

   Questions:
   1. Does the response indicate successful exploitation?
   2. Is this a false positive (e.g., WAF block, error page)?
   3. What data was leaked or manipulated?
   4. What is the actual impact?

   Respond in JSON:
   {{
     "is_exploitable": true/false,
     "confidence": 0.0-1.0,
     "evidence": "...",
     "impact": {{"data_leaked": [...], "functions_compromised": [...]}},
     "severity": "CRITICAL/HIGH/MEDIUM/LOW"
   }}
   """
```
예시 1: True Positive (SQL Injection)
```python
# DAST 테스트
test = {
   "url": "http://127.0.0.1:3000/api/users?id=1' OR '1'='1",
   "payload": "1' OR '1'='1",
   "vulnerability_type": "SQL Injection"
}

# 응답
response = {
   "status_code": 200,
   "body": """
   [
     {"id": 1, "name": "Alice", "email": "alice@example.com"},
     {"id": 2, "name": "Bob", "email": "bob@example.com"},
     {"id": 3, "name": "Charlie", "email": "charlie@example.com"},
     ...
     {"id": 500, "name": "Zara", "email": "zara@example.com"}
   ]
   """
}

# LLM 해석
interpretation = {
   "is_exploitable": True,
   "confidence": 0.99,
   "evidence": """
   정상 요청 (?id=1)은 1개 레코드 반환 예상.
   SQL Injection 페이로드로 500개 레코드 반환됨.
   OR '1'='1' 조건이 모든 행을 반환하도록 만듦.
   """,
   "impact": {
       "data_leaked": ["user_emails", "user_names"],
       "records_exposed": 500
   },
   "severity": "CRITICAL"
}
```
예시 2: False Positive (WAF 차단)
```python
# DAST 테스트
test = {
   "url": "http://127.0.0.1:3000/api/users?id=1' OR '1'='1",
   "payload": "1' OR '1'='1",
   "vulnerability_type": "SQL Injection"
}

# 응답
response = {
   "status_code": 403,
   "body": """
   <html>
     <head><title>403 Forbidden</title></head>
     <body>
       <h1>ModSecurity Action</h1>
       <p>Your request has been blocked by our Web Application Firewall.</p>
       <p>Rule ID: 942100 (SQL Injection Attack Detected)</p>
     </body>
   </html>
   """
}

# LLM 해석
interpretation = {
   "is_exploitable": False,
   "confidence": 0.95,
   "evidence": """
   403 상태 코드와 ModSecurity 메시지 확인됨.
   WAF가 SQL Injection 패턴을 탐지하고 차단함.
   실제 DB 쿼리 실행 전에 차단되어 취약점 악용 불가.

   주의: WAF 우회 가능성 있으므로 코드 수정 여전히 권장.
   """,
   "impact": {
       "blocked_by": "ModSecurity WAF"
   },
   "severity": "MEDIUM"  # 완화됨
}
```
---
Phase 4: False Positive 통합 필터링 (신규)
```python
# src/integration/validator.py
async def cross_validate_findings(
   self,
   sast_result: dict,
   cve_result: dict,
   dast_result: dict
) -> dict:
   """
   SAST, CVE, DAST 결과를 종합 분석

   역할: 3가지 소스의 일치/불일치 해석
   """

   prompt = f"""
   Vulnerability Assessment Summary:

   1. SAST Finding:
      Tool: {sast_result['tool']}
      Issue: {sast_result['message']}
      File: {sast_result['file']}:{sast_result['line']}
      Code: {sast_result['code']}
      LLM Analysis: {sast_result['llm_analysis']}

   2. CVE Match:
      {f"CVE-{cve_result['id']}: {cve_result['description']}" if cve_result else "No matching CVE
found"}
      {f"Applicability: {cve_result['llm_validation']}" if cve_result else ""}

   3. DAST Result:
      {f"Exploit attempted: {dast_result['test_case']}" if dast_result else "Build failed, no DAST
performed"}
      {f"Result: {dast_result['llm_interpretation']}" if dast_result else ""}

   Validation Matrix:
   - SAST says: {sast_result['llm_analysis']['is_true_positive']}
   - CVE says: {cve_result['llm_validation']['is_applicable'] if cve_result else 'N/A'}
   - DAST says: {dast_result['llm_interpretation']['is_exploitable'] if dast_result else 'N/A'}

   Question: What is the final verdict?

   Consider:
   1. Do all three sources agree?
   2. If they disagree, which one is most reliable in this case?
   3. What is the actual risk to the organization?
   4. What is the recommended priority?

   Respond in JSON:
   {{
     "final_verdict": "CONFIRMED/LIKELY/UNLIKELY/FALSE_POSITIVE",
     "confidence": 0.0-1.0,
     "reasoning": "...",
     "priority": "P0/P1/P2/P3",
     "recommended_action": "..."
   }}
   """
```
예시: 3-Way 일치 (최고 신뢰도)
```python
# 입력
findings = {
   "sast": {
       "is_true_positive": True,
       "message": "SQL Injection in user search",
       "confidence": 0.9
   },
   "cve": {
       "matched": False,  # 커스텀 코드 취약점
       "reason": "Not a dependency issue"
   },
   "dast": {
       "is_exploitable": True,
       "evidence": "500 records leaked",
       "confidence": 0.99
   }
}

# LLM 최종 판단
final_verdict = {
   "final_verdict": "CONFIRMED",
   "confidence": 0.99,
   "reasoning": """
   강력한 3단계 검증:
   1. SAST: 코드에서 패턴 발견 ✓
   2. CVE: 해당 없음 (커스텀 코드)
   3. DAST: 실제 exploit 성공 ✓

   SAST와 DAST 모두 긍정적 → 확실한 취약점.
   CVE 없음은 문제 없음 (모든 취약점이 CVE는 아님).
   """,
   "priority": "P0",
   "recommended_action": "즉시 수정. 프로덕션 배포 금지."
}
```
예시: 불일치 (SAST만 양성)
```python
# 입력
findings = {
   "sast": {
       "is_true_positive": True,
       "message": "Hardcoded password",
       "code": 'DEFAULT_PASSWORD = "admin123"',
       "confidence": 0.8
   },
   "cve": {
       "matched": False
   },
   "dast": {
       "is_exploitable": False,
       "evidence": "Login failed with default password",
       "confidence": 0.95
   }
}

# LLM 최종 판단
final_verdict = {
   "final_verdict": "FALSE_POSITIVE",
   "confidence": 0.9,
   "reasoning": """
   SAST가 하드코딩된 비밀번호 발견했으나:
   1. 변수명은 DEFAULT_PASSWORD (실제 사용 의심)
   2. DAST에서 실제 로그인 시도했으나 실패
   3. 코드 리뷰 결과: 테스트용 플레이스홀더로 판명

   실제 프로덕션에서는 환경변수 사용 중.
   """,
   "priority": "P3",
   "recommended_action": "코드 주석 추가로 명확화. 실제 위험 없음."
}
```
---
## Phase 5: 우선순위화 (신규)
```python
# src/ai/priority_ranker.py
async def rank_vulnerabilities(
   self,
   vulnerabilities: List[dict],
   business_context: dict
) -> List[dict]:
   """
   비즈니스 영향도 기반 우선순위화

   역할: CVSS 점수만으로는 부족, 실제 영향도 고려
   """

   prompt = f"""
   Application Context:
   - Type: {business_context['app_type']}  # e.g., "e-commerce"
   - Users: {business_context['user_count']}
   - Data Sensitivity: {business_context['data_types']}  # e.g., ["PII", "payment_info"]
   - Compliance: {business_context['regulations']}  # e.g., ["GDPR", "PCI-DSS"]

   Vulnerabilities Found:
   {json.dumps(vulnerabilities, indent=2)}

   Question: Rank these by actual business impact, not just technical severity.

   Consider:
   1. What data is at risk?
   2. How many users are affected?
   3. What are the compliance implications?
   4. What is the exploit difficulty?
   5. Is this in a critical business flow?

   Respond in JSON with ranked list:
   [
     {{
       "vulnerability_id": "...",
       "priority": 1,
       "business_impact": "...",
       "compliance_impact": "...",
       "recommended_timeline": "..."
     }},
     ...
   ]
   """
```
---
## Phase 6: 자동 수정 제안 (신규)
```python
# src/ai/fix_suggester.py
async def suggest_fix(
   self,
   vulnerability: dict,
   code_context: dict
) -> dict:
   """
   수정 코드 자동 생성

   역할: 개발자가 즉시 적용 가능한 패치 제공
   """

   prompt = f"""
   Vulnerability:
   {vulnerability['description']}

   Current Code:
   \`\`\`{code_context['language']}
   {code_context['vulnerable_code']}
   \`\`\`

   File Context:
   {code_context['surrounding_code']}

   Framework: {code_context['framework']}  # e.g., Express.js, Django

   Task: Generate a secure fix for this vulnerability.

   Requirements:
   1. Fix the vulnerability completely
   2. Maintain backward compatibility if possible
   3. Follow framework best practices
   4. Include comments explaining the fix
   5. Suggest any additional changes (e.g., add validation middleware)

   Respond in JSON:
   {{
     "fixed_code": "...",
     "diff": "...",
     "explanation": "...",
     "additional_changes": [...],
     "testing_suggestions": [...]
   }}
   """
```
예시:
```python
# 입력
vulnerability = {
   "type": "SQL Injection",
   "code": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"
}

# LLM 제안
fix = {
   "fixed_code": """
   // Parameterized query prevents SQL Injection
   db.query(
     'SELECT * FROM users WHERE id = ?',
     [req.params.id]
   )
   """,
   "diff": """
   - db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
   + db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
   """,
   "explanation": """
   변경사항:
   1. 템플릿 리터럴 제거
   2. Parameterized query (?) 사용
   3. 사용자 입력을 배열로 전달

   이렇게 하면 DB 드라이버가 자동으로 이스케이프 처리.
   """,
   "additional_changes": [
       "Add input validation: if (!Number.isInteger(Number(req.params.id))) return 400",
       "Consider using ORM (Sequelize/TypeORM) for automatic escaping"
   ],
   "testing_suggestions": [
       "Test with normal ID: /api/users/1",
       "Test with SQL injection: /api/users/1' OR '1'='1 (should return 400)",
       "Test with non-numeric: /api/users/abc (should return 400)"
   ]
}
```
---
## Phase 7: 빌드 실패 해석 (신규)
```python
# src/build/error_analyzer.py
async def analyze_build_failure(
   self,
   build_log: str,
   project_info: dict
) -> dict:
   """
   빌드 실패 원인 분석 및 해결 방법 제안
   """

   prompt = f"""
   Build Log:
   {build_log[-2000:]}  # 마지막 2000자

   Project Info:
   - Language: {project_info['language']}
   - Framework: {project_info['framework']}
   - Dependencies: {project_info['dependency_file']}

   Question: Why did the build fail and how to fix it?

   Respond in JSON:
   {{
     "root_cause": "...",
     "missing_dependencies": [...],
     "env_vars_needed": [...],
     "suggested_fixes": [...],
     "can_proceed_without_dast": true/false
   }}
   """
```
---
## 3. LLM 사용 위치 요약
┌───────────────┬───────────────┬───────────────────────────┬────────────┐
│     Phase     │ LLM 사용 여부 │           역할            │   중요도   │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 1. SAST       │ ✅ 필수       │ False Positive 필터링     │ ⭐⭐⭐⭐⭐ │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 2. CVE 매칭   │ ✅ 필수       │ 실제 적용 가능성 판단     │ ⭐⭐⭐⭐⭐ │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 3. 빌드       │ ✅ 선택       │ 빌드 에러 해석            │ ⭐⭐⭐     │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 4. DAST       │ ✅ 필수       │ 응답 해석 및 exploit 판단 │ ⭐⭐⭐⭐⭐ │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 5. 통합 검증  │ ✅ 필수       │ 3-way 교차검증            │ ⭐⭐⭐⭐⭐ │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 6. 우선순위화 │ ✅ 필수       │ 비즈니스 영향도 평가      │ ⭐⭐⭐⭐   │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 7. 수정 제안  │ ✅ 선택       │ 자동 패치 생성            │ ⭐⭐⭐⭐   │
├───────────────┼───────────────┼───────────────────────────┼────────────┤
│ 8. 보고서     │ ✅ 필수       │ Executive Summary         │ ⭐⭐⭐⭐   │
└───────────────┴───────────────┴───────────────────────────┴────────────┘
---
## 4. 비용 최적화 전략

### 4.1 모델 선택

LLM_USAGE_STRATEGY = {
   "sast_analysis": {
       "model": "gpt-4o-mini",      # 빠르고 저렴
       "reason": "패턴 분석은 간단"
   },
   "cve_validation": {
       "model": "gpt-4o",            # 정확도 중요
       "reason": "복잡한 의존성 추론"
   },
   "dast_interpretation": {
       "model": "gpt-4o-mini",
       "reason": "HTTP 응답 분석은 간단"
   },
   "cross_validation": {
       "model": "gpt-4o",            # 최종 판단
       "reason": "종합 분석, 정확도 최우선"
   },
   "priority_ranking": {
       "model": "gpt-4o",
       "reason": "비즈니스 컨텍스트 이해 필요"
   },
   "fix_suggestion": {
       "model": "gpt-4o",
       "reason": "코드 생성 품질 중요"
   },
   "executive_summary": {
       "model": "gpt-4o-mini",
       "reason": "요약만 하면 됨"
   }
}

### 4.2 캐싱 전략
```python
# 동일한 CVE에 대한 LLM 판단은 캐싱
cache_key = f"cve_validation:{cve_id}:{package}:{version}"
if cached := redis.get(cache_key):
   return cached

result = await openai_validate(cve, package, version)
redis.setex(cache_key, 86400, result)  # 24시간 캐싱
```
### 4.3 배치 처리
```python
# 여러 취약점을 한 번에 분석 (토큰 효율)
prompt = f"""
Analyze these {len(vulnerabilities)} vulnerabilities in one go:

1. {vuln1}
2. {vuln2}
...

Return JSON array with analysis for each.
"""
```
---
## 5. 최종 워크플로우
```
┌─────────────────────────────────────────────┐
│  1. SAST 실행                                │
│     ├─ Semgrep 스캔                          │
│     └─ 🤖 LLM: False Positive 필터링          │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  2. CVE 쿼리                                 │
│     ├─ OSV.dev + NVD                        │
│     └─ 🤖 LLM: 적용 가능성 판단                 │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  3. 빌드 & 실행                               │
│     ├─ Docker build                         │
│     └─ 🤖 LLM: 빌드 에러 해석 (실패 시)          │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  4. DAST 실행                                │
│     ├─ OWASP ZAP 스캔                        │
│     └─ 🤖 LLM: 응답 해석 & Exploit 판단         │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  5. 통합 분석                                 │
│     └─ 🤖 LLM: 3-Way 교차검증                  │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  6. 우선순위화                                 │
│     └─ 🤖 LLM: 비즈니스 영향도 평가               │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  7. 수정 제안                                 │
│     └─ 🤖 LLM: 자동 패치 코드 생성               │
└─────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│  8. 보고서 생성                                │
│     └─ 🤖 LLM: Executive Summary            │
└─────────────────────────────────────────────┘
```
LLM 호출 횟수: 스캔당 평균 20~50회
예상 비용: 스캔당 $0.50 ~ $2.00 (프로젝트 크기에 따라)

---
## 결론

OpenAI API는 단순 요약이 아니라 전체 파이프라인의 두뇌 역할을 합니다:

1. SAST 정확도 향상: 80% → 95%
2. CVE 적용성 판단: hamalab.io 41→0 같은 정확한 필터링
3. DAST 결과 해석: WAF 차단 vs 실제 exploit 구분
4. 통합 검증: 3가지 소스 교차 분석
5. 비즈니스 우선순위: CVSS만으로는 부족한 실제 영향도
6. 자동 수정: 개발자 생산성 10배 향상
7. Executive Summary: 비기술 이해관계자 소통

LLM 없이는 불가능한 것들:
- False Positive 90% 제거
- 컨텍스트 기반 위험도 평가
- 자연어 설명 및 수정 제안

이게 바로 AI-Powered Security Platform의 핵심 차별점입니다!
