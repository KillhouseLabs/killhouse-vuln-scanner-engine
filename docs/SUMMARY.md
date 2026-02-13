## 📋 문서 구성

### Phase 2: 기술 스택 탐지 및 취약점 조회 ✅ 구현 완료

  - TechStackDetector: Wappalyzer, HTTP 헤더, HTML, 메타 태그 분석 (4가지 방법 병렬 실행)
  - VulnerabilityDatabase: OSV.dev + NVD 병렬 조회, 24시간 캐싱
  - VectorStore: Supabase pgvector 기반 의미론적 검색 (선택)
  - 출력: 탐지된 기술 스택 + 41개 취약점 목록

### Phase 3: Feedback Loop 및 AI 검증 ✅ 구현 완료

  - Policy Engine: JWT 기반 권한 제어 (책임 소재 명확화)
  - Feedback Loop State Machine: OODA Loop 8단계
    - IDLE → OBSERVING → ORIENTING → HYPOTHESIZING → DECIDING → ACTING → VALIDATING → REPORTING
  - LLM Validator: GPT-4o-mini로 실제 악용 가능성 검증 (오탐 필터링)
  - Vulnerability Analyzer: 한국어 요약 + 경영진 보고서 생성
  - Persistence: SQLite에 모든 상태 및 메트릭 저장
  - 출력: 검증된 0개 취약점 (41개 중 모두 필터링)

### Phase 4: 자동화된 모의 공격 🎯 설계 단계

  - Exploit Orchestrator: 모의 공격 실행 관리
  - Exploit Modules: SQL Injection, XSS, CSRF 등 개별 모듈
  - Sandbox Manager: Podman/Docker 기반 격리 환경
  - Impact Analyzer: CIA Triad 기반 영향도 측정
  - 3단계 안전성: Passive → Active-Safe → Active-Risky
  - 안전장치: 다중 권한 확인, 자동 롤백, 타임아웃, 감사 로깅

## 📊 주요 내용

### 상세 다이어그램:
  - Phase 2 워크플로우
  - Phase 3 OODA Loop 상태 전환도
  - Phase 4 실행 시나리오
  - 전체 데이터 흐름도

### 코드 예시:
  - 각 컴포넌트별 구조 및 인터페이스
  - 실제 사용 예시
  - 입력/출력 형식
  - SQL 스키마

### 실행 결과:
  - 콘솔 출력 예시
  - JSON 파일 구조
  - 검증 통계
