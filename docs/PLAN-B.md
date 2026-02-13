  1. 제안 방식의 장점

  통합 보안 파이프라인

  ┌─────────────────────────────────────────────────────────┐
  │                  GitHub 레포 입력                         │
  └─────────────────────────────────────────────────────────┘
                           ↓
  ┌─────────────────────────────────────────────────────────┐
  │  Phase 1: SAST (정적 분석)                               │
  │  • 소스코드 스캔                                          │
  │  • 코드 패턴 분석 (SQL Injection, XSS 등)                 │
  │  • 하드코딩된 시크릿 탐지                                  │
  │  • 의존성 파일 파싱                                       │
  └─────────────────────────────────────────────────────────┘
                           ↓
  ┌─────────────────────────────────────────────────────────┐
  │  Phase 2: SCA (Software Composition Analysis)           │
  │  • 기술스택 정확한 파악                                    │
  │  • 버전별 CVE 쿼리 (OSV.dev + NVD)                       │
  │  • Transitive dependencies 분석                         │
  │  • 라이선스 컴플라이언스 체크                              │
  └─────────────────────────────────────────────────────────┘
                           ↓
  ┌─────────────────────────────────────────────────────────┐
  │  Phase 3: 자동 빌드 & 로컬 실행                            │
  │  • Dockerfile/docker-compose 자동 생성                   │
  │  • 샌드박스 환경에서 빌드                                  │
  │  • localhost 포트 바인딩 (예: 127.0.0.1:3000)            │
  │  • 실행 로그 모니터링                                      │
  └─────────────────────────────────────────────────────────┘
                           ↓
  ┌─────────────────────────────────────────────────────────┐
  │  Phase 4: DAST (동적 분석)                                │
  │  • localhost 대상 크롤링                                  │
  │  • 인증 플로우 자동화                                      │
  │  • SQL Injection, XSS 실제 테스트                         │
  │  • OWASP Top 10 자동 검증                                │
  └─────────────────────────────────────────────────────────┘
                           ↓
  ┌─────────────────────────────────────────────────────────┐
  │  Phase 5: 결과 통합 & AI 분석                             │
  │  • SAST + CVE + DAST 결과 교차검증                        │
  │  • False Positive 제거                                   │
  │  • Exploit 우선순위화                                     │
  │  • 수정 방법 자동 제안                                     │
  └─────────────────────────────────────────────────────────┘

  핵심 이점

  ✅ 정확도 극대화
  - SAST: 코드에 취약점 패턴 있음 (가능성)
  - CVE: 해당 버전 라이브러리에 알려진 취약점 존재 (확인됨)
  - DAST: 실제 exploit 가능 (증명됨)
  - → 3단계 검증으로 False Positive 거의 제거

  ✅ 보안성 유지
  - 퍼블릭 인터넷 노출 없음
  - localhost만 접근
  - 샌드박스 격리
  - 스캔 후 자동 환경 삭제

  ✅ 실제 환경 반영
  - 빌드 과정에서 발견되는 문제
  - 런타임 의존성 누락
  - 환경변수 설정 오류
  - 실제 동작 여부 확인

  ---
  2. 상세 방법론

  Phase 1: SAST 구현

  1.1 코드 패턴 분석

  # Semgrep 룰 예시
  rules:
    - id: sql-injection-risk
      pattern: |
        const query = `SELECT * FROM ${$VAR}`
        db.query(query)
      message: "SQL Injection vulnerability"
      severity: ERROR

    - id: hardcoded-secret
      pattern: |
        const apiKey = "$SECRET"
      message: "Hardcoded API key"
      severity: CRITICAL

  1.2 의존성 파일 파싱

  SAST_OUTPUTS = {
      "code_vulnerabilities": [
          {
              "type": "SQL Injection",
              "file": "src/api/users.js",
              "line": 42,
              "severity": "CRITICAL",
              "pattern": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"
          }
      ],
      "dependencies": {
          "react": "17.0.2",      # 취약 버전
          "axios": "0.21.1",      # 취약 버전
          "lodash": "4.17.20"     # 취약 버전
      },
      "secrets": [
          {
              "type": "AWS Access Key",
              "file": ".env.example",
              "value": "AKIA..."
          }
      ]
  }

  ---
  Phase 2: CVE 쿼리 (SAST 결과 기반)

  2.1 정확한 의존성 매핑

  # SAST에서 파싱한 의존성 기반
  for package, version in sast_result["dependencies"].items():
      cves = await query_osv(
          package=package,
          version=version,        # 정확한 버전
          ecosystem=detect_ecosystem(package)  # 자동 감지
      )

      # 실제 코드에서 사용 여부 확인 (AST 분석)
      if is_package_imported(codebase, package):
          for cve in cves:
              # 영향받는 함수 실제 사용 여부
              if is_vulnerable_function_used(codebase, cve.affected_functions):
                  validated_cves.append(cve)

  2.2 CVE + SAST 교차검증

  # 예: CVE-2021-23337 (lodash Prototype Pollution)
  cve = {
      "id": "CVE-2021-23337",
      "package": "lodash",
      "versions": "< 4.17.21",
      "vulnerability": "Prototype Pollution",
      "affected_functions": ["merge", "mergeWith", "defaultsDeep"]
  }

  # SAST 코드 분석 결과
  sast_finding = {
      "file": "src/utils/config.js",
      "line": 15,
      "code": "_.merge(target, source)",  # 취약한 함수 사용!
      "package": "lodash",
      "version": "4.17.20"  # 취약 버전!
  }

  # 매칭 → 실제 취약점 확인
  if cve.package == sast_finding.package and \
     cve.is_version_affected(sast_finding.version) and \
     any(func in sast_finding.code for func in cve.affected_functions):

      vulnerability = {
          "source": "SAST + CVE",
          "confidence": "HIGH",
          "exploitable": "LIKELY",  # DAST로 검증 필요
      }

  ---
  Phase 3: 자동 빌드 & 로컬 실행

  3.1 프로젝트 타입 자동 감지

  BUILD_STRATEGIES = {
      "node": {
          "detect": ["package.json"],
          "install": "npm install",
          "build": "npm run build",
          "start": "npm start",
          "port": 3000
      },
      "python-django": {
          "detect": ["manage.py", "requirements.txt"],
          "install": "pip install -r requirements.txt",
          "migrate": "python manage.py migrate",
          "start": "python manage.py runserver 127.0.0.1:8000",
          "port": 8000
      },
      "docker": {
          "detect": ["Dockerfile"],
          "build": "docker build -t vulner-scan .",
          "start": "docker run -p 127.0.0.1:8080:8080 vulner-scan",
          "port": 8080
      }
  }

  3.2 샌드박스 환경 구성

  # 격리된 환경에서 실행
  sandbox:
    network: "isolated"        # 외부 네트워크 차단
    filesystem: "read-only"    # 루트 파일시스템 읽기 전용
    capabilities: "minimal"    # 최소 권한
    timeout: "5m"              # 최대 실행 시간

    bindings:
      - "127.0.0.1:0:3000"    # 랜덤 포트 → 앱 포트 매핑
      - "/tmp/vulner-scan:/app:ro"  # 코드 마운트

    environment:
      - "NODE_ENV=development"
      - "DATABASE_URL=sqlite:///tmp/test.db"  # 임시 DB
      - "DISABLE_AUTH=true"   # DAST 용이성

  3.3 빌드 실패 처리

  build_result = {
      "success": False,
      "stage": "npm install",
      "error": "ENOENT: no such file or directory, open 'node_modules/react'",
      "action": "skip_dast",  # 빌드 실패 시 DAST 건너뛰기
      "report": "빌드 실패로 DAST 불가. SAST + CVE 결과만 제공"
  }

  ---
  Phase 4: 내부 DAST 실행

  4.1 DAST 도구 통합

  DAST_ENGINES = {
      "owasp-zap": {
          "container": "owasp/zap2docker-stable",
          "command": "zap-baseline.py -t http://host.docker.internal:3000",
          "output": "/zap/wrk/baseline-report.html"
      },
      "nuclei": {
          "binary": "nuclei",
          "command": "nuclei -u http://127.0.0.1:3000 -t cves/ -json",
          "templates": "CVE-2021-*, CVE-2022-*"
      },
      "custom": {
          "script": "dast_scanner.py",
          "checks": ["xss", "sqli", "csrf", "xxe", "ssrf"]
      }
  }

  4.2 인증 자동화

  # SAST에서 발견한 인증 엔드포인트
  auth_endpoint = sast_result.get("auth_routes", [])
  # → POST /api/login

  # 자동 로그인 시도
  dast_config = {
      "authentication": {
          "type": "form",
          "url": "http://127.0.0.1:3000/api/login",
          "credentials": {
              "username": "test@vulner.io",
              "password": "Test123!@#"
          },
          "success_indicator": "token"
      },
      "session": {
          "store": "cookies",
          "include_in_requests": True
      }
  }

  4.3 SAST 결과 기반 타겟팅

  # SAST에서 발견한 SQL Injection 의심 코드
  sast_sqli = {
      "endpoint": "/api/users",
      "parameter": "id",
      "method": "GET"
  }

  # DAST에서 실제 테스트
  dast_test = {
      "url": "http://127.0.0.1:3000/api/users",
      "payloads": [
          "?id=1' OR '1'='1",
          "?id=1; DROP TABLE users--",
          "?id=1 UNION SELECT null,null,null--"
      ],
      "validation": [
          "check_http_500",           # 에러 발생?
          "check_sql_error_message",  # SQL 에러 메시지 노출?
          "check_data_leakage"        # 추가 데이터 반환?
      ]
  }

  # 결과
  if dast_test.is_exploitable():
      vulnerability.status = "CONFIRMED"  # SAST 의심 → DAST 확인
      vulnerability.exploit_proof = dast_test.response

  ---
  Phase 5: 결과 통합 & AI 분석

  5.1 3-Way 검증

  VULNERABILITY_LIFECYCLE = {
      "1_SAST_ONLY": {
          "confidence": "LOW",
          "status": "Potential (코드 패턴만 발견)",
          "action": "추가 검증 필요"
      },
      "2_SAST_CVE": {
          "confidence": "MEDIUM",
          "status": "Likely (알려진 취약점 + 코드 사용 확인)",
          "action": "DAST 검증 대기"
      },
      "3_SAST_CVE_DAST": {
          "confidence": "CRITICAL",
          "status": "CONFIRMED (실제 exploit 성공)",
          "action": "즉시 수정 필요"
      },
      "CVE_ONLY": {
          "confidence": "MEDIUM",
          "status": "Dependency Risk (의존성에 취약점 존재, 사용 여부 불명)",
          "action": "코드 사용 여부 확인 필요"
      },
      "DAST_ONLY": {
          "confidence": "MEDIUM",
          "status": "Runtime Issue (동적 스캔 발견, 원인 불명)",
          "action": "SAST 재분석 필요"
      }
  }

  5.2 통합 보고서 예시

  {
    "vulnerability_id": "VULNER-2024-001",
    "title": "SQL Injection in User Search Endpoint",

    "evidence": {
      "sast": {
        "tool": "semgrep",
        "finding": {
          "file": "src/api/users.js",
          "line": 42,
          "code": "db.query(`SELECT * FROM users WHERE name LIKE '%${req.query.search}%')`",
          "severity": "CRITICAL"
        }
      },

      "cve": {
        "matched": false,
        "reason": "Custom code vulnerability, no CVE assigned"
      },

      "dast": {
        "tool": "nuclei",
        "exploit": {
          "url": "http://127.0.0.1:3000/api/users?search=%27%20OR%20%271%27%3D%271",
          "method": "GET",
          "response_code": 200,
          "data_leaked": true,
          "proof": "Returned all users (500+ records) instead of filtered results"
        }
      }
    },

    "confidence": "CRITICAL",
    "verification_level": "CONFIRMED",

    "impact": {
      "confidentiality": "HIGH",
      "integrity": "LOW",
      "availability": "LOW",
      "cvss_score": 7.5
    },

    "remediation": {
      "priority": "P0 - Fix immediately",
      "suggestion": "Use parameterized queries or ORM",
      "code_fix": "db.query('SELECT * FROM users WHERE name LIKE ?', [`%${req.query.search}%`])",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      ]
    }
  }

  ---
  3. 도전 과제 & 해결 방안

  도전 1: 빌드 환경 다양성

  문제: Node.js, Python, Java, Go, Rust 등 각기 다른 빌드 시스템

  해결:
  # 빌드 전략 자동 감지
  builders = [
      NodeBuilder(),      # package.json
      PythonBuilder(),    # requirements.txt, Pipfile
      JavaBuilder(),      # pom.xml, build.gradle
      GoBuilder(),        # go.mod
      DockerBuilder(),    # Dockerfile (최우선)
  ]

  for builder in builders:
      if builder.can_handle(repo):
          return builder.build()

  도전 2: 환경변수 & 시크릿

  문제: .env 파일 없으면 앱 실행 불가

  해결:
  # .env.example 파싱 후 더미 값 생성
  env_template = parse_file(".env.example")
  # DATABASE_URL=
  # REDIS_URL=
  # API_KEY=

  dummy_env = {
      "DATABASE_URL": "sqlite:///tmp/test.db",
      "REDIS_URL": "redis://127.0.0.1:6379",
      "API_KEY": "dummy-key-for-scanning",
      "JWT_SECRET": "test-secret-do-not-use-in-prod"
  }

  도전 3: 데이터베이스 의존성

  문제: PostgreSQL, MySQL 등 외부 DB 필요

  해결:
  # docker-compose 자동 생성
  services:
    app:
      build: .
      ports:
        - "127.0.0.1:3000:3000"
      environment:
        DATABASE_URL: "postgresql://postgres:password@db:5432/testdb"

    db:
      image: postgres:14-alpine
      environment:
        POSTGRES_PASSWORD: password
        POSTGRES_DB: testdb
      tmpfs:
        - /var/lib/postgresql/data  # 메모리에만 저장, 스캔 후 삭제

  도전 4: 빌드 시간

  문제: 대규모 프로젝트는 빌드에 10분+ 소요

  해결:
  # 캐싱 전략
  build_cache = {
      "node_modules": True,      # npm install 캐싱
      "venv": True,              # pip install 캐싱
      ".m2": True,               # Maven 캐싱
      "target/": False,          # 빌드 결과물은 캐싱 안 함
  }

  # 타임아웃
  if build_time > 15_minutes:
      return {
          "status": "TIMEOUT",
          "partial_results": {
              "sast": sast_results,
              "cve": cve_results,
              "dast": None  # 빌드 실패로 건너뜀
          }
      }

  도전 5: 네트워크 요청

  문제: 앱이 외부 API 호출 (결제, 이메일 등)

  해결:
  # 네트워크 모킹
  mock_server = start_mock_server()
  # GET /api/payment → 200 OK (fake response)
  # POST /api/email → 200 OK

  # DNS 오버라이드
  /etc/hosts:
    127.0.0.1 api.stripe.com
    127.0.0.1 api.sendgrid.com

  ---
  4. 실제 구현 아키텍처

  전체 시스템 다이어그램

  ┌──────────────────────────────────────────────────────────┐
  │                    Vulner Platform                        │
  │                    (Main Orchestrator)                    │
  └──────────────────────────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │ SAST Worker  │ │  CVE Worker  │ │ DAST Worker  │
  │              │ │              │ │              │
  │ • Semgrep    │ │ • OSV.dev    │ │ • OWASP ZAP  │
  │ • Bandit     │ │ • NVD        │ │ • Nuclei     │
  │ • ESLint     │ │ • GitHub     │ │ • Custom     │
  └──────────────┘ └──────────────┘ └──────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │  Build Orchestrator   │
              │                       │
              │  • Clone repo         │
              │  • Detect build type  │
              │  • Create sandbox     │
              │  • Execute build      │
              │  • Start app          │
              └───────────────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │   Sandbox Manager     │
              │                       │
              │  • Docker/Podman      │
              │  • Network isolation  │
              │  • Resource limits    │
              │  • Auto cleanup       │
              └───────────────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │  AI Validator (LLM)   │
              │                       │
              │  • 결과 통합          │
              │  • False positive 제거│
              │  • 우선순위화         │
              │  • 수정 방법 제안     │
              └───────────────────────┘

  워크플로우 타임라인

  T+0:00  │ GitHub 레포 입력
          ├─ Git clone (shallow, depth=1)
          └─ 의존성 파일 파싱

  T+0:30  │ SAST 시작 (병렬)
          ├─ Semgrep (2분)
          ├─ 의존성 분석 (1분)
          └─ 시크릿 스캔 (30초)

  T+2:30  │ CVE 쿼리 시작 (병렬)
          ├─ OSV.dev (5초)
          ├─ NVD (10초)
          └─ GitHub Advisory (5초)

  T+2:45  │ 빌드 시작
          ├─ Dockerfile 생성 (10초)
          ├─ Docker build (5분)
          └─ 앱 시작 (30초)

  T+8:25  │ DAST 시작
          ├─ 크롤링 (2분)
          ├─ 인증 (30초)
          ├─ 취약점 테스트 (5분)
          └─ 결과 수집 (30초)

  T+16:25 │ AI 분석
          ├─ 결과 통합 (1분)
          ├─ False positive 제거 (1분)
          └─ 보고서 생성 (1분)

  T+19:25 │ 완료 (총 ~20분)

  ---
  5. 기존 도구와의 비교
  ┌───────────┬────────────────┬─────────────────┬────────────────────┐
  │   기능    │      Snyk      │ GitLab Ultimate │ 제안 방식 (Vulner) │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ SAST      │ ✅             │ ✅              │ ✅ Semgrep         │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ SCA       │ ✅             │ ✅              │ ✅ OSV.dev + NVD   │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ DAST      │ ❌ (별도 제품) │ ✅              │ ✅ OWASP ZAP       │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ 로컬 빌드 │ ❌             │ ✅ (CI/CD)      │ ✅ 샌드박스        │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ AI 분석   │ ✅ (DeepCode)  │ ❌              │ ✅ GPT-4           │
  ├───────────┼────────────────┼─────────────────┼────────────────────┤
  │ 가격      │ $$$$           │ $$$$            │ 💰 오픈소스        │
  └───────────┴────────────────┴─────────────────┴────────────────────┘
  ---
  6. 최종 추천 아키텍처

  모듈 구조

  src/
  ├── sast/
  │   ├── semgrep_scanner.py
  │   ├── dependency_parser.py
  │   └── secret_detector.py
  │
  ├── sca/
  │   ├── osv_client.py
  │   ├── nvd_client.py
  │   └── cve_matcher.py
  │
  ├── build/
  │   ├── builder_factory.py
  │   ├── node_builder.py
  │   ├── python_builder.py
  │   ├── docker_builder.py
  │   └── sandbox_manager.py
  │
  ├── dast/
  │   ├── zap_scanner.py
  │   ├── nuclei_scanner.py
  │   ├── auth_handler.py
  │   └── crawler.py
  │
  ├── integration/
  │   ├── orchestrator.py          # 전체 워크플로우 조율
  │   ├── validator.py             # 3-way 검증
  │   └── reporter.py              # 통합 보고서
  │
  └── ai/
      ├── false_positive_filter.py
      ├── priority_ranker.py
      └── fix_suggester.py

  ---
  결론

  제안하신 방식은 매우 강력합니다:

  ✅ 정확도: SAST + CVE + DAST 3단계 검증으로 False Positive 최소화
  ✅ 보안성: 로컬 실행으로 퍼블릭 노출 없음
  ✅ 실용성: 실제 빌드/실행으로 환경 문제 사전 발견
  ✅ 차별화: 대부분의 오픈소스 도구는 SAST+SCA만 제공, DAST 통합은 엔터프라이즈급

  구현 우선순위:
  1. MVP: SAST + CVE (빠른 검증)
  2. V2: 빌드 자동화 + 로컬 실행 (도커 기반)
  3. V3: DAST 통합 (OWASP ZAP)
  4. V4: AI 검증 고도화

  이 방식으로 진행하시면 Snyk + GitLab SAST + OWASP ZAP를 통합한 수준의 플랫폼이 됩니다.

  구현 시작하시겠습니까? 단계별 구현 계획 수립해드리겠습니다.
