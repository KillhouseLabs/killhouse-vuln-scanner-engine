#!/usr/bin/env python3
"""Phase 3 기능 데모 스크립트"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config import settings
from src.feedback.llm_validator import LLMVulnerabilityValidator
from src.feedback.persistence import FeedbackLoopPersistence
from src.feedback.state_machine import FeedbackLoopStateMachine
from src.policy.engine import ActionType, ExecutionContext, PolicyEngine


def demo_policy_engine():
    """Policy Engine 데모"""
    print("\n" + "=" * 80)
    print("1️⃣  POLICY ENGINE 데모")
    print("=" * 80)

    engine = PolicyEngine()

    # 1. SCAN 액션 (항상 허용)
    context = ExecutionContext(target_url="https://example.com", user_id="demo-user")

    allowed, reason = engine.check_permission(ActionType.SCAN, context)
    print(f"\n✅ SCAN 액션: {'허용됨' if allowed else '거부됨'}")
    print(f"   사유: {reason}")

    # 2. EXPLOIT 액션 (토큰 없이 - 거부됨)
    allowed, reason = engine.check_permission(ActionType.EXPLOIT, context)
    print(f"\n❌ EXPLOIT 액션 (토큰 없음): {'허용됨' if allowed else '거부됨'}")
    print(f"   사유: {reason}")

    # 3. JWT 토큰 생성
    token = engine.generate_token(
        user_id="demo-user", permissions=["scan", "exploit"], expires_in_hours=24
    )
    print(f"\n🔑 생성된 JWT 토큰: {token[:50]}...")

    # 4. EXPLOIT 액션 (토큰 있음 - 허용됨)
    context_with_token = ExecutionContext(
        target_url="https://example.com", user_id="demo-user", authorization_token=token
    )

    allowed, reason = engine.check_permission(ActionType.EXPLOIT, context_with_token)
    print(f"\n✅ EXPLOIT 액션 (토큰 있음): {'허용됨' if allowed else '거부됨'}")
    print(f"   사유: {reason}")

    # 5. 거부된 액션 로그 확인
    denied = engine.get_denied_actions()
    print(f"\n📝 거부된 액션 로그: {len(denied)}개")
    for action in denied[:2]:
        print(f"   - {action['action']}: {action['reason']}")


async def demo_feedback_loop():
    """Feedback Loop State Machine 데모"""
    print("\n" + "=" * 80)
    print("2️⃣  FEEDBACK LOOP STATE MACHINE 데모")
    print("=" * 80)

    # 샘플 취약점 데이터
    vulnerabilities = [
        {
            "id": "CVE-2024-0001",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "description": "Remote code execution vulnerability in web framework",
        },
        {
            "id": "CVE-2024-0002",
            "severity": "HIGH",
            "cvss_score": 8.2,
            "description": "SQL injection vulnerability in database layer",
        },
        {
            "id": "CVE-2024-0003",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "description": "Cross-site scripting (XSS) vulnerability",
        },
    ]

    tech_stack = {
        "technologies": {
            "nginx": {"version": "1.20.0", "category": "Web Server"},
            "node.js": {"version": "18.0.0", "category": "Runtime"},
        }
    }

    # State Machine 초기화
    sm = FeedbackLoopStateMachine(scan_id="demo-scan")

    print(f"\n📍 초기 상태: {sm.current_state.value}")

    # 1. OBSERVING
    print("\n🔍 [OBSERVING] 데이터 수집 중...")
    sm.observe(vulnerabilities, tech_stack, "https://example.com")
    print(f"   상태: {sm.current_state.value}")
    print(f"   관찰 횟수: {sm.metrics.observations_made}")

    # 2. ORIENTING
    print("\n🧭 [ORIENTING] 데이터 분석 중...")
    analysis = sm.orient()
    print(f"   상태: {sm.current_state.value}")
    print(f"   총 취약점: {analysis['total_vulnerabilities']}")
    print(f"   고위험 취약점: {analysis['high_priority_count']}")
    print(f"   심각도 분포: {analysis['severity_distribution']}")

    # 3. HYPOTHESIZING
    print("\n💡 [HYPOTHESIZING] 가설 생성 중...")
    hypotheses = sm.hypothesize()
    print(f"   상태: {sm.current_state.value}")
    print(f"   생성된 가설: {len(hypotheses)}개")
    for i, h in enumerate(hypotheses[:2], 1):
        print(f"\n   가설 {i}:")
        print(f"   - 취약점 ID: {h.vulnerability_id}")
        print(f"   - 신뢰도: {h.confidence:.2f}")
        print(f"   - 가설: {h.hypothesis[:80]}...")
        print(f"   - 증거: {len(h.evidence)}개")

    # 4. DECIDING
    print("\n📋 [DECIDING] 검증 액션 계획 중...")
    actions = sm.decide()
    print(f"   상태: {sm.current_state.value}")
    print(f"   계획된 액션: {len(actions)}개")
    for i, a in enumerate(actions[:2], 1):
        print(f"   - 액션 {i}: {a.action_type} on {a.target}")

    # 5. ACTING
    print("\n⚡ [ACTING] 액션 실행 중...")
    executed = await sm.act()
    print(f"   상태: {sm.current_state.value}")
    print(f"   실행된 액션: {len(executed)}개")
    print(f"   총 액션 수행: {sm.metrics.actions_executed}")

    # 6. VALIDATING
    print("\n✅ [VALIDATING] 결과 검증 중...")
    validations = sm.validate()
    print(f"   상태: {sm.current_state.value}")
    print(f"   검증 완료: {len(validations)}개")
    print(f"   실제 취약점: {sm.metrics.true_positives}")
    print(f"   오탐지: {sm.metrics.false_positives}")

    # 7. REPORTING
    print("\n📊 [REPORTING] 리포트 생성 중...")
    report = sm.report()
    print(f"   상태: {sm.current_state.value} (루프 완료)")

    print("\n📈 최종 메트릭:")
    print(f"   - 총 루프: {report['metrics']['total_loops']}")
    print(f"   - 관찰: {report['metrics']['observations_made']}")
    print(f"   - 가설: {report['metrics']['hypotheses_generated']}")
    print(f"   - 액션: {report['metrics']['actions_executed']}")
    print(f"   - 검증: {report['metrics']['validations_completed']}")
    print(f"   - 실제 취약점: {report['metrics']['true_positives']}")

    return report


def demo_persistence():
    """Persistence Layer 데모"""
    print("\n" + "=" * 80)
    print("3️⃣  SQLITE PERSISTENCE 데모")
    print("=" * 80)

    # 임시 DB 생성
    db_path = Path(".feedback/demo_feedback.db")
    persistence = FeedbackLoopPersistence(db_path=db_path)

    print(f"\n💾 데이터베이스 생성: {db_path}")

    # 세션 생성
    scan_id = "demo-scan-001"
    success = persistence.create_session(
        scan_id=scan_id, target_url="https://example.com", metadata={"demo": True}
    )
    print(f"\n✅ 세션 생성: {'성공' if success else '실패'}")

    # 관찰 추가
    persistence.add_observation(
        scan_id=scan_id, observation_data={"vulnerability_count": 5, "scan_type": "demo"}
    )
    print("   - 관찰 데이터 추가")

    # 가설 추가
    persistence.add_hypothesis(
        scan_id=scan_id,
        vulnerability_id="CVE-2024-0001",
        hypothesis="이 취약점은 실제로 악용 가능함",
        confidence=0.85,
        evidence=["증거 1", "증거 2"],
        validation_plan=["단계 1", "단계 2"],
    )
    print("   - 가설 추가")

    # 메트릭 조회
    metrics = persistence.get_metrics(scan_id)
    print("\n📊 현재 메트릭:")
    print(f"   - 관찰: {metrics['observations_made']}")
    print(f"   - 가설: {metrics['hypotheses_generated']}")

    # 세션 완료
    persistence.complete_session(scan_id)
    print("\n✅ 세션 완료")

    # 세션 정보 조회
    session = persistence.get_session(scan_id)
    print("\n📄 세션 정보:")
    print(f"   - 스캔 ID: {session['scan_id']}")
    print(f"   - 대상 URL: {session['target_url']}")
    print(f"   - 상태: {session['current_state']}")
    print(f"   - 생성 시각: {session['created_at']}")
    print(f"   - 완료 시각: {session['completed_at']}")


async def demo_llm_validator():
    """LLM Validator 데모 (OpenAI API 필요)"""
    print("\n" + "=" * 80)
    print("4️⃣  LLM VALIDATOR 데모")
    print("=" * 80)

    if not settings.openai_api_key:
        print("\n⚠️  OpenAI API 키가 설정되지 않았습니다.")
        print("   .env 파일에 OPENAI_API_KEY를 추가하면 LLM 검증을 테스트할 수 있습니다.")
        print("\n   예시:")
        print("   OPENAI_API_KEY=sk-...")
        return

    print(f"\n✅ OpenAI API 키 확인됨: {settings.openai_api_key[:10]}...")

    from src.feedback.state_machine import ValidationHypothesis

    # Validator 초기화
    validator = LLMVulnerabilityValidator(
        openai_api_key=settings.openai_api_key,
        model="gpt-4o-mini",
        cache_dir=Path(".cache/demo_validation"),
    )

    print("🤖 LLM Validator 초기화 완료")

    # 테스트 가설
    hypothesis = ValidationHypothesis(
        vulnerability_id="CVE-2024-0001",
        hypothesis="이 SQL injection 취약점은 인증 우회를 통해 악용 가능합니다",
        confidence=0.7,
        evidence=[
            "사용자 입력이 직접 SQL 쿼리에 포함됨",
            "Prepared statement 미사용",
            "인증 체크가 SQL 쿼리 전에 수행되지 않음",
        ],
        validation_plan=[
            "SQL injection 페이로드 테스트",
            "인증 우회 시도",
            "데이터베이스 접근 확인",
        ],
    )

    print("\n💡 테스트 가설:")
    print(f"   취약점: {hypothesis.vulnerability_id}")
    print(f"   가설: {hypothesis.hypothesis}")
    print(f"   초기 신뢰도: {hypothesis.confidence:.2f}")

    try:
        print("\n🔄 LLM 검증 진행 중... (3-5초 소요)")

        result = await validator.validate_hypothesis(
            hypothesis=hypothesis,
            tech_stack={"technologies": {"PostgreSQL": {"version": "13.0"}}},
            target_url="https://example.com",
        )

        print("\n✅ 검증 완료!")
        print("\n📊 검증 결과:")
        print(f"   - 악용 가능성: {'예' if result['is_exploitable'] else '아니오'}")
        print(f"   - 신뢰도: {result['confidence']:.2f}")
        print("\n   💬 분석 내용:")
        print(f"   {result['reasoning'][:200]}...")

        if result["attack_vectors"]:
            print("\n   ⚔️  공격 벡터:")
            for vector in result["attack_vectors"][:3]:
                print(f"      - {vector}")

        if result["recommended_actions"]:
            print("\n   🔧 권장 조치:")
            for action in result["recommended_actions"][:3]:
                print(f"      - {action}")

        print("\n   📈 메타데이터:")
        print(f"      - 모델: {result['validation_metadata']['model']}")
        print(f"      - 토큰 사용: {result['validation_metadata']['tokens_used']}")
        print(
            f"      - 예상 비용: ~${result['validation_metadata']['tokens_used'] * 0.00000015:.6f}"
        )

    except Exception as e:
        print(f"\n❌ LLM 검증 실패: {e}")


async def main():
    """메인 데모 실행"""
    print("\n" + "=" * 80)
    print("🚀 Phase 3 기능 데모 시작")
    print("=" * 80)

    try:
        # 1. Policy Engine
        demo_policy_engine()

        # 2. Feedback Loop State Machine
        await demo_feedback_loop()

        # 3. Persistence
        demo_persistence()

        # 4. LLM Validator (optional)
        await demo_llm_validator()

        print("\n" + "=" * 80)
        print("✅ 모든 데모 완료!")
        print("=" * 80)

        print("\n📁 생성된 파일:")
        print("   - .feedback/demo-scan/state.json (State Machine 상태)")
        print("   - .feedback/demo-scan/feedback_report.json (리포트)")
        print("   - .feedback/demo_feedback.db (SQLite 데이터베이스)")
        print("   - .cache/demo_validation/ (LLM 검증 캐시)")

        print("\n💡 다음 단계:")
        print("   1. 실제 스캔 실행: python -m src.main")
        print("   2. SQLite DB 확인: sqlite3 .feedback/demo_feedback.db")
        print("   3. 상태 파일 확인: cat .feedback/demo-scan/state.json")

    except Exception as e:
        print(f"\n❌ 에러 발생: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
