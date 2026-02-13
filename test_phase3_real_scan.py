#!/usr/bin/env python3
"""Phase 3 실제 스캔 테스트"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.main import VulnerPlatform
from src.config import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    """실제 URL로 Phase 3 기능 테스트"""

    print("\n" + "="*80)
    print("🚀 Phase 3 실제 스캔 테스트")
    print("="*80)

    # 테스트 URL
    test_url = "https://hamalab.io"

    print(f"\n🎯 대상 URL: {test_url}")
    print(f"📦 컨테이너 런타임: {settings.container_runtime}")
    print(f"🤖 OpenAI API: {'설정됨' if settings.openai_api_key else '미설정'}")

    if not settings.openai_api_key:
        print("\n⚠️  OpenAI API 키가 없어서 LLM 검증은 건너뜁니다.")
        print("   .env 파일에 OPENAI_API_KEY를 추가하면 AI 검증을 사용할 수 있습니다.")

    print("\n" + "-"*80)
    print("스캔 시작...")
    print("-"*80)

    try:
        # Platform 초기화
        platform = VulnerPlatform(
            repo_path=".",
            container_runtime=settings.container_runtime
        )

        # 스캔 실행 (Phase 3 Feedback Loop 포함)
        result = await platform.scan_target(test_url)

        print("\n" + "="*80)
        print("📊 스캔 결과")
        print("="*80)

        # 콘솔 출력
        result.print_summary()

        # JSON 저장
        output_path = result.save_to_json()
        print(f"\n💾 전체 리포트 저장: {output_path}")

        # Feedback Loop 리포트 확인
        if result.feedback_loop_report:
            print("\n" + "="*80)
            print("🔄 Feedback Loop 상세 정보")
            print("="*80)

            metrics = result.feedback_loop_report.get('metrics', {})
            print(f"\n총 루프: {metrics.get('total_loops', 0)}")
            print(f"관찰: {metrics.get('observations_made', 0)}")
            print(f"가설 생성: {metrics.get('hypotheses_generated', 0)}")
            print(f"액션 실행: {metrics.get('actions_executed', 0)}")
            print(f"검증 완료: {metrics.get('validations_completed', 0)}")
            print(f"실제 취약점: {metrics.get('true_positives', 0)}")
            print(f"오탐지: {metrics.get('false_positives', 0)}")

            validated = result.feedback_loop_report.get('validated_vulnerabilities', {})
            print(f"\n✅ 검증된 취약점: {len([v for v in validated.values() if v])}개")

            transitions = result.feedback_loop_report.get('transitions', [])
            print(f"\n🔄 상태 전환 과정:")
            for t in transitions:
                print(f"   {t['from']} → {t['to']}: {t['reason']}")

        # 생성된 파일 확인
        print("\n" + "="*80)
        print("📁 생성된 파일")
        print("="*80)

        # Feedback state
        feedback_dirs = list(Path(".feedback").glob("*"))
        if feedback_dirs:
            print(f"\n피드백 루프 상태:")
            for d in feedback_dirs:
                if d.is_dir() and not d.name.startswith('.'):
                    files = list(d.glob("*"))
                    print(f"   {d.name}/")
                    for f in files:
                        print(f"      - {f.name}")

        # SQLite DB
        db_path = Path(".feedback/feedback_loop.db")
        if db_path.exists():
            print(f"\n데이터베이스: {db_path}")

        print("\n" + "="*80)
        print("✅ 테스트 완료!")
        print("="*80)

        print("\n💡 다음 단계:")
        print("   1. SQLite DB 확인: sqlite3 .feedback/feedback_loop.db")
        print("   2. 리포트 보기: cat scan_results/*.json")
        print("   3. 상태 확인: cat .feedback/*/state.json")

        # Cleanup
        platform.cleanup_old_worktrees()

    except Exception as e:
        print(f"\n❌ 에러 발생: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
