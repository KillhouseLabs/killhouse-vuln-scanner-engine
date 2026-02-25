Feature: 파이프라인 단계별 로그 메시지 전송
  스캐너 파이프라인이 각 분석 단계에서 상세 로그 메시지를
  웹훅 콜백에 포함하여 전송한다.

  Background:
    Given 콜백 URL이 설정되어 있다

  Scenario: CLONING 단계에서 로그 메시지를 전송한다
    When 파이프라인이 CLONING 상태 콜백을 전송한다
    Then 웹훅 콜백에 status "CLONING"이 포함된다
    And 웹훅 콜백에 log_message가 포함된다

  Scenario: STATIC_ANALYSIS 완료 시 결과 로그를 전송한다
    Given SAST 스캔이 5건을 발견했다
    When 파이프라인이 SAST 결과 콜백을 전송한다
    Then 웹훅 콜백에 log_message에 "SAST completed: 5 findings"가 포함된다

  Scenario: BUILDING 단계에서 로그 메시지를 전송한다
    When 파이프라인이 BUILDING 상태 콜백을 전송한다
    Then 웹훅 콜백에 status "BUILDING"이 포함된다
    And 웹훅 콜백에 log_message가 포함된다

  Scenario: PENETRATION_TEST 완료 시 결과 로그를 전송한다
    Given DAST 스캔이 3건을 발견했다
    When 파이프라인이 DAST 결과 콜백을 전송한다
    Then 웹훅 콜백에 log_message에 "DAST completed: 3 findings"가 포함된다

  Scenario: EXPLOIT_VERIFICATION 시작 시 로그를 전송한다
    When 파이프라인이 EXPLOIT_VERIFICATION 상태 콜백을 전송한다
    Then 웹훅 콜백에 status "EXPLOIT_VERIFICATION"이 포함된다
    And 웹훅 콜백에 log_message가 포함된다

  Scenario: 단계 실패 시 에러 로그를 전송한다
    Given SAST 스캔이 "semgrep not found" 에러로 실패했다
    When 파이프라인이 SAST 에러 콜백을 전송한다
    Then 웹훅 콜백에 log_level "error"가 포함된다
    And 웹훅 콜백에 log_message에 "semgrep not found"가 포함된다
