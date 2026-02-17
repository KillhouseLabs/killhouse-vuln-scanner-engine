Feature: 파이프라인 상태 머신

  Scenario: 모든 스텝 성공 시 COMPLETED
    Given SAST가 성공한다
    And DAST가 성공한다
    When 파이프라인이 완료된다
    Then 최종 상태는 "COMPLETED"이다

  Scenario: DAST 실패 시 COMPLETED_WITH_ERRORS
    Given SAST가 성공한다
    And DAST가 실패한다
    When 파이프라인이 완료된다
    Then 최종 상태는 "COMPLETED_WITH_ERRORS"이다

  Scenario: SAST 실패 시 COMPLETED_WITH_ERRORS
    Given SAST가 실패한다
    And DAST가 성공한다
    When 파이프라인이 완료된다
    Then 최종 상태는 "COMPLETED_WITH_ERRORS"이다
