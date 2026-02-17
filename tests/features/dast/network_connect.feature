Feature: DAST 스캐너 네트워크 연결

  Scenario: 스캐너가 target 네트워크에 연결 후 스캔
    Given target 네트워크 "killhouse-test-123"이 존재한다
    When DAST 스캔을 실행한다
    Then 스캐너 컨테이너가 네트워크에 연결된다
    And 스캔 완료 후 네트워크에서 해제된다

  Scenario: 네트워크 없이 스캔
    Given network_name이 없다
    When DAST 스캔을 실행한다
    Then 네트워크 연결 없이 직접 스캔한다
