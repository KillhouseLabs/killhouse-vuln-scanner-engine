Feature: 코드 수정 제안 생성

  Scenario: 소스코드와 취약점 정보로 수정 코드 생성
    Given 취약점이 있는 소스코드가 있다
    And SAST 취약점 정보가 있다
    When 코드 수정 제안을 요청한다
    Then 수정된 코드와 설명이 반환된다

  Scenario: OpenAI API 키가 없을 때
    Given OpenAI API 키가 설정되지 않았다
    When 코드 수정 제안을 요청한다
    Then 503 에러가 반환된다
