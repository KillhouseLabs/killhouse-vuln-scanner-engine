"""Step definitions for DAST network connect feature."""

from unittest.mock import MagicMock, patch

import pytest
from pytest_bdd import given, scenario, then, when


@scenario(
    "../features/dast/network_connect.feature",
    "스캐너가 target 네트워크에 연결 후 스캔",
)
def test_scanner_connects_to_network():
    pass


@scenario(
    "../features/dast/network_connect.feature",
    "네트워크 없이 스캔",
)
def test_scanner_runs_without_network():
    pass


@pytest.fixture
def context():
    return {}


@given('target 네트워크 "killhouse-test-123"이 존재한다')
def network_exists(context):
    context["network_name"] = "killhouse-test-123"
    context["target_url"] = "http://killhouse-target-test123:8080"


@given("network_name이 없다")
def no_network(context):
    context["network_name"] = None
    context["target_url"] = "http://localhost:8080"


@when("DAST 스캔을 실행한다")
def run_dast_scan(context):
    from src.scanner.dast import NucleiScanner

    scanner = NucleiScanner(timeout=60)
    with patch("src.scanner.dast.subprocess.run") as mock_run, \
         patch("src.scanner.dast.docker.from_env") as mock_docker:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_network = MagicMock()
        mock_docker.return_value.networks.get.return_value = mock_network

        scanner.run(context["target_url"], network_name=context.get("network_name"))

        context["mock_docker"] = mock_docker
        context["mock_network"] = mock_network
        context["mock_run"] = mock_run


@then("스캐너 컨테이너가 네트워크에 연결된다")
def scanner_connected(context):
    context["mock_network"].connect.assert_called_once()


@then("스캔 완료 후 네트워크에서 해제된다")
def scanner_disconnected(context):
    context["mock_network"].disconnect.assert_called_once()


@then("네트워크 연결 없이 직접 스캔한다")
def no_network_connection(context):
    context["mock_docker"].assert_not_called()
