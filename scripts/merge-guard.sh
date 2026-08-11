#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTEST_BIN="${PYTEST_BIN:-.venv/bin/pytest}"
GO_CACHE_DIR="${GOCACHE:-/private/tmp/strix-go-cache}"

echo "[merge-guard] python contracts"
PYTHONPATH=. "$PYTEST_BIN" -q \
  tests/test_merge_guard_contracts.py \
  tests/test_proxy_scope.py \
  tests/test_inputs.py::test_build_root_task_burp_passive_mode \
  tests/test_inputs.py::test_build_scope_context_burp_passive_mode \
  tests/test_inputs.py::test_build_scope_context_burp_mode_with_explicit_target_allowlist \
  tests/test_agent_factory_shell.py \
  tests/test_runner_root_prompt.py \
  tests/test_session_manager_proxy.py \
  tests/test_runner_proxy_metadata.py \
  tests/test_report_state_proxy.py \
  tests/test_proxy_capture.py \
  tests/test_proxy_coverage.py \
  tests/test_proxy_client.py::test_list_requests_merges_passive_proxy_feature_cutoff \
  tests/test_interface_stats.py \
  tests/test_ui_localization.py \
  tests/test_tui_backend_controller.py

echo "[merge-guard] go tui contracts"
(
  cd strix/interface/tui
  env GOCACHE="$GO_CACHE_DIR" go test ./internal/app -run \
    'TestPassiveProxyWaitingRestoresCaptureGuidance|TestPassiveProxyWaitingWithoutTrafficShowsZeroCaptureState|TestPassiveProxyPhaseSwitchesToTestingWhileChildAgentRuns|TestPassiveProxyTestingWaitsForNextFeatureCommandAfterCompletion|TestTypingReclaimsComposerFocusFromChat|TestTypingReclaimsComposerFocusFromSidebar|TestPassiveProxyStatsKeepCaidoLineTogetherOnDesktop|TestClickingRenderedRootAgentDoesNotTriggerViewerOpenWhileTesting|TestViewerChromeDoesNotTriggerViewerOpen|TestSidebarWidthIsCappedOnWideTerminal'
)

echo "[merge-guard] all checks passed"
