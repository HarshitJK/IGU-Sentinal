"""Shared pytest fixtures for IGU Sentinel.

Model-persistence isolation
---------------------------
`detect/isoforest.py` and `detect/xgb.py` persist every ``train_*`` call to a
new versioned artifact under the shared ``models/`` directory, and both modules
load the *highest-numbered* artifact as the model the running service uses
(see ``_latest_model_path``).

The unit tests for those detectors call ``train_isoforest`` / ``train_xgb`` on
small fixture subsets purely to exercise the code path. Left unchecked, those
calls write throwaway models into the production ``models/`` directory and — because
the loader always picks the highest version — leave a test-trained model as the
one the API serves at next startup. ``test_xgb_end_to_end_with_held_out`` in
particular trains on a class-ordered 70% split, dropping the last two threat
classes and producing a degraded 5-class model.

This autouse fixture redirects both modules' ``_MODELS_DIR`` to a per-test
temporary directory for the detector/training test modules, so training tests
stay hermetic and never mutate (or clobber the "latest" of) the real ``models/``
directory. Non-training test modules (api, benchmark, fusion, ...) are untouched;
they rely on the production model loaded into memory at import time.
"""
import pytest

import igu_sentinel.detect.isoforest as _iso
import igu_sentinel.detect.xgb as _xgb

# Test modules whose tests call train_isoforest / train_xgb and therefore must
# not write into the shared models/ directory.
# test_drift is included because the bounded-retrain tests call
# trigger_bounded_retrain(), which calls train_isoforest() — so they persist new
# versioned artifacts too. Without this they wrote models trained on a handful of
# fixture rows into the real models/ directory, and since the loader always picks
# the HIGHEST version, the next service start would have served a model trained
# on test data (including the deliberately poisoned pool).
_TRAINING_TEST_MODULES = {"test_isoforest", "test_xgb", "test_drift"}


@pytest.fixture(autouse=True)
def isolate_model_artifacts(request, tmp_path, monkeypatch):
    """Redirect model persistence to a tmp dir for training test modules."""
    module_name = request.module.__name__.rsplit(".", 1)[-1]
    if module_name in _TRAINING_TEST_MODULES:
        tmp_models = tmp_path / "models"
        tmp_models.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(_iso, "_MODELS_DIR", tmp_models)
        monkeypatch.setattr(_xgb, "_MODELS_DIR", tmp_models)
    yield


@pytest.fixture(autouse=True)
def reset_drift_state():
    """Reset drift/ globals around every test.

    The detection pipeline now feeds isoforest scores and fused-benign verdicts
    into drift/ (it was previously dead code that nothing called). That state is
    module-global and cumulative, so without this any test that ran the pipeline
    would establish a baseline distribution for whatever test ran next — making
    drift assertions depend on test ordering.
    """
    from igu_sentinel.drift import reset_retrain_log

    reset_retrain_log()
    yield
    reset_retrain_log()


@pytest.fixture(autouse=True)
def reset_ws_connections():
    """Clear the shared WebSocket ConnectionManager around every test.

    ``igu_sentinel.api.manager`` is a module-level singleton whose
    ``active_connections`` set persists across tests. A TestClient WebSocket that
    is torn down abruptly can leave a stale connection behind; a later test that
    broadcasts would then block trying to send to that dead socket. Clearing the
    set before and after each test keeps WebSocket tests hermetic.
    """
    def _clear():
        try:
            import igu_sentinel.api as _api
            _api.manager.active_connections.clear()
        except Exception:
            pass

    _clear()
    yield
    _clear()


# ── Docker availability gating ────────────────────────────────────────────────
# The infra test modules drive a real container stack. When Docker (or a Compose
# implementation) is not installed they used to FAIL, not skip — so a clean
# checkout on a machine without Docker reported 12 red tests that said nothing
# about the code. A missing tool is an environment gap, not a defect.
#
# They also invoked the legacy `docker-compose` v1 binary, which Docker removed
# in favour of the `docker compose` plugin; on a current Docker install the v1
# name does not exist, so every one of these tests failed even WITH Docker
# present. compose_command() resolves whichever implementation is available.

import functools
import shutil
import subprocess

# Only the tests that actually drive a container stack are gated. The static
# tests in the same modules parse docker-compose.yml off disk and must keep
# running everywhere — they are what catches a broken compose file in CI.
_DOCKER_RUNTIME_TESTS = {
    "test_diode_container_starts",
    "test_diode_startup_logs",
    "test_all_containers_running",
    "test_networks_exist_and_separate",
    "test_one_way_relay_proof_artifact",
    "test_sentinel_service_starts",
    "test_sentinel_health_endpoint",
    "test_all_services_running",
    "test_diode_blocks_return_traffic",
    "test_docker_compose_full_pipeline",
    "test_networks_can_be_created",
    "test_traffic_gen_container_startup",
}


@functools.lru_cache(maxsize=1)
def compose_command() -> str | None:
    """Return the working Compose command ('docker compose' or 'docker-compose')."""
    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True, timeout=15,
            )
            if probe.returncode == 0:
                return "docker compose"
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("docker-compose"):
        return "docker-compose"
    return None


@functools.lru_cache(maxsize=1)
def docker_available() -> bool:
    """True only when the Docker daemon is reachable AND Compose is usable."""
    import os
    if os.environ.get("SKIP_DOCKER_TESTS", "").lower() in ("1", "true", "yes"):
        return False
    if not shutil.which("docker") or compose_command() is None:
        return False
    try:
        # `docker info` fails when the CLI exists but the daemon is not running.
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=20
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pytest_collection_modifyitems(config, items):
    """Skip container-stack tests when Docker is unavailable."""
    if docker_available():
        return
    reason = (
        "Docker unavailable (needs the docker CLI, a running daemon, and either "
        "`docker compose` or `docker-compose`)"
    )
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if item.name in _DOCKER_RUNTIME_TESTS:
            item.add_marker(skip)
