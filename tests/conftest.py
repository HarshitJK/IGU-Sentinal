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
_TRAINING_TEST_MODULES = {"test_isoforest", "test_xgb"}


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
