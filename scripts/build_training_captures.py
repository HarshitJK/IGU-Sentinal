"""Compatibility shim — imports build-training-captures as a Python module.

The canonical filename uses dashes for shell ergonomics but Python requires
underscores for imports. This shim allows tests to do:
  import scripts.build_training_captures as btc
"""
import importlib.util
import sys
from pathlib import Path

_script = Path(__file__).parent / "build-training-captures.py"
_spec = importlib.util.spec_from_file_location("scripts.build_training_captures", _script)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["scripts.build_training_captures"] = _mod
_spec.loader.exec_module(_mod)
