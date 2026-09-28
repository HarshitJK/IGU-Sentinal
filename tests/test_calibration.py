import pytest
from igu_sentinel.fusion.calibration import fit, predict
from igu_sentinel.eval.candidate import check_partitions


def test_calibration_requires_independent_outcomes():
    with pytest.raises(ValueError):
        fit([[.8] * 5] * 30, [1] * 30)


def test_calibration_fits_and_stays_bounded():
    model = fit([[i / 99] * 5 for i in range(100)], [int(i > 49) for i in range(100)])
    assert 0 < predict(model, [.1] * 5) < predict(model, [.9] * 5) < 1


def test_capture_leakage_is_rejected():
    with pytest.raises(ValueError):
        check_partitions([[{'group': 'same'}], [{'group': 'same'}]])
    with pytest.raises(ValueError):
        check_partitions([[{'group': 'a', 'source_sha256': 'x'}], [{'group': 'b', 'source_sha256': 'x'}]])
