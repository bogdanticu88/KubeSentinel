from datetime import timedelta

import pytest

from kubesentinel.cli.duration import DurationParseError, parse_duration


def test_days_hours_and_minutes():
    assert parse_duration("7d") == timedelta(days=7)
    assert parse_duration("24h") == timedelta(hours=24)
    assert parse_duration("30m") == timedelta(minutes=30)


def test_strips_surrounding_whitespace():
    assert parse_duration("  7d  ") == timedelta(days=7)


@pytest.mark.parametrize("value", ["", "d", "7", "7x", "abc"])
def test_invalid_values_raise(value):
    with pytest.raises(DurationParseError):
        parse_duration(value)
