"""Parses the simple duration strings --since takes, "7d", "24h", "30m".

A single number plus a unit suffix covers every real use of --since anyone
is likely to type. A full duration grammar is not worth the complexity it
would add for a CLI flag.
"""

from datetime import timedelta

_UNITS = {"d": "days", "h": "hours", "m": "minutes"}


class DurationParseError(Exception):
    """A --since value could not be parsed."""


def parse_duration(value: str) -> timedelta:
    value = value.strip()
    unit = value[-1] if value else ""
    if unit not in _UNITS:
        raise DurationParseError(
            f"{value!r} is not a duration, use a number followed by d, h, or m, for example 7d"
        )
    try:
        amount = int(value[:-1])
    except ValueError as error:
        raise DurationParseError(
            f"{value!r} is not a duration, use a number followed by d, h, or m, for example 7d"
        ) from error
    return timedelta(**{_UNITS[unit]: amount})
