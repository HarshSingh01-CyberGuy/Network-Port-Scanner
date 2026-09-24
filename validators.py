import re


def validate_ports(port_text):
    """
    Validate comma-separated port numbers.
    """
    if not port_text.strip():
        return True

    if not re.fullmatch(
        r"[0-9,\-\s]+",
        port_text
    ):
        return False

    return True


def validate_range(range_text):
    """
    Validate port range.
    """
    if not range_text.strip():
        return True

    if not re.fullmatch(
        r"\d+\s*-\s*\d+",
        range_text
    ):
        return False

    start, end = map(
        int,
        range_text.split("-")
    )

    return (
        1 <= start <= 65535
        and
        1 <= end <= 65535
        and
        start <= end
    )