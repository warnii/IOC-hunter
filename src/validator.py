import hashlib
import ipaddress
import re
from urllib.parse import urlsplit


def validate_ipv4(value: str) -> bool:
    """Return True if value is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def validate_domain(value: str) -> bool:
    """Validate a domain name, including reserved testing domains."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False

    # Permit the reserved .test suffix used in our training dataset.
    if value.endswith("."):
        value = value[:-1]

    labels = value.split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                label,
            )
        ):
            return False

    return True


def validate_url(value: str) -> bool:
    """Check URL structure without visiting the URL."""
    if not isinstance(value, str):
        return False

    try:
        parsed = urlsplit(value)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if not validate_domain(parsed.hostname):
            return False

        # Accessing .port also detects malformed port numbers.
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False

        return True

    except ValueError:
        return False


def validate_sha256(value: str) -> bool:
    """Check that value has the expected SHA-256 hexadecimal format."""
    if not isinstance(value, str):
        return False

    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))


def validate_indicator(indicator: dict) -> tuple[bool, str]:
    """Validate an indicator's type and value."""

    if not isinstance(indicator, dict):
        return False, "Indicator must be a dictionary."

    indicator_type = indicator.get("type")
    value = indicator.get("value")

    if not isinstance(value, str) or not value.strip():
        return False, "Missing or empty indicator value."

    validators = {
        "ipv4-addr": validate_ipv4,
        "domain-name": validate_domain,
        "url": validate_url,
        "file:hashes.SHA-256": validate_sha256,
    }

    validator = validators.get(indicator_type)

    if validator is None:
        return False, f"Unsupported indicator type: {indicator_type}"

    if not validator(value):
        return False, f"Invalid value for indicator type: {indicator_type}"

    return True, "Valid format."


if __name__ == "__main__":
    test_cases = [
        {"type": "ipv4-addr", "value": "192.0.2.25"},
        {"type": "domain-name", "value": "suspicious-example.test"},
        {
            "type": "url",
            "value": "https://suspicious-example.test/login",
        },
        {
            "type": "file:hashes.SHA-256",
            "value": "a" * 64,
        },
        {"type": "ipv4-addr", "value": "not-an-ip"},
    ]

    for item in test_cases:
        valid, message = validate_indicator(item)
        print(
            f"{item['type']:<22} "
            f"{item['value'][:35]:<35} "
            f"{'PASS' if valid else 'FAIL'} - {message}"
        )