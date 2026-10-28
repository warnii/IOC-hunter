import sys
import unittest
from pathlib import Path

# Add src/ to the module search path.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from validator import validate_indicator
from deduplicator import deduplicate_indicators
from enrichment import calculate_recency_score, get_priority


class TestIOCValidator(unittest.TestCase):

    def test_valid_ipv4(self):
        valid, _ = validate_indicator({
            "type": "ipv4-addr",
            "value": "192.0.2.25",
        })
        self.assertTrue(valid)

    def test_invalid_ipv4(self):
        valid, _ = validate_indicator({
            "type": "ipv4-addr",
            "value": "999.999.999.999",
        })
        self.assertFalse(valid)

    def test_valid_domain(self):
        valid, _ = validate_indicator({
            "type": "domain-name",
            "value": "suspicious-example.test",
        })
        self.assertTrue(valid)

    def test_invalid_sha256(self):
        valid, _ = validate_indicator({
            "type": "file:hashes.SHA-256",
            "value": "abc123",
        })
        self.assertFalse(valid)


class TestIOCDeduplication(unittest.TestCase):

    def test_duplicate_ip_is_merged(self):
        records = [
            {
                "id": "IOC-001",
                "type": "ipv4-addr",
                "value": "192.0.2.25",
                "source": "Feed Alpha",
                "first_seen": "2026-10-27T09:00:00Z",
                "last_seen": "2026-10-27T10:00:00Z",
                "analyst_confidence": 40,
                "notes": "First report",
            },
            {
                "id": "IOC-002",
                "type": "ipv4-addr",
                "value": "192.0.2.25",
                "source": "Feed Beta",
                "first_seen": "2026-10-27T08:00:00Z",
                "last_seen": "2026-10-28T10:00:00Z",
                "analyst_confidence": 70,
                "notes": "Second report",
            },
        ]

        result = deduplicate_indicators(records)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source_count"], 2)
        self.assertIn("Feed Alpha", result[0]["sources"])
        self.assertIn("Feed Beta", result[0]["sources"])
        self.assertEqual(
            result[0]["first_seen"],
            "2026-10-27T08:00:00Z",
        )
        self.assertEqual(
            result[0]["last_seen"],
            "2026-10-28T10:00:00Z",
        )

    def test_different_types_are_not_merged(self):
        records = [
            {"type": "domain-name", "value": "example.test"},
            {"type": "url", "value": "example.test"},
        ]

        result = deduplicate_indicators(records)
        self.assertEqual(len(result), 2)


class TestEnrichmentHelpers(unittest.TestCase):

    def test_priority_thresholds(self):
        self.assertEqual(get_priority(85), "HIGH")
        self.assertEqual(get_priority(65), "MEDIUM")
        self.assertEqual(get_priority(35), "LOW")

    def test_recent_indicator_score(self):
        # A timestamp just before the current time should be recent.
        from datetime import datetime, timezone, timedelta

        recent = (
            datetime.now(timezone.utc) - timedelta(minutes=5)
        ).isoformat()

        self.assertEqual(calculate_recency_score(recent), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)