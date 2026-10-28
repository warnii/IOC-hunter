import json
from pathlib import Path
from collections import defaultdict


def normalize_value(indicator: dict) -> str:
    """Normalize values for duplicate comparison."""
    indicator_type = indicator.get("type", "")
    value = indicator.get("value", "").strip()

    if indicator_type in ("domain-name", "url"):
        return value.lower()

    return value


def deduplicate_indicators(indicators: list[dict]) -> list[dict]:
    """
    Combine duplicate indicators while preserving their provenance.
    Indicators with different types are never merged.
    """
    grouped = {}

    for indicator in indicators:
        key = (
            indicator.get("type"),
            normalize_value(indicator),
        )

        if key not in grouped:
            record = indicator.copy()
            record["sources"] = [indicator.get("source", "Unknown")]
            record["record_ids"] = [indicator.get("id", "Unknown")]
            record["notes_list"] = [indicator.get("notes", "")]
            grouped[key] = record
            continue

        existing = grouped[key]

        source = indicator.get("source", "Unknown")
        record_id = indicator.get("id", "Unknown")
        notes = indicator.get("notes", "")

        if source not in existing["sources"]:
            existing["sources"].append(source)

        if record_id not in existing["record_ids"]:
            existing["record_ids"].append(record_id)

        if notes and notes not in existing["notes_list"]:
            existing["notes_list"].append(notes)

        # Preserve the earliest first-seen timestamp.
        first_seen = indicator.get("first_seen")
        current_first_seen = existing.get("first_seen")

        if first_seen and (
            not current_first_seen or first_seen < current_first_seen
        ):
            existing["first_seen"] = first_seen

        # Preserve the latest last-seen timestamp.
        last_seen = indicator.get("last_seen")
        current_last_seen = existing.get("last_seen")

        if last_seen and (
            not current_last_seen or last_seen > current_last_seen
        ):
            existing["last_seen"] = last_seen

        # Keep the highest analyst confidence for this basic exercise.
        confidence = indicator.get("analyst_confidence", 0)
        current_confidence = existing.get("analyst_confidence", 0)

        existing["analyst_confidence"] = max(
            current_confidence, confidence
        )

    results = []

    for record in grouped.values():
        record["source_count"] = len(record["sources"])
        record["notes"] = " | ".join(
            note for note in record.pop("notes_list") if note
        )
        results.append(record)

    return results


def main():
    project_root = Path(__file__).resolve().parent.parent
    input_file = project_root / "data" / "sample_iocs.json"

    with input_file.open("r", encoding="utf-8") as file:
        dataset = json.load(file)

    indicators = dataset["indicators"]
    unique_indicators = deduplicate_indicators(indicators)

    print("IOC Deduplication Report")
    print("=" * 50)
    print(f"Input indicators : {len(indicators)}")
    print(f"Unique indicators: {len(unique_indicators)}")
    print(f"Duplicates merged: {len(indicators) - len(unique_indicators)}")
    print()

    for item in unique_indicators:
        print(f"Type       : {item['type']}")
        print(f"Value      : {item['value']}")
        print(f"Sources    : {', '.join(item['sources'])}")
        print(f"First seen : {item.get('first_seen', 'Unknown')}")
        print(f"Last seen  : {item.get('last_seen', 'Unknown')}")
        print(f"Confidence : {item.get('analyst_confidence', 'Unknown')}")
        print("-" * 50)


if __name__ == "__main__":
    main()