import json
from datetime import datetime, timezone
from pathlib import Path

from deduplicator import deduplicate_indicators
from validator import validate_indicator


# Source reliability weights for this training exercise.
RELIABILITY_WEIGHTS = {
    "A": 100,
    "B": 75,
    "C": 50,
    "D": 25,
    "E": 10,
}


def calculate_recency_score(last_seen: str) -> int:
    """Assign a simple score based on how recently an IOC was seen."""
    try:
        timestamp = datetime.fromisoformat(
            last_seen.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        age_days = (
            datetime.now(timezone.utc) - timestamp
        ).total_seconds() / 86400

        if age_days < 0:
            return 50
        if age_days <= 1:
            return 100
        if age_days <= 7:
            return 80
        if age_days <= 30:
            return 50

        return 20

    except (ValueError, TypeError, AttributeError):
        return 0


def calculate_threat_score(indicator: dict) -> int:
    """
    Calculate an illustrative 0-100 prioritization score.
    This is not a probability that an indicator is malicious.
    """
    reliability = RELIABILITY_WEIGHTS.get(
        indicator.get("source_reliability", "E"), 10
    )

    confidence = indicator.get("analyst_confidence", 0)
    confidence = max(0, min(100, confidence))

    recency = calculate_recency_score(
        indicator.get("last_seen", "")
    )

    score = (
        reliability * 0.30
        + confidence * 0.50
        + recency * 0.20
    )

    return round(score)


def get_priority(score: int) -> str:
    """Convert the score into a simple triage priority."""
    if score >= 80:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"


def enrich_indicators(indicators: list[dict]) -> list[dict]:
    """Validate, deduplicate, and score the supplied indicators."""
    valid_indicators = []

    for indicator in indicators:
        is_valid, reason = validate_indicator(indicator)

        if is_valid:
            valid_indicators.append(indicator)
        else:
            print(
                f"Skipping {indicator.get('id', 'UNKNOWN')}: {reason}"
            )

    unique_indicators = deduplicate_indicators(valid_indicators)

    enriched = []

    for indicator in unique_indicators:
        result = indicator.copy()
        result["recency_score"] = calculate_recency_score(
            result.get("last_seen", "")
        )
        result["threat_score"] = calculate_threat_score(result)
        result["priority"] = get_priority(result["threat_score"])
        result["assessment"] = (
            "Requires analyst review; score is for triage only."
        )
        enriched.append(result)

    return enriched


def main():
    project_root = Path(__file__).resolve().parent.parent
    input_file = project_root / "data" / "sample_iocs.json"
    output_file = project_root / "outputs" / "enrichment_report.json"

    with input_file.open("r", encoding="utf-8") as file:
        dataset = json.load(file)

    results = enrich_indicators(dataset["indicators"])

    report = {
        "report_name": "IOC Enrichment and Contextual Scoring",
        "dataset_type": dataset.get("dataset_type", "unknown"),
        "scoring_note": (
            "Illustrative training score, not a probability of maliciousness."
        ),
        "input_count": len(dataset["indicators"]),
        "unique_valid_count": len(results),
        "results": results,
    }

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("\nIOC Enrichment Report")
    print("=" * 65)
    print(f"Input indicators : {len(dataset['indicators'])}")
    print(f"Unique valid IOCs: {len(results)}")
    print(f"Report saved to  : {output_file.relative_to(project_root)}")
    print()

    for item in results:
        print(
            f"{item['value']:<40} "
            f"Score: {item['threat_score']:>3}  "
            f"Priority: {item['priority']}"
        )


if __name__ == "__main__":
    main()