import json
import sys
from pathlib import Path

from stix2 import Bundle, Indicator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from enrichment import enrich_indicators


# Map our training dataset types to STIX Cyber Observable types.
STIX_PATTERNS = {
    "ipv4-addr": lambda value: f"[ipv4-addr:value = '{value}']",
    "domain-name": lambda value: f"[domain-name:value = '{value}']",
    "url": lambda value: f"[url:value = '{value}']",
    "file:hashes.SHA-256": lambda value: (
        f"[file:hashes.'SHA-256' = '{value.lower()}']"
    ),
}


def create_stix_indicators(indicators: list[dict]) -> list[Indicator]:
    """Convert supported IOCs into STIX 2.1 Indicator objects."""
    stix_indicators = []

    for item in indicators:
        pattern_builder = STIX_PATTERNS.get(item.get("type"))

        if pattern_builder is None:
            print(f"Skipping unsupported type: {item.get('type')}")
            continue

        value = item["value"]

        stix_indicator = Indicator(
            name=f"Training IOC: {item['type']}",
            pattern=pattern_builder(value),
            pattern_type="stix",
            confidence=max(
                0, min(100, item.get("analyst_confidence", 0))
            ),
            labels=["threat-intelligence", "training"],
            description=(
                f"Synthetic training indicator. "
                f"Sources: {', '.join(item.get('sources', []))}. "
                f"Threat triage score: {item.get('threat_score', 0)}. "
                f"Priority: {item.get('priority', 'UNKNOWN')}."
            ),
        )

        stix_indicators.append(stix_indicator)

    return stix_indicators


def main():
    input_file = PROJECT_ROOT / "data" / "sample_iocs.json"
    output_file = PROJECT_ROOT / "outputs" / "stix_bundle.json"

    with input_file.open("r", encoding="utf-8") as file:
        dataset = json.load(file)

    enriched = enrich_indicators(dataset["indicators"])
    stix_indicators = create_stix_indicators(enriched)

    bundle = Bundle(
        objects=stix_indicators,
        allow_custom=False,
    )

    with output_file.open("w", encoding="utf-8") as file:
        file.write(bundle.serialize(pretty=True))

    print("STIX 2.1 Export Complete")
    print("=" * 40)
    print(f"Enriched indicators: {len(enriched)}")
    print(f"STIX objects       : {len(stix_indicators)}")
    print(f"Output file        : outputs/stix_bundle.json")
    print(f"Bundle ID          : {bundle.id}")


if __name__ == "__main__":
    main()