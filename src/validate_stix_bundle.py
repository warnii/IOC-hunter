import json
from pathlib import Path

from stix2 import parse


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUNDLE_FILE = PROJECT_ROOT / "outputs" / "stix_bundle.json"


def validate_bundle(file_path: Path) -> bool:
    """Check that the exported file contains a valid STIX bundle."""

    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        return False

    try:
        with file_path.open("r", encoding="utf-8") as file:
            raw_data = json.load(file)

        if raw_data.get("type") != "bundle":
            print("ERROR: The JSON document is not a STIX bundle.")
            return False

        parsed_bundle = parse(
            json.dumps(raw_data),
            allow_custom=False,
        )

        objects = raw_data.get("objects", [])

        if not objects:
            print("ERROR: The bundle contains no objects.")
            return False

        object_ids = [
            item.get("id")
            for item in objects
            if isinstance(item, dict)
        ]

        if len(object_ids) != len(objects):
            print("ERROR: One or more objects are not JSON objects.")
            return False

        if any(not object_id for object_id in object_ids):
            print("ERROR: One or more objects are missing IDs.")
            return False

        if len(object_ids) != len(set(object_ids)):
            print("ERROR: Duplicate STIX object IDs found.")
            return False

        indicator_count = 0

        for item in objects:
            if item.get("type") == "indicator":
                indicator_count += 1

                if item.get("spec_version") != "2.1":
                    print(
                        f"ERROR: Indicator {item.get('id')} "
                        "does not specify STIX 2.1."
                    )
                    return False

                if not item.get("pattern"):
                    print(
                        f"ERROR: Indicator {item.get('id')} "
                        "has no pattern."
                    )
                    return False

                if not item.get("pattern_type"):
                    print(
                        f"ERROR: Indicator {item.get('id')} "
                        "has no pattern type."
                    )
                    return False

        if indicator_count == 0:
            print("ERROR: No indicator objects found.")
            return False

        print("STIX Bundle Validation Report")
        print("=" * 40)
        print("JSON parsing       : PASS")
        print("STIX parsing       : PASS")
        print("Bundle structure   : PASS")
        print("Object IDs         : PASS")
        print("STIX 2.1 indicators: PASS")
        print(f"Total objects      : {len(objects)}")
        print(f"Indicators         : {indicator_count}")
        print(f"Bundle ID          : {parsed_bundle.id}")
        print("\nValidation successful!")

        return True

    except (json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"VALIDATION FAILED: {error}")
        return False


if __name__ == "__main__":
    success = validate_bundle(BUNDLE_FILE)
    raise SystemExit(0 if success else 1)