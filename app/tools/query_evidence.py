from pathlib import Path
import json
from datetime import datetime


EVIDENCE_FILE = Path(
    r"C:\DFIR-POC\data\cases\CASE-001\evidence.json"
)


def load_evidence():
    if not EVIDENCE_FILE.exists():
        raise FileNotFoundError(
            f"Evidence file not found: {EVIDENCE_FILE}"
        )

    with EVIDENCE_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_timeline():
    evidence = load_evidence()

    return sorted(
        evidence,
        key=lambda item: item.get("timestamp") or ""
    )


def find_by_type(artifact_type):
    evidence = load_evidence()

    return [
        item
        for item in evidence
        if item.get("artifact_type") == artifact_type
    ]


def find_by_object(object_name):
    evidence = load_evidence()

    return [
        item
        for item in evidence
        if item.get("object") == object_name
    ]


def get_case_summary():
    evidence = load_evidence()

    return {
        "case_id": evidence[0]["case_id"] if evidence else None,
        "evidence_count": len(evidence),
        "artifact_types": sorted(
            set(item["artifact_type"] for item in evidence)
        ),
        "first_event": (
            min(
                item["timestamp"]
                for item in evidence
                if item.get("timestamp")
            )
            if evidence
            else None
        ),
        "last_event": (
            max(
                item["timestamp"]
                for item in evidence
                if item.get("timestamp")
            )
            if evidence
            else None
        ),
    }
