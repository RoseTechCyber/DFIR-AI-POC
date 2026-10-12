import hashlib
import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_FILE = DATA_DIR / "dfir_evidence.db"

CASES = {
    "CASE-0001": {
        "case_name": "Evidence Identification and Preservation",
        "file": DATA_DIR / "cases" / "CASE-0001" / "evidence_1.json",
        "records": [
            ("C1-E001", "case_authorization", "2026-09-14T08:00:00Z",
             "CASE-0001", "authorized", "preparation",
             {"scope": "Synthetic workstation investigation",
              "examiner": "examiner01"}),

            ("C1-E002", "evidence_inventory", "2026-09-14T08:15:00Z",
             "WORKSTATION-01", "identified", "identification",
             {"device_type": "workstation",
              "source": "synthetic evidence inventory"}),

            ("C1-E003", "preservation_record", "2026-09-14T08:30:00Z",
             "DISK-001", "preservation_reviewed", "preservation",
             {"write_blocker_recorded": True,
              "chain_of_custody_verified": False,
              "note": "Independent verification still required"}),

            ("C1-E004", "acquisition_record", "2026-09-14T09:00:00Z",
             "IMAGE-001", "acquisition_documented", "acquisition",
             {"image_reference": "synthetic://CASE-0001/IMAGE-001",
              "acquisition_method": "synthetic fixture",
              "acquisition_verified": False}),

            ("C1-E005", "filesystem_file", "2026-09-14T09:30:00Z",
             "C:/Users/analyst01/Documents/Report.docx", "found",
             "examination",
             {"file_size": 18432, "extension": ".docx",
              "source": "synthetic filesystem record"}),

            ("C1-E006", "preservation_hash", "2026-09-14T09:35:00Z",
             "IMAGE-001", "hash_fixture_calculated", "preservation",
             {"algorithm": "SHA-256",
              "scope": "synthetic artifact payload",
              "note": "Not a hash of a real disk image"}),

            ("C1-E007", "validation_check", "2026-09-14T10:00:00Z",
             "IMAGE-001", "review_required", "validation",
             {"hash_recalculation_required": True,
              "chain_of_custody_review_required": True}),

            ("C1-E008", "report_finding", "2026-09-14T11:00:00Z",
             "CASE-0001", "drafted", "reporting",
             {"finding": "A synthetic file record was identified",
              "limitations": ["No real disk image examined"]}),

            ("C1-E009", "examiner_review", "2026-09-14T11:30:00Z",
             "CASE-0001", "pending", "presentation",
             {"review_status": "pending examiner approval"}),
        ],
    },
    "CASE-0002": {
        "case_name": "USB Timeline and Correlation Investigation",
        "file": DATA_DIR / "cases" / "CASE-0002" / "evidence_2.json",
        "records": [
            ("C2-E001", "case_authorization", "2026-09-15T08:00:00Z",
             "CASE-0002", "authorized", "preparation",
             {"scope": "Synthetic USB and file-access investigation"}),

            ("C2-E002", "evidence_inventory", "2026-09-15T08:15:00Z",
             "WORKSTATION-02", "identified", "identification",
             {"device_type": "workstation",
              "source": "synthetic evidence inventory"}),

            ("C2-E003", "usb_connection", "2026-09-15T10:00:00Z",
             "USB-DEVICE-01", "connected", "examination",
             {"host": "WORKSTATION-02",
              "source": "synthetic USB event"}),

            ("C2-E004", "file_access", "2026-09-15T10:03:00Z",
             "Confidential.docx", "accessed", "examination",
             {"host": "WORKSTATION-02",
              "user": "analyst01",
              "source": "synthetic file-access event"}),

            ("C2-E005", "usb_connection", "2026-09-15T10:10:00Z",
             "USB-DEVICE-01", "disconnected", "examination",
             {"host": "WORKSTATION-02",
              "source": "synthetic USB event"}),

            ("C2-E006", "timeline_event", "2026-09-15T10:15:00Z",
             "CASE-0002", "timeline_built", "analysis",
             {"events_considered": 3,
              "observation": "File access occurred during the recorded USB session"}),

            ("C2-E007", "validation_check", "2026-09-15T10:30:00Z",
             "Confidential.docx", "transfer_not_proven", "validation",
             {"direct_copy_artifact": False,
              "destination_file_confirmed": False,
              "note": "Temporal correlation does not prove copying"}),

            ("C2-E008", "report_finding", "2026-09-15T11:00:00Z",
             "CASE-0002", "drafted", "reporting",
             {"finding": "File access coincided with a recorded USB session",
              "conclusion": "File transfer not proven"}),

            ("C2-E009", "examiner_review", "2026-09-15T11:30:00Z",
             "CASE-0002", "pending", "presentation",
             {"review_status": "pending examiner approval"}),

            ("C2-E010", "preservation_record", "2026-09-15T08:30:00Z",
             "USB-DEVICE-01", "preservation_reviewed", "preservation",
             {"acquisition_verified": False,
              "note": "No physical USB image supplied"}),
        ],
    },
}


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":")
    )


def create_record(case_id, row):
    (
        evidence_id, artifact_type, timestamp, obj, action,
        lifecycle_stage, payload
    ) = row

    payload_hash = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()

    return {
    "evidence_id": evidence_id,
    "case_id": case_id,
    "artifact_type": artifact_type,
    "timestamp": timestamp,
    "object": obj,
    "action": action,

    "tool_name": "synthetic-fixture",
    "evidence_source": "synthetic",

    "source_host":
        payload.get("host"),

    "source_user":
        payload.get("user"),

    "lifecycle_stage":
        lifecycle_stage,

    "source_reference":
        f"synthetic://{case_id}/evidence/{evidence_id}",

    "provenance":
        (
            "Synthetic fixture; SHA-256 covers "
            "artifact_payload only."
        ),

    "sha256": payload_hash,

    "artifact_payload": payload,
}


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        # Fail clearly rather than silently mixing incompatible schemas.
        existing = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='evidence'"
        ).fetchone()

        if existing:
            columns = {
                row[1] for row in
                conn.execute("PRAGMA table_info(evidence)")
            }
            required = {
                "evidence_id", "case_id", "artifact_type", "timestamp",
                "object", "action", "source_reference", "provenance",
                "sha256", "tool_name", "raw_json",
            }
            if not required.issubset(columns):
                raise RuntimeError(
                    "Existing evidence table has an incompatible schema. "
                    "Back up any needed data and use a fresh synthetic "
                    "database or migrate the existing table."
                )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,

    artifact_type TEXT NOT NULL,
    timestamp TEXT,

    object TEXT,
    action TEXT,

    lifecycle_stage TEXT,

    source_host TEXT,
    source_user TEXT,

    evidence_source TEXT,

    source_reference TEXT,
    provenance TEXT,

    sha256 TEXT,
    tool_name TEXT,

    raw_json TEXT NOT NULL,

    FOREIGN KEY (case_id)
    REFERENCES cases(case_id)
    )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_case_time
            ON evidence(case_id, timestamp)
        """)

        for case_id, case in CASES.items():
            conn.execute("""
                INSERT INTO cases(case_id, case_name)
                VALUES (?, ?)
                ON CONFLICT(case_id)
                DO UPDATE SET case_name=excluded.case_name
            """, (case_id, case["case_name"]))

            records = [
                create_record(case_id, row)
                for row in case["records"]
            ]

            # Export JSON files for compatibility and inspection.
            case["file"].parent.mkdir(parents=True, exist_ok=True)
            case["file"].write_text(
                json.dumps(records, indent=2) + "\n",
                encoding="utf-8",
            )

            for record in records:
              conn.execute("""
    INSERT INTO evidence (
        evidence_id,
        case_id,
        artifact_type,
        timestamp,
        object,
        action,
        lifecycle_stage,
        source_host,
        source_user,
        evidence_source,
        source_reference,
        provenance,
        sha256,
        tool_name,
        raw_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    ON CONFLICT(evidence_id) DO UPDATE SET
        case_id=excluded.case_id,
        artifact_type=excluded.artifact_type,
        timestamp=excluded.timestamp,
        object=excluded.object,
        action=excluded.action,
        lifecycle_stage=excluded.lifecycle_stage,
        source_host=excluded.source_host,
        source_user=excluded.source_user,
        evidence_source=excluded.evidence_source,
        source_reference=excluded.source_reference,
        provenance=excluded.provenance,
        sha256=excluded.sha256,
        tool_name=excluded.tool_name,
        raw_json=excluded.raw_json
""", (
    record["evidence_id"],
    record["case_id"],
    record["artifact_type"],
    record["timestamp"],
    record["object"],
    record["action"],
    record.get("lifecycle_stage"),
    record.get("source_host"),
    record.get("source_user"),
    record.get("evidence_source"),
    record["source_reference"],
    record["provenance"],
    record["sha256"],
    record["tool_name"],
    json.dumps(record)
))

            print(
                f"{case_id}: {len(records)} records -> "
                f"{case['file']}"
            )

        conn.commit()

    print(f"SQLite database: {DB_FILE}")
    print("Synthetic dataset generation complete.")


if __name__ == "__main__":
    main()