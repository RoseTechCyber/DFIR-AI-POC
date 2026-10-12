import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = BASE_DIR / "data" / "dfir_evidence.db"

SOURCES = [
    (
        "CASE-0001",
        BASE_DIR / "data/cases/CASE-0001/evidence_1.json",
        "JSON",
    ),
    (
        "CASE-0002",
        BASE_DIR / "data/cases/CASE-0002/evidence_2.json",
        "JSON",
    ),
]


def main():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                case_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                timestamp TEXT,
                source_reference TEXT,
                provenance TEXT,
                tool_name TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (case_id, evidence_id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_case_timestamp
            ON evidence(case_id, timestamp)
        """)

        for case_id, file_path, tool_name in SOURCES:
            if not file_path.is_file():
                raise FileNotFoundError(file_path)

            records = json.loads(
                file_path.read_text(encoding="utf-8")
            )

            if not isinstance(records, list):
                raise ValueError(f"Expected a JSON list: {file_path}")

            if not all(isinstance(r, dict) for r in records):
                raise ValueError(f"Invalid evidence record: {file_path}")

            for record in records:
                if record.get("case_id") != case_id:
                    raise ValueError(
                        f"Unexpected case ID in {file_path}: "
                        f"{record.get('case_id')}"
                    )

                evidence_id = record.get("evidence_id")
                if not evidence_id:
                    raise ValueError(
                        f"Missing evidence_id in {file_path}"
                    )

                conn.execute("""
                    INSERT INTO evidence (
                        case_id, evidence_id, artifact_type,
                        timestamp, source_reference, provenance,
                        tool_name, raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id, evidence_id)
                    DO UPDATE SET
                        artifact_type = excluded.artifact_type,
                        timestamp = excluded.timestamp,
                        source_reference = excluded.source_reference,
                        provenance = excluded.provenance,
                        tool_name = excluded.tool_name,
                        raw_json = excluded.raw_json
                """, (
                    case_id,
                    evidence_id,
                    str(record.get("artifact_type", "unknown")),
                    record.get("timestamp"),
                    record.get("source_reference"),
                    record.get("provenance"),
                    tool_name,
                    json.dumps(record),
                ))

            print(f"Imported {len(records)} records for {case_id}")

    print(f"SQLite database created/updated: {DB_FILE}")


if __name__ == "__main__":
    main()