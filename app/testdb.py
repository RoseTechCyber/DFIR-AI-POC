import sqlite3
from pathlib import Path

DB_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "dfir_evidence.db"
)

def inspect_database():
    if not DB_FILE.exists():
        print(f"Database missing: {DB_FILE}")
        return

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row

        tables = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
        """).fetchall()

        print("Database:", DB_FILE)
        print("Tables:", [row["name"] for row in tables])

        for row in tables:
            table = row["name"]

            # Table names originate from sqlite_master, not user input.
            columns = conn.execute(
                f'PRAGMA table_info("{table}")'
            ).fetchall()

            print(f"\nTable: {table}")
            for column in columns:
                print(
                    column["name"],
                    column["type"],
                    "PRIMARY KEY" if column["pk"] else ""
                )

        if any(row["name"] == "evidence" for row in tables):
            print("\nEvidence counts by case:")
            for row in conn.execute("""
                SELECT case_id, COUNT(*) AS record_count
                FROM evidence
                GROUP BY case_id
            """):
                print(dict(row))

if __name__ == "__main__":
    inspect_database()