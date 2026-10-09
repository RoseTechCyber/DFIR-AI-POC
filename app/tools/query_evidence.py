import os
from pathlib import Path
import json
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parents[2]

EVIDENCE_FILE = Path(
    os.getenv(
        "DFIR_EVIDENCE_FILE",
        str(
            BASE_DIR
            / "data"
            / "cases"
            / "CASE-001"
            / "evidence.json"
        ),
    )
)
