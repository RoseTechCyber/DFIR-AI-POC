# app/evidence/models.py

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any, Optional


class EvidenceItem(BaseModel):
    evidence_id: str
    case_id: str

    artifact_type: str
    timestamp: Optional[datetime] = None

    subject: Optional[str] = None
    action: Optional[str] = None
    object: Optional[str] = None
    value: Optional[Any] = None

    tool: str
    confidence: float = Field(ge=0.0, le=1.0)

    source_reference: Optional[str] = None
    provenance: Optional[dict] = None