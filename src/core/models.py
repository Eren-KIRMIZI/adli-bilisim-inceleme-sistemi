"""Standardized Pydantic forensic artifact output model."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ForensicArtifactModel(BaseModel):
    """Standard analysis output contract shared across all independent forensic engines."""

    artifact_id: str
    case_id: int
    evidence_id: Optional[int] = None
    artifact_type: str
    source_file: str
    source_location: str
    extracted_data: Dict[str, Any] = Field(default_factory=dict)
    original_timestamp: Optional[str] = None
    normalized_timestamp: Optional[datetime] = None
    parser_name: str
    parser_version: str
    confidence: int = Field(default=100, ge=0, le=100)
    analysis_date: datetime = Field(default_factory=datetime.utcnow)
    warnings: List[str] = Field(default_factory=list)
