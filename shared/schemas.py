"""
Shared schemas and models for HoneyKube honeypot system.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from enum import Enum


class ScannerFamily(str, Enum):
    WEB_SCANNER = "web_scanner"
    PORT_SCANNER = "port_scanner"
    VULN_SCANNER = "vuln_scanner"
    EXPLOIT_FRAMEWORK = "exploit_framework"
    CUSTOM_PROBE = "custom_probe"
    UNKNOWN = "unknown"


class ScannerDetectionResult(BaseModel):
    """Result from scanner detection analysis."""
    is_scanner: bool = False
    tool: str = "unknown"
    family: ScannerFamily = ScannerFamily.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RequestMetadata(BaseModel):
    """Metadata extracted from incoming request."""
    src_ip: str
    src_port: int
    dst_port: int
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, str] = {}
    body: Optional[str] = None
    body_size: int = 0
    timestamp: str
    raw_request: Optional[str] = None


class SessionState(BaseModel):
    """Session state stored in Redis."""
    src_ip: str
    dst_port: int = 0
    prior_paths: List[str] = []
    fingerprint_leaks: List[str] = []
    staging_detected: bool = False
    exploit_detected: bool = False
    request_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    scanner_info: Optional[ScannerDetectionResult] = None
    notes: List[str] = []


class LLMResponse(BaseModel):
    """Expected response format from LLM."""
    status_code: int = Field(ge=100, le=599)
    headers: Dict[str, str] = {}
    body: str = ""
    delay_ms: int = Field(default=0, ge=0, le=10000)
    notes: str = ""


class LLMPlannerRequest(BaseModel):
    """Request to LLM planner service."""
    fingerprint: Dict[str, Any]
    request_metadata: RequestMetadata
    session_state: SessionState
    scanner_info: ScannerDetectionResult





class ArtifactRecord(BaseModel):
    """Record of captured artifact."""
    sha256: str
    filename: str
    content_type: str
    size: int
    src_ip: str
    dst_port: int
    timestamp: str
    path: str


class LogEntry(BaseModel):
    """Structured log entry for request/response pairs."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_port: int
    request: RequestMetadata
    response: LLMResponse
    scanner_info: ScannerDetectionResult
    session_state: SessionState
    artifacts: List[str] = []  # SHA256 hashes
    exploit_stage: bool = False


class Fingerprint(BaseModel):
    """Service fingerprint configuration."""
    name: str
    port: int
    protocol: str = "http"
    server_header: str
    banner: Optional[str] = None
    vuln_tags: List[str] = []
    version: str
    os_hint: str = "Linux"
    default_responses: Dict[str, Dict[str, Any]] = {}
    behavior_hints: List[str] = []
