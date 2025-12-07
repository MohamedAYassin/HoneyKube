"""
Artifact Sink Service - HoneyKube Honeypot
Handles logging, artifact storage, and exploit detection.
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from aiohttp import web
import aiofiles
import aiofiles.os

# Add shared module to path
sys.path.insert(0, "/app/shared")

from schemas import LogEntry, ArtifactRecord
from redis_client import redis_manager
from utils import setup_logging, get_timestamp, sanitize_path, compute_sha256

logger = setup_logging("artifact-sink")

# Configuration
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8083"))
LOG_DIR = os.getenv("LOG_DIR", "/logs")
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "/artifacts")
MAX_ARTIFACT_SIZE = int(os.getenv("MAX_ARTIFACT_SIZE", "52428800"))  # 50MB
EXPLOIT_MARKERS = os.getenv("EXPLOIT_MARKERS", "").split(",") if os.getenv("EXPLOIT_MARKERS") else []

# Exploit stage detection patterns
EXPLOIT_STAGE_PATTERNS = [
    # Post-exploitation commands
    r"(?:cat|type)\s+(?:/etc/passwd|/etc/shadow|C:\\Windows\\System32\\config)",
    r"(?:wget|curl|certutil|powershell).*(?:http|https|ftp)://",
    r"(?:nc|ncat|netcat)\s+.*\s+-[elp]",
    r"(?:python|perl|ruby|php)\s+-[cre]",
    r"(?:base64|openssl)\s+(?:-d|dec)",
    # Persistence mechanisms
    r"cron(?:tab)?|at\s+\d|schtasks|reg\s+add",
    r"(?:useradd|adduser|net\s+user)",
    r"(?:chmod|chown|icacls)\s+.*(?:\+[xs]|777|\/grant)",
    # Data exfiltration
    r"tar\s+.*-[czf]|zip\s+-r|7z\s+a",
    r"scp\s+|rsync\s+|ftp\s+",
    # Lateral movement
    r"(?:ssh|psexec|wmic|winrm)",
    r"pass(?:word)?.*(?:dump|hash|crack)",
]

# Compile patterns
import re
EXPLOIT_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in EXPLOIT_STAGE_PATTERNS]


async def ensure_directories():
    """Ensure log and artifact directories exist."""
    for directory in [LOG_DIR, ARTIFACT_DIR]:
        path = Path(directory)
        if not path.exists():
            await aiofiles.os.makedirs(str(path), exist_ok=True)
            logger.info(f"Created directory: {directory}")


def detect_exploit_stage(log_entry: LogEntry) -> bool:
    """Detect if request indicates exploit stage (not reconnaissance)."""
    # Check request body
    body = log_entry.request.body or ""
    
    # Check path and query params
    path = log_entry.request.path
    query = " ".join(f"{k}={v}" for k, v in log_entry.request.query_params.items())
    
    search_text = f"{path} {query} {body}"
    
    for pattern in EXPLOIT_PATTERNS_COMPILED:
        if pattern.search(search_text):
            return True
    
    # Check for file uploads (potential payload delivery)
    if log_entry.artifacts:
        return True
    
    # Check session state indicators
    if log_entry.session_state.staging_detected:
        return True
    
    # High request count + scanner = likely moving to exploit
    if log_entry.session_state.request_count > 50 and log_entry.scanner_info.is_scanner:
        return True
    
    return False


async def write_log_entry(log_entry: LogEntry):
    """Write log entry to JSON file."""
    # Create date-based log file
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    log_file = Path(LOG_DIR) / f"honeypot-{date_str}.jsonl"
    
    # Convert to JSON
    log_json = log_entry.model_dump_json()
    
    async with aiofiles.open(str(log_file), mode="a") as f:
        await f.write(log_json + "\n")


async def log_endpoint(request: web.Request) -> web.Response:
    """Handle incoming log entries."""
    try:
        data = await request.json()
        log_entry = LogEntry(**data)
        
        # Detect exploit stage
        is_exploit = detect_exploit_stage(log_entry)
        log_entry.exploit_stage = is_exploit
        
        if is_exploit:
            logger.info(
                f"EXPLOIT STAGE DETECTED from {log_entry.src_ip}:{log_entry.dst_port} "
                f"- {log_entry.request.method} {log_entry.request.path}"
            )
            # Mark session as exploit
            await redis_manager.mark_exploit(log_entry.src_ip, log_entry.dst_port)
        
        # Write log entry
        await write_log_entry(log_entry)
        
        logger.info(
            f"Logged: {log_entry.src_ip} -> :{log_entry.dst_port} "
            f"{log_entry.request.method} {log_entry.request.path} "
            f"[{log_entry.response.status_code}]"
        )
        
        return web.json_response({"status": "logged", "exploit_stage": is_exploit})
    
    except Exception as e:
        logger.error(f"Log error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def artifact_endpoint(request: web.Request) -> web.Response:
    """Handle artifact uploads."""
    try:
        reader = await request.multipart()
        
        file_data = None
        sha256 = None
        src_ip = None
        dst_port = None
        path = None
        filename = "unnamed"
        content_type = "application/octet-stream"
        
        async for part in reader:
            if part.name == "file":
                filename = part.filename or "unnamed"
                content_type = part.headers.get("Content-Type", "application/octet-stream")
                file_data = await part.read(decode=False)
                
                # Check size limit
                if len(file_data) > MAX_ARTIFACT_SIZE:
                    return web.json_response(
                        {"error": "Artifact too large"},
                        status=413
                    )
            elif part.name == "sha256":
                sha256 = (await part.read()).decode()
            elif part.name == "src_ip":
                src_ip = (await part.read()).decode()
            elif part.name == "dst_port":
                dst_port = int((await part.read()).decode())
            elif part.name == "path":
                path = (await part.read()).decode()
        
        if not file_data:
            return web.json_response({"error": "No file data"}, status=400)
        
        # Compute hash if not provided
        if not sha256:
            sha256 = compute_sha256(file_data)
        else:
            # Verify provided hash
            computed = compute_sha256(file_data)
            if sha256 != computed:
                logger.warning(f"Hash mismatch: {sha256} != {computed}")
                sha256 = computed
        
        # Check if artifact already exists
        if await redis_manager.artifact_exists(sha256):
            logger.info(f"Artifact already exists: {sha256}")
            return web.json_response({
                "status": "exists",
                "sha256": sha256
            })
        
        # Sanitize filename
        safe_filename = sanitize_path(filename)
        
        # Store artifact with hash as filename
        artifact_path = Path(ARTIFACT_DIR) / f"{sha256}_{safe_filename}"
        
        async with aiofiles.open(str(artifact_path), mode="wb") as f:
            await f.write(file_data)
        
        # Create artifact record
        artifact = ArtifactRecord(
            sha256=sha256,
            filename=safe_filename,
            content_type=content_type,
            size=len(file_data),
            src_ip=src_ip or "unknown",
            dst_port=dst_port or 0,
            timestamp=get_timestamp(),
            path=path or "/"
        )
        
        # Store in Redis
        await redis_manager.store_artifact(artifact)
        
        # Mark session as staging (file upload is usually staging/exploitation)
        if src_ip and dst_port:
            await redis_manager.mark_staging(src_ip, dst_port)
        
        logger.info(
            f"Artifact saved: {sha256} ({safe_filename}, {len(file_data)} bytes) "
            f"from {src_ip}"
        )
        
        return web.json_response({
            "status": "saved",
            "sha256": sha256,
            "size": len(file_data)
        })
    
    except Exception as e:
        logger.error(f"Artifact save error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def get_artifact(request: web.Request) -> web.Response:
    """Retrieve artifact metadata."""
    try:
        sha256 = request.match_info.get("sha256")
        if not sha256:
            return web.json_response({"error": "SHA256 required"}, status=400)
        
        artifact = await redis_manager.get_artifact(sha256)
        if artifact:
            return web.json_response(artifact.model_dump())
        else:
            return web.json_response({"error": "Not found"}, status=404)
    
    except Exception as e:
        logger.error(f"Get artifact error: {e}")
        return web.json_response({"error": str(e)}, status=500)


async def stats_endpoint(request: web.Request) -> web.Response:
    """Get logging statistics."""
    try:
        # Count log files
        log_path = Path(LOG_DIR)
        log_files = list(log_path.glob("honeypot-*.jsonl"))
        
        # Count artifacts
        artifact_path = Path(ARTIFACT_DIR)
        artifacts = list(artifact_path.glob("*"))
        
        total_log_size = sum(f.stat().st_size for f in log_files)
        total_artifact_size = sum(f.stat().st_size for f in artifacts)
        
        return web.json_response({
            "log_files": len(log_files),
            "log_size_bytes": total_log_size,
            "artifacts": len(artifacts),
            "artifact_size_bytes": total_artifact_size,
            "timestamp": get_timestamp()
        })
    
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return web.json_response({"error": str(e)}, status=500)


async def health_check(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.Response(text="OK")


async def on_startup(app: web.Application):
    """Initialize on startup."""
    await ensure_directories()
    await redis_manager.connect()
    logger.info(f"Artifact sink started on port {LISTEN_PORT}")


async def on_cleanup(app: web.Application):
    """Cleanup on shutdown."""
    await redis_manager.close()
    logger.info("Artifact sink shutdown complete")


def create_app() -> web.Application:
    """Create the application."""
    app = web.Application(client_max_size=MAX_ARTIFACT_SIZE + 1048576)
    
    app.router.add_get("/_health", health_check)
    app.router.add_post("/log", log_endpoint)
    app.router.add_post("/artifact", artifact_endpoint)
    app.router.add_get("/artifact/{sha256}", get_artifact)
    app.router.add_get("/stats", stats_endpoint)
    
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    
    return app


if __name__ == "__main__":
    logger.info(f"Artifact sink starting on port {LISTEN_PORT}")
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT)
