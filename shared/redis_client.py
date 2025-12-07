"""
Redis client wrapper for HoneyKube session management.
"""

import os
import json
import logging
from typing import Optional
from datetime import datetime
import redis.asyncio as redis

from schemas import SessionState, ArtifactRecord, ScannerDetectionResult

logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

SESSION_TTL = int(os.getenv("SESSION_TTL", "3600"))  # 1 hour default


class RedisSessionManager:
    """Manages session state in Redis."""
    
    def __init__(self):
        self._pool: Optional[redis.ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Establish Redis connection."""
        self._pool = redis.ConnectionPool(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            decode_responses=True,
            max_connections=20
        )
        self._client = redis.Redis(connection_pool=self._pool)
        # Test connection
        await self._client.ping()
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    
    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
    
    def _session_key(self, src_ip: str, dst_port: int) -> str:
        """Generate session key."""
        return f"session:{src_ip}:{dst_port}"
    
    def _artifact_key(self, sha256: str) -> str:
        """Generate artifact key."""
        return f"artifact:{sha256}"
    
    async def get_session(self, src_ip: str, dst_port: int) -> SessionState:
        """Retrieve or create session state."""
        key = self._session_key(src_ip, dst_port)
        data = await self._client.get(key)
        
        now = datetime.utcnow().isoformat()
        
        if data:
            session = SessionState(**json.loads(data))
            session.last_seen = now
            session.request_count += 1
        else:
            session = SessionState(
                src_ip=src_ip,
                dst_port=dst_port,
                first_seen=now,
                last_seen=now,
                request_count=1
            )
        
        return session
    
    async def save_session(self, session: SessionState):
        """Save session state to Redis."""
        key = self._session_key(session.src_ip, session.dst_port)
        await self._client.setex(
            key,
            SESSION_TTL,
            session.model_dump_json()
        )
    
    async def update_session_paths(self, src_ip: str, dst_port: int, path: str):
        """Add path to session history."""
        session = await self.get_session(src_ip, dst_port)
        if path not in session.prior_paths:
            session.prior_paths.append(path)
            # Keep only last 100 paths
            session.prior_paths = session.prior_paths[-100:]
        await self.save_session(session)
    
    async def add_fingerprint_leak(self, src_ip: str, dst_port: int, leak: str):
        """Record a fingerprint leak shown to attacker."""
        session = await self.get_session(src_ip, dst_port)
        if leak not in session.fingerprint_leaks:
            session.fingerprint_leaks.append(leak)
        await self.save_session(session)
    
    async def mark_staging(self, src_ip: str, dst_port: int):
        """Mark session as in staging phase."""
        session = await self.get_session(src_ip, dst_port)
        session.staging_detected = True
        session.notes.append(f"Staging detected at {datetime.utcnow().isoformat()}")
        await self.save_session(session)
    
    async def mark_exploit(self, src_ip: str, dst_port: int):
        """Mark session as exploit attempt detected."""
        session = await self.get_session(src_ip, dst_port)
        session.exploit_detected = True
        session.notes.append(f"Exploit detected at {datetime.utcnow().isoformat()}")
        await self.save_session(session)
    
    async def update_scanner_info(
        self, src_ip: str, dst_port: int, scanner_info: ScannerDetectionResult
    ):
        """Update scanner detection info for session."""
        session = await self.get_session(src_ip, dst_port)
        session.scanner_info = scanner_info
        await self.save_session(session)
    
    async def store_artifact(self, artifact: ArtifactRecord):
        """Store artifact metadata in Redis."""
        key = self._artifact_key(artifact.sha256)
        # Use hash to allow querying by various fields
        await self._client.hset(
            key,
            mapping={
                "sha256": artifact.sha256,
                "filename": artifact.filename,
                "content_type": artifact.content_type,
                "size": str(artifact.size),
                "src_ip": artifact.src_ip,
                "dst_port": str(artifact.dst_port),
                "timestamp": artifact.timestamp,
                "path": artifact.path
            }
        )
        # Add to artifacts index
        await self._client.sadd(f"artifacts:ip:{artifact.src_ip}", artifact.sha256)
        await self._client.sadd("artifacts:all", artifact.sha256)
    
    async def artifact_exists(self, sha256: str) -> bool:
        """Check if artifact already captured."""
        return await self._client.exists(self._artifact_key(sha256))
    
    async def get_artifact(self, sha256: str) -> Optional[ArtifactRecord]:
        """Retrieve artifact metadata."""
        key = self._artifact_key(sha256)
        data = await self._client.hgetall(key)
        if data:
            data["size"] = int(data["size"])
            data["dst_port"] = int(data["dst_port"])
            return ArtifactRecord(**data)
        return None


# Global instance
redis_manager = RedisSessionManager()
