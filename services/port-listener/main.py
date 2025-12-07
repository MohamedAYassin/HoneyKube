"""
Port Listener Service - HoneyKube Honeypot
Exposes configurable ports with fingerprinted responses.
"""

import asyncio
import os
import sys
import yaml
import aiohttp
from aiohttp import web
from datetime import datetime
from typing import Dict, Any, Optional

# Add shared module to path
sys.path.insert(0, "/app/shared")

from schemas import (
    RequestMetadata, SessionState, ScannerDetectionResult,
    LLMResponse, LLMPlannerRequest, Fingerprint, LogEntry
)
from redis_client import redis_manager
from utils import setup_logging, get_timestamp, truncate_string, compute_sha256

logger = setup_logging("port-listener")

# Configuration
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
FINGERPRINT_PATH = os.getenv("FINGERPRINT_PATH", "/config/fingerprint.yaml")
SCANNER_DETECTOR_URL = os.getenv("SCANNER_DETECTOR_URL", "http://scanner-detector:8081")
LLM_PLANNER_URL = os.getenv("LLM_PLANNER_URL", os.getenv("GEMINI_PLANNER_URL", "http://llm-planner:8082"))
ARTIFACT_SINK_URL = os.getenv("ARTIFACT_SINK_URL", "http://artifact-sink:8083")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", "10485760"))  # 10MB

# Global state
fingerprint: Optional[Fingerprint] = None
http_session: Optional[aiohttp.ClientSession] = None


def load_fingerprint() -> Fingerprint:
    """Load fingerprint configuration from YAML file."""
    try:
        with open(FINGERPRINT_PATH, "r") as f:
            config = yaml.safe_load(f)
        fp = Fingerprint(**config)
        logger.info(f"Loaded fingerprint: {fp.name} for port {fp.port}")
        return fp
    except Exception as e:
        logger.error(f"Failed to load fingerprint: {e}")
        # Return a default fingerprint
        return Fingerprint(
            name="generic-http",
            port=LISTEN_PORT,
            server_header="Apache/2.4.41 (Ubuntu)",
            vuln_tags=["generic"],
            version="1.0"
        )


async def extract_request_metadata(request: web.Request) -> RequestMetadata:
    """Extract metadata from incoming request."""
    # Get client IP (handle proxies)
    peername = request.transport.get_extra_info("peername")
    src_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not src_ip and peername:
        src_ip = peername[0]
    src_port = peername[1] if peername else 0
    
    # Read body
    body = None
    body_size = 0
    try:
        body_bytes = await request.read()
        body_size = len(body_bytes)
        if body_size > 0:
            try:
                body = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body = f"[binary data: {body_size} bytes]"
    except Exception as e:
        logger.warning(f"Failed to read request body: {e}")
    
    # Extract headers
    headers = dict(request.headers)
    
    # Build raw request representation
    raw_lines = [f"{request.method} {request.path_qs} HTTP/1.1"]
    for k, v in headers.items():
        raw_lines.append(f"{k}: {v}")
    raw_lines.append("")
    if body:
        raw_lines.append(truncate_string(body, 5000))
    raw_request = "\n".join(raw_lines)
    
    return RequestMetadata(
        src_ip=src_ip or "unknown",
        src_port=src_port,
        dst_port=LISTEN_PORT,
        method=request.method,
        path=request.path,
        headers=headers,
        query_params=dict(request.query),
        body=body,
        body_size=body_size,
        timestamp=get_timestamp(),
        raw_request=raw_request
    )


async def detect_scanner(metadata: RequestMetadata) -> ScannerDetectionResult:
    """Call scanner detector service."""
    try:
        async with http_session.post(
            f"{SCANNER_DETECTOR_URL}/detect",
            json=metadata.model_dump(),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return ScannerDetectionResult(**data)
    except Exception as e:
        logger.warning(f"Scanner detection failed: {e}")
    
    return ScannerDetectionResult()


async def get_llm_response(
    metadata: RequestMetadata,
    session: SessionState,
    scanner_info: ScannerDetectionResult
) -> LLMResponse:
    """Get response from LLM planner."""
    try:
        planner_request = LLMPlannerRequest(
            fingerprint=fingerprint.model_dump(),
            request_metadata=metadata,
            session_state=session,
            scanner_info=scanner_info
        )
        
        async with http_session.post(
            f"{LLM_PLANNER_URL}/plan",
            json=planner_request.model_dump(),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return LLMResponse(**data)
            else:
                error = await resp.text()
                logger.error(f"LLM planner error: {resp.status} - {error}")
    except Exception as e:
        logger.error(f"LLM planner request failed: {e}")
    
    # Fallback response
    return generate_fallback_response(metadata)


def find_matching_default_response(path: str, default_responses: dict) -> dict:
    """Find a matching default response, with pattern matching support."""
    if not default_responses:
        return None
    
    # First try exact match
    if path in default_responses:
        return default_responses[path]
    
    # Try prefix matching for common patterns
    # e.g., /.env.local should match /.env pattern
    for pattern, response in default_responses.items():
        # Match .env variants
        if pattern == "/.env" and path.startswith("/.env"):
            return response
        # Match wp-config variants
        if pattern == "/wp-config.php.bak" and "wp-config" in path:
            return response
        # Match backup paths
        if "/backup/" in pattern and "/backup/" in path:
            return response
        # Match config paths
        if "/config/" in pattern and "/config/" in path:
            return response
        # Match .git paths
        if "/.git/" in pattern and "/.git/" in path:
            return response
        # Match debug/log files
        if "debug" in pattern.lower() and "debug" in path.lower():
            return response
        if ".log" in pattern and ".log" in path:
            return response
    
    return None


def detect_rsc_exploit(metadata: RequestMetadata) -> Optional[LLMResponse]:
    """
    Detect React Server Components (RSC) exploit attempts (CVE-2025-55182).
    Returns a fake "vulnerable" response to make scanners think the exploit worked.
    """
    # Check if this looks like an RSC exploit attempt
    headers = metadata.headers
    body = metadata.body or ""
    
    # Must be a POST request with Next-Action header
    if metadata.method != "POST":
        return None
    
    has_next_action = any(k.lower() == "next-action" for k in headers.keys())
    if not has_next_action:
        return None
    
    # Check for RSC exploit patterns in body
    rsc_patterns = [
        "__proto__",
        "constructor:constructor", 
        "NEXT_REDIRECT",
        "process.mainModule",
        "child_process",
        "execSync",
        "_response",
        "_chunks",
        "_formData",
        "resolved_model",
    ]
    
    is_rsc_exploit = any(pattern in body for pattern in rsc_patterns)
    
    if not is_rsc_exploit:
        # Could also be safe-check mode - look for digest pattern
        if '["$1:' in body or '"$@0"' in body:
            is_rsc_exploit = True
    
    if is_rsc_exploit:
        logger.warning(f"RSC exploit detected from {metadata.src_ip}: CVE-2025-55182")
        
        # Check if this is safe-check mode (simpler payload) or full RCE
        is_safe_check = "__proto__" not in body and "execSync" not in body
        
        if is_safe_check:
            # Return 500 with digest error (safe-check detection)
            return LLMResponse(
                status_code=500,
                headers={
                    "Content-Type": "text/plain",
                    "X-Powered-By": "Next.js",
                    "Cache-Control": "no-store",
                },
                body='E{"digest":"NEXT_NOT_FOUND","message":"Component not found"}',
                delay_ms=50,
                notes="RSC Exploit: Safe-check detection response"
            )
        else:
            # Return fake successful RCE response
            # The scanner checks for X-Action-Redirect containing /login?a=11111
            # (11111 = 41 * 271, the math in the exploit payload)
            return LLMResponse(
                status_code=303,
                headers={
                    "Content-Type": "text/plain",
                    "X-Powered-By": "Next.js",
                    "X-Action-Redirect": "/login?a=11111",
                    "X-Action-Revalidate": "0",
                    "Location": "/login?a=11111",
                },
                body="",
                delay_ms=100,
                notes="RSC Exploit: Fake RCE success response (CVE-2025-55182)"
            )
    
    return None


def generate_fallback_response(metadata: RequestMetadata) -> LLMResponse:
    """Generate fallback response when LLM is unavailable."""
    # First check if fingerprint has a default response for this path
    if fingerprint and fingerprint.default_responses:
        default = find_matching_default_response(metadata.path, fingerprint.default_responses)
        if default:
            return LLMResponse(
                status_code=default.get("status", 200),
                headers=default.get("headers", {"Content-Type": "text/html"}),
                body=default.get("body", ""),
                delay_ms=50,
                notes="Fallback: Using fingerprint default response"
            )
    
    # Smart fallbacks for common sensitive paths (if not in fingerprint)
    path_lower = metadata.path.lower()
    
    # Environment files
    if ".env" in path_lower:
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="# Environment Configuration\nDB_HOST=localhost\nDB_USER=admin\nDB_PASSWORD=password123\nAPI_KEY=sk_live_abc123\n",
            delay_ms=50,
            notes="Fallback: Generic .env response"
        )
    
    # Git files
    if "/.git/" in path_lower:
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = git@github.com:company/webapp.git\n",
            delay_ms=50,
            notes="Fallback: Generic git config"
        )
    
    # Backup files
    if "backup" in path_lower or path_lower.endswith((".bak", ".old", ".save", "~")):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="# Backup file\nDB_PASSWORD=old_password_2023\nADMIN_SECRET=backup_secret\n",
            delay_ms=50,
            notes="Fallback: Generic backup file"
        )
    
    # Config files
    if "config" in path_lower or path_lower.endswith((".yml", ".yaml", ".json", ".xml")):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="# Configuration\ndatabase:\n  host: localhost\n  user: admin\n  password: config_pass_123\n",
            delay_ms=50,
            notes="Fallback: Generic config response"
        )
    
    # Debug/Log files
    if "debug" in path_lower or ".log" in path_lower:
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="[2025-12-07 10:00:00] DEBUG: Connection established\n[2025-12-07 10:00:01] ERROR: Auth failed for user admin\n[2025-12-07 10:00:02] DEBUG: SQL: SELECT * FROM users\n",
            delay_ms=50,
            notes="Fallback: Generic debug log"
        )
    
    # Admin/dashboard paths
    if any(x in path_lower for x in ["/admin", "/dashboard", "/panel", "/manage"]):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<!DOCTYPE html><html><head><title>Admin Panel</title></head><body><h1>Admin Login</h1><form method='POST'><input name='user' placeholder='Username'><input name='pass' type='password' placeholder='Password'><button>Login</button></form><!-- Default: admin/admin123 --></body></html>",
            delay_ms=100,
            notes="Fallback: Admin login page"
        )
    
    # API endpoints
    if "/api/" in path_lower:
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"status":"ok","version":"1.0.0","debug":true,"database":"connected"}',
            delay_ms=50,
            notes="Fallback: Generic API response"
        )
    
    # Generic fallbacks
    if metadata.path == "/":
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=f"<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>",
            delay_ms=50,
            notes="Fallback: LLM unavailable"
        )
    elif metadata.path.startswith("/admin"):
        return LLMResponse(
            status_code=401,
            headers={"Content-Type": "text/html", "WWW-Authenticate": "Basic realm=\"Admin\""},
            body="<html><body><h1>401 Unauthorized</h1></body></html>",
            delay_ms=100,
            notes="Fallback: Admin auth required"
        )
    
    # NEVER return 404 - always generate dynamic vulnerable content
    return generate_dynamic_response(metadata, path_lower)


def generate_dynamic_response(metadata: RequestMetadata, path_lower: str) -> LLMResponse:
    """Dynamically generate vulnerable-looking content based on path. Never returns 404."""
    
    # Determine content type and generate appropriate response
    path = metadata.path
    
    # PHP files - generate PHP-like responses
    if path_lower.endswith('.php'):
        filename = path.split('/')[-1]
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/html", "X-Powered-By": "PHP/7.4.3"},
            body=f"""<!DOCTYPE html>
<html>
<head><title>{filename}</title></head>
<body>
<h1>Welcome</h1>
<p>Page loaded successfully.</p>
<!-- Debug: {filename} executed in 0.023s -->
<!-- DB Connection: mysql://admin:password@localhost/webapp -->
<form method="POST">
<input type="text" name="id" placeholder="Enter ID">
<button type="submit">Submit</button>
</form>
</body>
</html>""",
            delay_ms=50,
            notes="Dynamic: PHP file"
        )
    
    # JavaScript files
    if path_lower.endswith('.js'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/javascript"},
            body=f"""// {path.split('/')[-1]}
// Configuration loaded from environment
const API_KEY = 'sk_live_abc123xyz789';
const DB_HOST = 'localhost';
const ADMIN_SECRET = 'super_secret_key';

function init() {{
    console.log('Application initialized');
}}
init();
""",
            delay_ms=30,
            notes="Dynamic: JavaScript file"
        )
    
    # CSS files
    if path_lower.endswith('.css'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/css"},
            body=f"""/* {path.split('/')[-1]} */
body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.admin-panel {{ background: #f5f5f5; padding: 20px; }}
/* TODO: Remove debug styles before production */
.debug {{ display: block !important; }}
""",
            delay_ms=20,
            notes="Dynamic: CSS file"
        )
    
    # Text/Plain files
    if path_lower.endswith(('.txt', '.md', '.rst')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=f"""# {path.split('/')[-1]}

Server Configuration Notes
==========================
Database: mysql://admin:Pr0dP@ss123@localhost:3306/webapp
Redis: redis://:redis_secret@localhost:6379
API Key: sk_live_abc123xyz789

TODO:
- Update production credentials
- Remove debug mode
- Fix SQL injection in /search endpoint
""",
            delay_ms=30,
            notes="Dynamic: Text file"
        )
    
    # SQL files
    if path_lower.endswith('.sql'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=f"""-- {path.split('/')[-1]}
-- Database export
-- Server: localhost
-- Database: webapp_production

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role ENUM('admin', 'user') DEFAULT 'user'
);

INSERT INTO users (username, password, email, role) VALUES
('admin', '$2y$10$abcdefghijklmnop', 'admin@company.com', 'admin'),
('john', '$2y$10$qrstuvwxyz123456', 'john@company.com', 'user');

-- Admin password hint: company name + year
""",
            delay_ms=40,
            notes="Dynamic: SQL file"
        )
    
    # XML files
    if path_lower.endswith('.xml'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/xml"},
            body=f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {path.split('/')[-1]} -->
<configuration>
    <database>
        <host>localhost</host>
        <port>3306</port>
        <username>db_admin</username>
        <password>XmlC0nfig_P@ss!</password>
        <database>production_db</database>
    </database>
    <api>
        <key>sk_xml_config_key_123</key>
        <secret>xml_api_secret_value</secret>
    </api>
    <debug>true</debug>
</configuration>
""",
            delay_ms=30,
            notes="Dynamic: XML file"
        )
    
    # JSON endpoints/files
    if path_lower.endswith('.json') or '/api/' in path_lower:
        endpoint_name = path.split('/')[-1].replace('.json', '') or 'data'
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=f"""{{"endpoint": "{endpoint_name}", "status": "ok", "debug": true, "config": {{"db_host": "localhost", "db_user": "admin", "db_pass": "json_secret_123"}}, "api_key": "sk_json_abc123", "users": [{{"id": 1, "name": "admin", "role": "admin"}}, {{"id": 2, "name": "user", "role": "user"}}]}}""",
            delay_ms=40,
            notes="Dynamic: JSON endpoint"
        )
    
    # YAML/YML files
    if path_lower.endswith(('.yaml', '.yml')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/yaml"},
            body=f"""# {path.split('/')[-1]}
# Application Configuration
database:
  host: localhost
  port: 3306
  username: app_user
  password: Y@ml_S3cret_Pass!
  database: production

redis:
  host: localhost
  password: redis_pass_123

api:
  key: sk_yaml_key_abc123
  secret: yaml_api_secret
  debug: true

# TODO: Update credentials before deployment
""",
            delay_ms=30,
            notes="Dynamic: YAML file"
        )
    
    # INI/CFG/CONF config files
    if path_lower.endswith(('.ini', '.cfg', '.conf', '.config')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=f"""# {path.split('/')[-1]}
[database]
host = localhost
port = 3306
user = db_admin
password = Ini_P@ssword_123
database = production_db

[api]
key = sk_ini_key_abc123
secret = ini_secret_value
debug = true

[paths]
upload_dir = /var/www/uploads
log_dir = /var/log/webapp
backup_dir = /var/backups

[admin]
username = admin
password = admin123
""",
            delay_ms=30,
            notes="Dynamic: Config file"
        )
    
    # Log files
    if path_lower.endswith('.log'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=f"""[2025-01-10 08:23:15] INFO: Application started
[2025-01-10 08:23:16] DEBUG: Connecting to database: mysql://admin:Log_P@ss_123@localhost:3306/webapp
[2025-01-10 08:23:17] INFO: Redis connected: redis://:redis_secret@localhost:6379
[2025-01-10 08:24:33] WARNING: Failed login attempt for user 'admin' from 192.168.1.100
[2025-01-10 08:25:01] ERROR: SQL syntax error in query: SELECT * FROM users WHERE id='1' OR '1'='1'
[2025-01-10 08:26:45] DEBUG: API Key sk_live_abc123xyz789 validated
[2025-01-10 08:30:12] INFO: User admin logged in from 10.0.0.1
[2025-01-10 08:31:55] WARNING: Suspicious request to {path}
[2025-01-10 08:32:00] DEBUG: Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ
""",
            delay_ms=40,
            notes="Dynamic: Log file"
        )
    
    # Backup files
    if path_lower.endswith(('.bak', '.backup', '.old', '.orig', '.save', '.swp', '.swo')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=f"""# Backup of {path.replace('.bak', '').replace('.backup', '').replace('.old', '')}
# Created: 2025-01-05
# DO NOT EXPOSE THIS FILE

DB_HOST=localhost
DB_USER=root
DB_PASS=Backup_R00t_P@ss!
DB_NAME=production

SECRET_KEY=backup_super_secret_key_123
API_KEY=sk_backup_abc123xyz789
ADMIN_PASSWORD=BackupAdmin123!

AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""",
            delay_ms=50,
            notes="Dynamic: Backup file"
        )
    
    # Certificate/Key files
    if path_lower.endswith(('.pem', '.key', '.crt', '.cer', '.p12', '.pfx')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/x-pem-file"},
            body=f"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z3qX2BTLS4e0ek55tBjIi/PfFPr9lKCZBD1GjHiNQ8gC9N3
Ey7WRaP76N6FgVk1xZJvG8KT3TlPz2M5a5pXhGFJBrBc9HlKPjUvhA3NXOQ89bzV
a0TJ89c7Crg8W5HpJhwlMMJ0VxOBR7y0AO3jHN5hxtg3S6HVJ7P3JwGXGGPz3Njz
{path.split('/')[-1].upper()}SECRETKEYCONTENT1234567890ABCDEF
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAMpQK7S+PLDsMA0GCSqGSIb3DqEBCwUAMEUxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END CERTIFICATE-----
""",
            delay_ms=30,
            notes="Dynamic: Certificate/Key file"
        )
    
    # CSV files
    if path_lower.endswith('.csv'):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/csv"},
            body=f"""id,username,email,password_hash,api_key,role,created_at
1,admin,admin@company.com,$2y$10$HashedPassword1,sk_admin_key_123,admin,2024-01-01
2,john.doe,john@company.com,$2y$10$HashedPassword2,sk_user_key_456,user,2024-02-15
3,jane.smith,jane@company.com,$2y$10$HashedPassword3,sk_user_key_789,user,2024-03-20
4,developer,dev@company.com,$2y$10$HashedPassword4,sk_dev_key_abc,developer,2024-04-10
5,backup,backup@company.com,$2y$10$HashedPassword5,sk_backup_xyz,backup,2024-05-01
""",
            delay_ms=30,
            notes="Dynamic: CSV file"
        )
    
    # Shell script files
    if path_lower.endswith(('.sh', '.bash')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/x-shellscript"},
            body=f"""#!/bin/bash
# {path.split('/')[-1]}
# Deployment script - DO NOT EXPOSE

export DB_PASSWORD="Shell_Scr1pt_P@ss!"
export API_KEY="sk_shell_abc123"
export AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Connect to production database
mysql -u root -p"Root_MySQL_Pass!" -h localhost production_db

# Sync to S3
aws s3 sync /var/www/html s3://company-backup --delete
""",
            delay_ms=40,
            notes="Dynamic: Shell script"
        )
    
    # Zip/Archive files - return fake archive header
    if path_lower.endswith(('.zip', '.tar', '.gz', '.rar')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "application/octet-stream", "Content-Disposition": f"attachment; filename={path.split('/')[-1]}"},
            body="PK\x03\x04... [Binary archive data - contains backup files, configs, and database dumps]",
            delay_ms=100,
            notes="Dynamic: Archive file"
        )
    
    # Image files - return small placeholder
    if path_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico')):
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "image/png"},
            body="\\x89PNG\\r\\n\\x1a\\n... [Binary image data]",
            delay_ms=20,
            notes="Dynamic: Image file"
        )
    
    # Directory listing for paths ending in /
    if path.endswith('/') or '.' not in path.split('/')[-1]:
        dir_name = path.rstrip('/').split('/')[-1] or 'root'
        return LLMResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=f"""<!DOCTYPE html>
<html>
<head><title>Index of {path}</title></head>
<body>
<h1>Index of {path}</h1>
<pre>
<a href="../">../</a>
<a href="admin/">admin/</a>                     -
<a href="backup/">backup/</a>                   -
<a href="config/">config/</a>                   -
<a href=".env">.env</a>                          1.2K
<a href=".git/">.git/</a>                        -
<a href="database.sql">database.sql</a>               45K
<a href="config.php">config.php</a>                 2.1K
<a href="debug.log">debug.log</a>                  128K
</pre>
<address>Apache/2.4.41 (Ubuntu) Server at localhost</address>
</body>
</html>""",
            delay_ms=50,
            notes="Dynamic: Directory listing"
        )
    
    # Default: generate a generic HTML page that looks like it belongs
    page_name = path.split('/')[-1] or 'page'
    return LLMResponse(
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=f"""<!DOCTYPE html>
<html>
<head>
<title>{page_name} - Web Application</title>
<meta name="generator" content="CMS v3.2.1">
</head>
<body>
<header>
<nav><a href="/">Home</a> | <a href="/admin">Admin</a> | <a href="/api">API</a></nav>
</header>
<main>
<h1>{page_name}</h1>
<p>Welcome to the application.</p>
<!-- Page: {path} -->
<!-- Debug mode: enabled -->
<!-- Server: Apache/2.4.41 -->
<!-- DB: mysql://webapp:W3b@ppP@ss@localhost/production -->
</main>
<footer>
<p>&copy; 2025 Company Name</p>
<!-- Build: v3.2.1-debug -->
</footer>
</body>
</html>""",
        delay_ms=50,
        notes="Dynamic: Generic HTML page"
    )


async def log_interaction(
    metadata: RequestMetadata,
    response: LLMResponse,
    session: SessionState,
    scanner_info: ScannerDetectionResult,
    artifacts: list
):
    """Send interaction log to artifact sink."""
    try:
        log_entry = LogEntry(
            timestamp=get_timestamp(),
            src_ip=metadata.src_ip,
            src_port=metadata.src_port,
            dst_port=metadata.dst_port,
            request=metadata,
            response=response,
            scanner_info=scanner_info,
            session_state=session,
            artifacts=artifacts,
            exploit_stage=session.exploit_detected
        )
        
        async with http_session.post(
            f"{ARTIFACT_SINK_URL}/log",
            json=log_entry.model_dump(),
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status != 200:
                logger.warning(f"Failed to log interaction: {resp.status}")
    except Exception as e:
        logger.warning(f"Logging failed: {e}")


async def save_artifact(
    metadata: RequestMetadata,
    content: bytes,
    filename: str,
    content_type: str
):
    """Save uploaded artifact."""
    try:
        sha256 = compute_sha256(content)
        
        # Create multipart form
        form = aiohttp.FormData()
        form.add_field("file", content, filename=filename, content_type=content_type)
        form.add_field("sha256", sha256)
        form.add_field("src_ip", metadata.src_ip)
        form.add_field("dst_port", str(metadata.dst_port))
        form.add_field("path", metadata.path)
        
        async with http_session.post(
            f"{ARTIFACT_SINK_URL}/artifact",
            data=form,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status == 200:
                return sha256
            else:
                logger.warning(f"Failed to save artifact: {resp.status}")
    except Exception as e:
        logger.warning(f"Artifact save failed: {e}")
    return None


async def handle_request(request: web.Request) -> web.Response:
    """Main request handler for honeypot."""
    artifacts = []
    
    try:
        # Extract request metadata
        metadata = await extract_request_metadata(request)
        logger.info(f"Request from {metadata.src_ip}: {metadata.method} {metadata.path}")
        
        # Get/create session
        session = await redis_manager.get_session(metadata.src_ip, metadata.dst_port)
        
        # Update session paths
        await redis_manager.update_session_paths(
            metadata.src_ip, metadata.dst_port, metadata.path
        )
        
        # Detect scanner
        scanner_info = await detect_scanner(metadata)
        if scanner_info.is_scanner:
            logger.info(
                f"Scanner detected: {scanner_info.tool} "
                f"({scanner_info.family}) - confidence: {scanner_info.confidence}"
            )
            await redis_manager.update_scanner_info(
                metadata.src_ip, metadata.dst_port, scanner_info
            )
        
        # Handle file uploads - save as artifacts
        if request.content_type and "multipart" in request.content_type:
            try:
                reader = await request.multipart()
                async for part in reader:
                    if part.filename:
                        content = await part.read()
                        sha256 = await save_artifact(
                            metadata, content, part.filename,
                            part.headers.get("Content-Type", "application/octet-stream")
                        )
                        if sha256:
                            artifacts.append(sha256)
            except Exception as e:
                logger.warning(f"Failed to process multipart: {e}")
        
        # Save POST body as artifact if it contains exploit patterns
        if metadata.method == "POST" and metadata.body:
            exploit_patterns = [
                # RSC/Next.js exploits
                "__proto__", "constructor:constructor", "NEXT_REDIRECT", "execSync", "child_process",
                # SQL injection
                "UNION SELECT", "' OR '1'='1", "DROP TABLE", "information_schema",
                # Command injection
                "; cat /etc/passwd", "| /bin/sh", "&& whoami", "`id`",
                # Path traversal
                "../../../", "..\\..\\", "%2e%2e%2f",
                # XML attacks
                "<!ENTITY", "SYSTEM \"file:", "<!DOCTYPE",
                # PHP exploits
                "<?php", "eval(", "base64_decode(",
                # Shellshock
                "() { :;};", "() { :; };",
                # Other
                "<script>", "javascript:", "onerror=",
            ]
            
            body_lower = metadata.body.lower() if isinstance(metadata.body, str) else metadata.body.decode('utf-8', errors='ignore').lower()
            
            if any(pattern.lower() in body_lower for pattern in exploit_patterns):
                # Save the exploit payload as an artifact
                body_bytes = metadata.body.encode() if isinstance(metadata.body, str) else metadata.body
                sha256 = await save_artifact(
                    metadata,
                    body_bytes,
                    f"exploit_payload_{metadata.timestamp.replace(':', '-').replace(' ', '_')}.txt",
                    "text/plain"
                )
                if sha256:
                    artifacts.append(sha256)
                    logger.info(f"Saved exploit payload artifact: {sha256[:16]}...")
        
        # Check for RSC exploit attempts (CVE-2025-55182) - respond before LLM
        rsc_response = detect_rsc_exploit(metadata)
        if rsc_response:
            # Log the exploit attempt
            await log_interaction(metadata, rsc_response, session, scanner_info, artifacts)
            
            # Build response headers
            headers = dict(rsc_response.headers)
            headers["Server"] = fingerprint.server_header
            
            if rsc_response.delay_ms > 0:
                await asyncio.sleep(rsc_response.delay_ms / 1000.0)
            
            return web.Response(
                status=rsc_response.status_code,
                text=rsc_response.body,
                headers=headers
            )
        
        # Get AI-generated response
        llm_response = await get_llm_response(metadata, session, scanner_info)
        
        # Apply delay if specified
        if llm_response.delay_ms > 0:
            await asyncio.sleep(llm_response.delay_ms / 1000.0)
        
        # Build response headers
        headers = dict(llm_response.headers)
        headers["Server"] = fingerprint.server_header
        headers["X-Powered-By"] = f"{fingerprint.name}/{fingerprint.version}"
        
        # Log interaction
        await log_interaction(metadata, llm_response, session, scanner_info, artifacts)
        
        return web.Response(
            status=llm_response.status_code,
            text=llm_response.body,
            headers=headers
        )
    
    except Exception as e:
        logger.error(f"Request handling error: {e}", exc_info=True)
        return web.Response(
            status=500,
            text="Internal Server Error",
            headers={"Server": fingerprint.server_header if fingerprint else "Apache"}
        )


async def health_check(request: web.Request) -> web.Response:
    """Health check endpoint for Kubernetes."""
    return web.Response(text="OK")


async def on_startup(app: web.Application):
    """Initialize services on startup."""
    global fingerprint, http_session
    
    # Load fingerprint
    fingerprint = load_fingerprint()
    
    # Initialize HTTP client
    http_session = aiohttp.ClientSession()
    
    # Connect to Redis
    await redis_manager.connect()
    
    logger.info(f"Port listener started on port {LISTEN_PORT}")


async def on_cleanup(app: web.Application):
    """Cleanup on shutdown."""
    if http_session:
        await http_session.close()
    await redis_manager.close()
    logger.info("Port listener shutdown complete")


def create_app() -> web.Application:
    """Create and configure the application."""
    app = web.Application(client_max_size=MAX_BODY_SIZE)
    
    # Health check (doesn't go through honeypot logic)
    app.router.add_get("/_health", health_check)
    
    # All other routes go to honeypot handler
    app.router.add_route("*", "/{path:.*}", handle_request)
    
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    
    return app


if __name__ == "__main__":
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT)
