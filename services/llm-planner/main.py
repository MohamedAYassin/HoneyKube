"""
LLM Response Planner - HoneyKube Honeypot
Generates realistic vulnerable server responses using OpenRouter API.
Supports multiple LLM providers through OpenRouter's unified interface.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any, Optional
from aiohttp import web
import aiohttp

# Add shared module to path
sys.path.insert(0, "/app/shared")

from schemas import (
    LLMPlannerRequest, LLMResponse, RequestMetadata,
    SessionState, ScannerDetectionResult
)
from utils import setup_logging, get_timestamp

logger = setup_logging("llm-planner")

# Configuration from environment variables
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8082"))
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "google/gemini-2.0-flash-001")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "1.0"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))

# HTTP session for API calls
http_session: Optional[aiohttp.ClientSession] = None

# System prompt for LLM
SYSTEM_PROMPT = """You are an AI assistant that generates realistic HTTP responses for a honeypot system.
Your goal is to simulate a vulnerable server to attract and study attackers.

IMPORTANT RULES:
1. NEVER execute any actual commands or code - only simulate responses
2. Generate responses that APPEAR vulnerable but contain no real exploits
3. Include realistic error messages, stack traces, and information leaks
4. Match the fingerprint profile provided (server type, version, OS)
5. Progress naturally through attack stages - reconnaissance → exploitation → post-exploitation
6. Include subtle hints about vulnerabilities based on vuln_tags
7. Maintain session continuity - remember what was already "leaked"
8. Add realistic delays to simulate server processing
9. Output ONLY valid JSON in the exact schema specified

VULNERABILITY SIMULATION GUIDELINES:
- SQL Injection: Show fake database errors with table/column names
- Command Injection: Echo back sanitized versions of commands as if executed
- Path Traversal: Show partial file contents (fake /etc/passwd, config files)
- XSS: Reflect payloads but in a visible, harmless way
- Authentication: Accept weak credentials, show session tokens
- Information Disclosure: Leak version numbers, paths, usernames

RESPONSE BEHAVIOR:
- For scanners: Respond slowly with generic errors initially, then "reveal" vulnerabilities
- For exploit attempts: Show fake "success" messages without real execution
- For post-exploitation: Simulate limited shell access with fake outputs

OUTPUT SCHEMA (strict JSON):
{
    "status_code": <int 100-599>,
    "headers": {"Header-Name": "value", ...},
    "body": "<response body as string>",
    "delay_ms": <int 0-10000>,
    "notes": "<internal diagnostics for logging>"
}

NEVER include actual executable code in responses. Only simulate the appearance of vulnerability."""


def validate_response_json(data: Dict[str, Any]) -> bool:
    """Validate response against expected schema."""
    try:
        required = ["status_code", "headers", "body", "delay_ms", "notes"]
        for field in required:
            if field not in data:
                return False
        
        if not isinstance(data["status_code"], int):
            return False
        if not (100 <= data["status_code"] <= 599):
            return False
        if not isinstance(data["headers"], dict):
            return False
        if not isinstance(data["body"], str):
            return False
        if not isinstance(data["delay_ms"], int):
            return False
        if not (0 <= data["delay_ms"] <= 10000):
            return False
        if not isinstance(data["notes"], str):
            return False
        
        return True
    except Exception:
        return False


def build_prompt(request) -> str:
    """Build the prompt for the LLM."""
    fingerprint = request.fingerprint
    metadata = request.request_metadata
    session = request.session_state
    scanner = request.scanner_info
    
    # Check if there's a default response for this path
    default_response_hint = ""
    if fingerprint.get('default_responses'):
        default = fingerprint['default_responses'].get(metadata.path)
        if default:
            default_response_hint = f"""
## Default Response Template (USE THIS AS BASE)
The fingerprint specifies a default response for this exact path. You MUST use this as the foundation:
- Status: {default.get('status', 200)}
- Headers: {json.dumps(default.get('headers', {}))}
- Body Template:
{default.get('body', '')}

Enhance this response realistically but keep the essential content and structure intact.
"""
    
    prompt = f"""Generate a honeypot HTTP response for the following scenario:

## Server Fingerprint
- Name: {fingerprint.get('name', 'unknown')}
- Server Header: {fingerprint.get('server_header', 'Apache')}
- Version: {fingerprint.get('version', '1.0')}
- OS Hint: {fingerprint.get('os_hint', 'Linux')}
- Vulnerability Tags: {', '.join(fingerprint.get('vuln_tags', []))}
- Behavior Hints: {', '.join(fingerprint.get('behavior_hints', []))}
- Banner: {fingerprint.get('banner', 'N/A')}
{default_response_hint}
## Incoming Request
- Method: {metadata.method}
- Path: {metadata.path}
- Query Params: {json.dumps(metadata.query_params)}
- Headers: {json.dumps(dict(list(metadata.headers.items())[:20]))}
- Body (truncated): {(metadata.body or '')[:2000]}
- Source IP: {metadata.src_ip}

## Session Context
- Request Count: {session.request_count}
- Prior Paths Visited: {', '.join(session.prior_paths[-10:])}
- Fingerprint Leaks Already Shown: {', '.join(session.fingerprint_leaks)}
- Staging Detected: {session.staging_detected}
- Exploit Detected: {session.exploit_detected}

## Scanner Detection
- Is Scanner: {scanner.is_scanner}
- Tool: {scanner.tool}
- Family: {scanner.family}
- Confidence: {scanner.confidence}

## Instructions
Based on the fingerprint and session context, generate a realistic response that:
1. Matches the server profile (headers, error formats, etc.)
2. Progressively reveals vulnerability hints if this is a scanner
3. Simulates vulnerability exploitation if exploit patterns detected
4. Maintains consistency with previously leaked information
5. Uses appropriate timing delays

Return ONLY the JSON response object, no other text."""

    return prompt


async def call_openrouter(prompt: str) -> Optional[Dict[str, Any]]:
    """Call OpenRouter API with retries."""
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/HoneyKube",
        "X-Title": "HoneyKube Honeypot"
    }
    
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "temperature": LLM_TEMPERATURE,
        "max_tokens": LLM_MAX_TOKENS,
        "response_format": {"type": "json_object"}
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            async with http_session.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    
                    # Extract content from OpenRouter response
                    if "choices" in result and len(result["choices"]) > 0:
                        content = result["choices"][0].get("message", {}).get("content", "")
                        
                        if content:
                            # Clean and parse JSON
                            text = content.strip()
                            if text.startswith("```json"):
                                text = text[7:]
                            if text.startswith("```"):
                                text = text[3:]
                            if text.endswith("```"):
                                text = text[:-3]
                            text = text.strip()
                            
                            try:
                                data = json.loads(text)
                                if validate_response_json(data):
                                    return data
                                else:
                                    logger.warning(f"Response validation failed: {text[:500]}")
                            except json.JSONDecodeError as e:
                                logger.warning(f"JSON parse error: {e}, response: {text[:500]}")
                else:
                    error_text = await resp.text()
                    logger.error(f"OpenRouter API error {resp.status}: {error_text[:500]}")
                    
        except asyncio.TimeoutError:
            logger.warning(f"OpenRouter request timeout (attempt {attempt + 1})")
        except Exception as e:
            logger.error(f"OpenRouter API error (attempt {attempt + 1}): {e}")
        
        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(RETRY_DELAY * (attempt + 1))
    
    return None


def find_matching_default_response(path: str, default_responses: dict) -> dict:
    """Find a matching default response with pattern matching support."""
    if not default_responses:
        return None
    
    # First try exact match
    if path in default_responses:
        return default_responses[path]
    
    # Try pattern matching for common sensitive paths
    for pattern, response in default_responses.items():
        # Match .env variants (.env.local, .env.backup, etc.)
        if pattern == "/.env" and path.startswith("/.env"):
            return response
        # Match wp-config variants
        if "wp-config" in pattern and "wp-config" in path:
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


def generate_fallback(request) -> Dict[str, Any]:
    """Generate fallback response when LLM fails."""
    metadata = request.request_metadata
    fingerprint = request.fingerprint
    path_lower = metadata.path.lower()
    
    # Check fingerprint default_responses first (with pattern matching)
    if fingerprint.get('default_responses'):
        default = find_matching_default_response(metadata.path, fingerprint['default_responses'])
        if default:
            return {
                "status_code": default.get("status", 200),
                "headers": default.get("headers", {"Content-Type": "text/html"}),
                "body": default.get("body", ""),
                "delay_ms": 50,
                "notes": "Fallback: Using fingerprint default response"
            }
    
    # Smart fallbacks for common sensitive paths
    
    # Environment files (.env, .env.local, .env.production, etc.)
    if ".env" in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": """# Environment Configuration
APP_ENV=production
APP_DEBUG=true

# Database
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=Pr0d_P@ssw0rd!
DB_NAME=webapp_prod

# API Keys
API_KEY=sk_live_abc123xyz789
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE

# Secrets
JWT_SECRET=super_secret_jwt_key_123
ENCRYPTION_KEY=aes256_encryption_key
""",
            "delay_ms": 50,
            "notes": "Fallback: .env file"
        }
    
    # Git config files
    if "/.git/" in path_lower:
        if "config" in path_lower:
            return {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = git@github.com:company/webapp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[user]
\temail = dev@company.com
""",
                "delay_ms": 50,
                "notes": "Fallback: git config"
            }
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": "ref: refs/heads/main",
            "delay_ms": 50,
            "notes": "Fallback: git file"
        }
    
    # Backup files
    if "backup" in path_lower or path_lower.endswith((".bak", ".old", ".save", ".swp", "~")):
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": """# Backup Configuration (OLD)
DB_PASSWORD=OldP@ssword_2023
ADMIN_SECRET=backup_admin_key
API_SECRET=old_api_key_xyz
""",
            "delay_ms": 50,
            "notes": "Fallback: backup file"
        }
    
    # Config files (yaml, json, xml, ini)
    if "config" in path_lower or path_lower.endswith((".yml", ".yaml", ".json", ".xml", ".ini", ".conf")):
        if path_lower.endswith((".json")):
            return {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": '{"database":{"host":"localhost","user":"admin","password":"config_pass_123"},"api_key":"sk_config_xyz","debug":true}',
                "delay_ms": 50,
                "notes": "Fallback: config json"
            }
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": """# Configuration File
database:
  host: localhost
  port: 3306
  user: db_admin
  password: DbP@ssw0rd_2024!

api:
  key: sk_live_configuration_key
  secret: api_secret_value

redis:
  host: 127.0.0.1
  password: redis_pass_123
""",
            "delay_ms": 50,
            "notes": "Fallback: config file"
        }
    
    # Debug/Log files
    if "debug" in path_lower or ".log" in path_lower or "error" in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": """[2025-12-07 10:00:00] INFO: Application started
[2025-12-07 10:00:01] DEBUG: Database connection: mysql://admin:Pr0d_P@ss@localhost/webapp
[2025-12-07 10:00:02] ERROR: Authentication failed for user 'admin' from 192.168.1.100
[2025-12-07 10:00:03] DEBUG: Session created: sess_abc123xyz
[2025-12-07 10:00:05] WARNING: Deprecated API endpoint called: /api/v1/users
[2025-12-07 10:00:10] ERROR: SQL Error: SELECT * FROM users WHERE id=1 OR 1=1
[2025-12-07 10:00:15] DEBUG: AWS credentials loaded: AKIA...
""",
            "delay_ms": 50,
            "notes": "Fallback: log file"
        }
    
    # SQL dump files
    if ".sql" in path_lower or "dump" in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": """-- Database Dump
-- Server: localhost
-- Database: webapp_prod

CREATE TABLE users (
  id INT PRIMARY KEY,
  email VARCHAR(255),
  password VARCHAR(255),
  role VARCHAR(50)
);

INSERT INTO users VALUES 
(1, 'admin@company.com', '$2y$10$hash...', 'admin'),
(2, 'user@company.com', '$2y$10$hash...', 'user');
""",
            "delay_ms": 50,
            "notes": "Fallback: SQL dump"
        }
    
    # phpinfo / server info
    if "phpinfo" in path_lower or "info.php" in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": """<!DOCTYPE html>
<html><head><title>phpinfo()</title></head>
<body>
<h1>PHP Version 7.4.3</h1>
<table><tr><td>System</td><td>Linux ubuntu 5.4.0-42-generic</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr></table>
<h2>Environment</h2>
<table><tr><td>DB_PASSWORD</td><td>Pr0d_P@ssw0rd!</td></tr>
<tr><td>API_KEY</td><td>sk_live_abc123</td></tr></table>
</body></html>""",
            "delay_ms": 50,
            "notes": "Fallback: phpinfo"
        }
    
    # Admin/Dashboard paths
    if any(x in path_lower for x in ["/admin", "/dashboard", "/panel", "/manage", "/console"]):
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body>
<h1>Administration Panel</h1>
<form method="POST" action="/admin/login">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
<!-- TODO: Remove default credentials - admin/admin123 -->
</body></html>""",
            "delay_ms": 100,
            "notes": "Fallback: admin panel"
        }
    
    # API endpoints
    if "/api/" in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"status":"ok","version":"1.0.0","debug":true,"env":"production"}',
            "delay_ms": 50,
            "notes": "Fallback: API endpoint"
        }
    
    # Basic fallback responses based on path
    if metadata.path == "/" or metadata.path == "":
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": f"""<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>It works!</h1>
<p>Server: {fingerprint.get('server_header', 'Apache')}</p>
</body>
</html>""",
            "delay_ms": 50,
            "notes": "Fallback: index page"
        }
    
    elif "/admin" in metadata.path or "/login" in metadata.path:
        return {
            "status_code": 401,
            "headers": {
                "Content-Type": "text/html",
                "WWW-Authenticate": 'Basic realm="Admin Area"'
            },
            "body": """<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>Authorization Required</h1>
<p>You must authenticate to access this area.</p>
</body>
</html>""",
            "delay_ms": 100,
            "notes": "Fallback: auth required"
        }
    
    elif metadata.method == "POST":
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"status": "received", "processed": true}',
            "delay_ms": 150,
            "notes": "Fallback: POST accepted"
        }
    
    # NEVER return 404 - dynamically generate content for ANY path
    else:
        return generate_dynamic_response(metadata.path, fingerprint)


def generate_dynamic_response(path: str, fingerprint: dict) -> dict:
    """
    Dynamically generate a realistic response for ANY path.
    Never returns 404 - always produces something that looks real and potentially vulnerable.
    """
    import os.path as osp
    import random
    import hashlib
    
    path_lower = path.lower()
    ext = osp.splitext(path)[1].lower()
    path_parts = [p for p in path.split('/') if p]
    server_type = fingerprint.get('server_header', 'Apache/2.4.41')
    
    # Generate consistent "random" values based on path for reproducibility
    path_hash = hashlib.md5(path.encode()).hexdigest()
    
    # Handle by file extension
    if ext in ['.php', '.phtml', '.php5', '.php7']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html", "X-Powered-By": "PHP/7.4.3"},
            "body": f"""<!DOCTYPE html>
<html><head><title>{path_parts[-1] if path_parts else 'index'}</title></head>
<body>
<!-- Debug: {path} -->
<!-- DB_HOST=localhost DB_USER=admin DB_PASS=P@ssw0rd123 -->
<h1>Page Loaded</h1>
<p>Request processed successfully.</p>
<form method="POST"><input name="data"><button>Submit</button></form>
</body></html>""",
            "delay_ms": 80,
            "notes": f"Dynamic: PHP file {path}"
        }
    
    elif ext in ['.js', '.mjs']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/javascript"},
            "body": f"""// {path_parts[-1] if path_parts else 'app'}.js
// API_KEY: sk_live_{path_hash[:16]}
// DEBUG_MODE: true
const config = {{
    apiEndpoint: "/api/v1",
    debug: true,
    adminToken: "admin_{path_hash[:8]}"
}};
console.log("Loaded:", config);
export default config;""",
            "delay_ms": 30,
            "notes": f"Dynamic: JS file {path}"
        }
    
    elif ext in ['.json']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": f'{{"name":"{path_parts[-1].replace(".json","") if path_parts else "config"}","version":"1.0.0","api_key":"key_{path_hash[:12]}","debug":true,"database":{{"host":"localhost","user":"admin","password":"db_pass_{path_hash[:8]}"}}}}',
            "delay_ms": 30,
            "notes": f"Dynamic: JSON file {path}"
        }
    
    elif ext in ['.xml']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/xml"},
            "body": f"""<?xml version="1.0" encoding="UTF-8"?>
<config>
    <database>
        <host>localhost</host>
        <user>admin</user>
        <password>xml_pass_{path_hash[:8]}</password>
    </database>
    <api key="api_{path_hash[:12]}" secret="secret_{path_hash[:16]}"/>
</config>""",
            "delay_ms": 30,
            "notes": f"Dynamic: XML file {path}"
        }
    
    elif ext in ['.yaml', '.yml']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/yaml"},
            "body": f"""# Configuration file
database:
  host: localhost
  user: admin
  password: yaml_pass_{path_hash[:8]}
api:
  key: api_{path_hash[:12]}
  secret: secret_{path_hash[:16]}
debug: true""",
            "delay_ms": 30,
            "notes": f"Dynamic: YAML file {path}"
        }
    
    elif ext in ['.txt', '.log', '.out']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": f"""[2024-01-15 10:23:45] INFO: Server started
[2024-01-15 10:23:46] DEBUG: DB connection: admin:log_pass_{path_hash[:8]}@localhost
[2024-01-15 10:23:47] INFO: API Key loaded: key_{path_hash[:12]}
[2024-01-15 10:24:01] WARN: Debug mode enabled
[2024-01-15 10:25:33] ERROR: Auth failed for user admin from 192.168.1.{int(path_hash[:2], 16) % 255}
[2024-01-15 10:26:12] INFO: Request to {path}""",
            "delay_ms": 30,
            "notes": f"Dynamic: Text/log file {path}"
        }
    
    elif ext in ['.bak', '.backup', '.old', '.orig', '.swp']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/octet-stream"},
            "body": f"""# Backup file - DO NOT EXPOSE
DB_HOST=localhost
DB_USER=root
DB_PASS=backup_pass_{path_hash[:8]}
SECRET_KEY=backup_secret_{path_hash[:16]}
ADMIN_EMAIL=admin@company.com
""",
            "delay_ms": 50,
            "notes": f"Dynamic: Backup file {path}"
        }
    
    elif ext in ['.sql', '.dump']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": f"""-- SQL Dump
-- Database: production_db
-- Generated: 2024-01-15

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(100),
    password VARCHAR(255),
    api_key VARCHAR(64)
);

INSERT INTO users VALUES
(1, 'admin', '$2y$10${path_hash[:22]}', 'key_{path_hash[:16]}'),
(2, 'developer', '$2y$10${path_hash[10:32]}', 'key_{path_hash[8:24]}');
""",
            "delay_ms": 80,
            "notes": f"Dynamic: SQL file {path}"
        }
    
    elif ext in ['.csv']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/csv"},
            "body": f"""id,username,email,password_hash,api_key
1,admin,admin@company.com,{path_hash[:32]},key_{path_hash[:16]}
2,user1,user1@company.com,{path_hash[8:40]},key_{path_hash[4:20]}
3,developer,dev@company.com,{path_hash[16:48]},key_{path_hash[8:24]}""",
            "delay_ms": 30,
            "notes": f"Dynamic: CSV file {path}"
        }
    
    elif ext in ['.ini', '.cfg', '.conf']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": f"""[database]
host = localhost
user = admin
password = ini_pass_{path_hash[:8]}

[api]
key = api_{path_hash[:12]}
secret = secret_{path_hash[:16]}

[debug]
enabled = true
log_level = DEBUG""",
            "delay_ms": 30,
            "notes": f"Dynamic: Config file {path}"
        }
    
    elif ext in ['.zip', '.tar', '.gz', '.rar', '.7z']:
        # Return fake archive header
        return {
            "status_code": 200,
            "headers": {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": f'attachment; filename="{path_parts[-1] if path_parts else "archive.zip"}"'
            },
            "body": "PK\\x03\\x04... [Binary archive data]",
            "delay_ms": 100,
            "notes": f"Dynamic: Archive file {path}"
        }
    
    elif ext in ['.key', '.pem', '.crt', '.cer', '.p12', '.pfx']:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/x-pem-file"},
            "body": f"""-----BEGIN RSA PRIVATE KEY-----
MIIEow{path_hash[:60]}
{path_hash}{path_hash[:28]}
{path_hash[16:]}{path_hash[:12]}
-----END RSA PRIVATE KEY-----""",
            "delay_ms": 30,
            "notes": f"Dynamic: Key/cert file {path}"
        }
    
    # Handle paths that look like API endpoints
    elif '/v1/' in path_lower or '/v2/' in path_lower or '/api/' in path_lower:
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": f'{{"endpoint":"{path}","status":"ok","data":{{"id":"{path_hash[:8]}","token":"tok_{path_hash[:16]}"}},"debug":true}}',
            "delay_ms": 50,
            "notes": f"Dynamic: API endpoint {path}"
        }
    
    # Default: return a generic HTML page that looks real
    else:
        page_name = path_parts[-1] if path_parts else "page"
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html", "Server": server_type},
            "body": f"""<!DOCTYPE html>
<html>
<head><title>{page_name}</title></head>
<body>
<!-- Debug: path={path} hash={path_hash[:8]} -->
<!-- TODO: Remove before production -->
<!-- Admin credentials: admin / admin123 -->
<h1>{page_name}</h1>
<p>Welcome to our site. This page is under construction.</p>
<form method="POST" action="{path}">
    <input type="hidden" name="csrf_token" value="{path_hash[:16]}">
    <input type="text" name="query" placeholder="Search...">
    <button type="submit">Submit</button>
</form>
<script>var API_KEY = "key_{path_hash[:12]}";</script>
</body>
</html>""",
            "delay_ms": 50,
            "notes": f"Dynamic: Generic page {path}"
        }


async def plan_response(request: web.Request) -> web.Response:
    """Main endpoint to plan honeypot responses."""
    try:
        data = await request.json()
        planner_request = LLMPlannerRequest(**data)
        
        logger.info(
            f"Planning response for {planner_request.request_metadata.src_ip}: "
            f"{planner_request.request_metadata.method} {planner_request.request_metadata.path}"
        )
        
        # Build and send prompt to LLM
        prompt = build_prompt(planner_request)
        
        response_data = await call_openrouter(prompt)
        
        if response_data:
            logger.info(f"LLM response generated: {response_data.get('status_code')}")
            return web.json_response(response_data)
        else:
            # Use fallback
            logger.warning("Using fallback response")
            fallback = generate_fallback(planner_request)
            return web.json_response(fallback)
    
    except Exception as e:
        logger.error(f"Planner error: {e}", exc_info=True)
        return web.json_response({
            "status_code": 500,
            "headers": {"Content-Type": "text/plain"},
            "body": "Internal Server Error",
            "delay_ms": 0,
            "notes": f"Error: {str(e)}"
        }, status=200)  # Return 200 to port-listener


async def health_check(request: web.Request) -> web.Response:
    """Health check endpoint."""
    if not OPENROUTER_API_KEY:
        return web.Response(text="NOT READY - No API key", status=503)
    return web.Response(text="OK")


async def model_info(request: web.Request) -> web.Response:
    """Return current model configuration."""
    return web.json_response({
        "model": LLM_MODEL,
        "base_url": OPENROUTER_BASE_URL,
        "temperature": LLM_TEMPERATURE,
        "max_tokens": LLM_MAX_TOKENS,
        "timeout": REQUEST_TIMEOUT
    })


async def on_startup(app: web.Application):
    """Initialize HTTP session on startup."""
    global http_session
    
    if not OPENROUTER_API_KEY:
        logger.error("OPENROUTER_API_KEY not set!")
        raise ValueError("OPENROUTER_API_KEY environment variable required")
    
    # Create HTTP session for API calls
    http_session = aiohttp.ClientSession()
    
    logger.info(f"LLM Planner initialized with model: {LLM_MODEL}")
    logger.info(f"OpenRouter base URL: {OPENROUTER_BASE_URL}")


async def on_cleanup(app: web.Application):
    """Cleanup HTTP session on shutdown."""
    if http_session:
        await http_session.close()
    logger.info("LLM Planner shutdown complete")


def create_app() -> web.Application:
    """Create the application."""
    app = web.Application()
    app.router.add_get("/_health", health_check)
    app.router.add_get("/model", model_info)
    app.router.add_post("/plan", plan_response)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    logger.info(f"LLM Planner starting on port {LISTEN_PORT}")
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT)
