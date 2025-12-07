"""
Scanner Detector Service - HoneyKube Honeypot
Classifies scanning tools and exploit frameworks.
"""

import os
import re
import sys
from aiohttp import web
from typing import Dict, List, Tuple, Optional

# Add shared module to path
sys.path.insert(0, "/app/shared")

from schemas import RequestMetadata, ScannerDetectionResult, ScannerFamily
from utils import setup_logging

logger = setup_logging("scanner-detector")

# Configuration
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8081"))


# Scanner signatures database
SCANNER_SIGNATURES: Dict[str, Dict] = {
    # Web vulnerability scanners
    "wpscan": {
        "family": ScannerFamily.VULN_SCANNER,
        "user_agents": [r"WPScan", r"wpscan", r"WPScan v[\d.]+"],
        "path_patterns": [
            r"/wp-json/wp/v2/users",
            r"/\?author=\d+",
            r"/wp-content/debug\.log",
            r"/wp-config\.php\.bak",
            r"/xmlrpc\.php",
        ],
    },
    "sqlmap": {
        "family": ScannerFamily.VULN_SCANNER,
        "user_agents": [r"sqlmap", r"sqlmap/[\d.]+"],
        "headers": {"X-Sqlmap": r".*"},
        "path_patterns": [
            r".*['\"].*(?:or|and|union|select).*",
            r".*(?:benchmark|sleep|waitfor)\s*\(",
        ],
        "body_patterns": [r"sqlmap", r"--dbs", r"--tables", r"--dump"],
    },
    "nikto": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"nikto", r"Nikto/[\d.]+"],
        "path_patterns": [
            r"/nikto-.*",
            r"/cgi-bin/test-cgi",
            r"/cgi-bin/printenv",
        ],
    },
    "acunetix": {
        "family": ScannerFamily.VULN_SCANNER,
        "user_agents": [r"acunetix", r"wvs", r"Acunetix-.*"],
        "headers": {
            "Acunetix-Product": r".*",
            "Acunetix-Scanning-Agreement": r".*",
        },
        "path_patterns": [r"/acunetix-wvs-test-for-some-.*"],
    },
    "nessus": {
        "family": ScannerFamily.VULN_SCANNER,
        "user_agents": [r"nessus", r"Nessus.*"],
        "path_patterns": [r"/nessus_.*", r"/tenable.*"],
    },
    "burp": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"burp", r"Burp.*"],
        "headers": {"X-Burp-.*": r".*"},
        "body_patterns": [r"burp.*collaborator", r"oastify\.com"],
    },
    "zap": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"zap", r"owasp", r"OWASP.*ZAP"],
        "headers": {"X-ZAP-.*": r".*"},
    },
    
    # Port/Network scanners
    "nmap": {
        "family": ScannerFamily.PORT_SCANNER,
        "user_agents": [r"nmap", r"Nmap.*", r"Nmap Scripting Engine"],
        "path_patterns": [r"/nmaplowercheck\d+", r"/nice%20ports.*"],
    },
    "masscan": {
        "family": ScannerFamily.PORT_SCANNER,
        "user_agents": [r"masscan"],
        "headers": {"User-Agent": r"masscan"},
    },
    
    # Directory/Content discovery
    "dirbuster": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"dirbuster", r"DirBuster.*"],
    },
    "gobuster": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"gobuster"],
    },
    "dirb": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"dirb"],
    },
    "ffuf": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"ffuf", r"Fuzz Faster U Fool"],
    },
    "wfuzz": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"wfuzz", r"Wfuzz.*"],
    },
    "feroxbuster": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"feroxbuster"],
    },
    
    # Exploit frameworks
    "metasploit": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "user_agents": [r"metasploit", r"meterpreter"],
        "body_patterns": [
            r"meterpreter",
            r"msf::",
            r"payload.*meterpreter",
            r"windows/meterpreter",
            r"linux/x64/meterpreter",
        ],
        "path_patterns": [
            r"/msf.*",
            r".*\.php\?.*cmd=",
        ],
    },
    "cobalt_strike": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "user_agents": [r"Mozilla/5\.0.*compatible.*"],
        "body_patterns": [r"beacon", r"cobaltstrike"],
        "path_patterns": [r"/beacon.*", r"/pixel\.gif"],
    },
    
    # Apache-specific exploits
    "apache_path_traversal": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "path_patterns": [
            r"/cgi-bin/\.%2e/",  # CVE-2021-41773
            r"/%2e%2e/",
            r"/\.\.;/",
            r"/icons/\.%2e/",
            r"%%32%65",  # CVE-2021-42013 double encoding
            r"%252e%252e",
        ],
        "body_patterns": [
            r"echo\s+Content-Type:",  # mod_cgi RCE
            r"/bin/sh",
            r"/bin/bash",
        ],
    },
    "shellshock": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "headers": {
            "User-Agent": r"\(\)\s*\{.*\}",  # ShellShock pattern
            "Referer": r"\(\)\s*\{.*\}",
            "Cookie": r"\(\)\s*\{.*\}",
        },
        "body_patterns": [
            r"\(\)\s*\{\s*:\s*;\s*\}",  # () { :; };
        ],
    },
    "struts_rce": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "headers": {
            "Content-Type": r".*ognl\.OgnlContext.*",  # S2-045
        },
        "body_patterns": [
            r"ognl\.OgnlContext",
            r"@ognl\.OgnlContext@",
            r"OgnlUtil",
            r"ProcessBuilder",
            r"getRuntime\(\)\.exec",
        ],
        "path_patterns": [
            r"\.action$",
            r"/struts",
        ],
    },
    
    # WordPress-specific exploits
    "wordpress_xmlrpc": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "path_patterns": [
            r"/xmlrpc\.php",
        ],
        "body_patterns": [
            r"<methodCall>",
            r"<methodName>",
            r"system\.multicall",
            r"pingback\.ping",
            r"wp\.getUsersBlogs",
            r"wp\.getUsers",
        ],
    },
    "wordpress_sqli": {
        "family": ScannerFamily.VULN_SCANNER,
        "path_patterns": [
            r"/wp-content/plugins/.*/.*\?.*(?:id|user|cat)=.*(?:union|select|and|or)",
            r"/wp-admin/admin-ajax\.php\?action=.*(?:union|select)",
        ],
        "body_patterns": [
            r"union\s+select",
            r"extractvalue",
            r"updatexml",
        ],
    },
    
    # Credential attacks
    "hydra": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "user_agents": [r"hydra"],
    },
    "medusa": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "user_agents": [r"medusa"],
    },
    
    # Generic/Custom probes
    "curl": {
        "family": ScannerFamily.CUSTOM_PROBE,
        "user_agents": [r"^curl/"],
    },
    "wget": {
        "family": ScannerFamily.CUSTOM_PROBE,
        "user_agents": [r"^Wget/"],
    },
    "python_requests": {
        "family": ScannerFamily.CUSTOM_PROBE,
        "user_agents": [r"python-requests", r"python-urllib"],
    },
    "httpx": {
        "family": ScannerFamily.WEB_SCANNER,
        "user_agents": [r"httpx"],
    },
    "nuclei": {
        "family": ScannerFamily.VULN_SCANNER,
        "user_agents": [r"nuclei", r"Nuclei.*"],
        "headers": {"X-Nuclei-.*": r".*"},
    },
    
    # React2Shell / Next.js RCE Scanner (CVE-2025-55182 & CVE-2025-66478)
    "react2shell": {
        "family": ScannerFamily.EXPLOIT_FRAMEWORK,
        "user_agents": [r"Assetnote", r"assetnote"],
        "headers": {
            "Next-Action": r".*",
            "X-Nextjs-Request-Id": r".*",
            "X-Nextjs-Html-Request-Id": r".*",
        },
        "body_patterns": [
            r"__proto__",
            r"\$1:__proto__:then",
            r"resolved_model",
            r"_response.*_prefix",
            r"_chunks.*_formData",
            r"NEXT_REDIRECT",
            r"process\.mainModule\.require",
            r"child_process.*execSync",
            r"\$@0",
            r"\$Q2",
            r"\$B1337",
            r"constructor:constructor",
            r"WebKitFormBoundary",
        ],
        "path_patterns": [
            r"^/$",  # Targets root path
        ],
    },
    
    # Generic Next.js/React probes
    "nextjs_scanner": {
        "family": ScannerFamily.VULN_SCANNER,
        "headers": {
            "Next-Action": r".*",
        },
        "body_patterns": [
            r"\[.*\$\d+:.*\]",  # RSC payload format
            r"multipart/form-data.*boundary",
        ],
        "path_patterns": [
            r"/_next/",
            r"/api/.*",
        ],
    },
}


# Exploit pattern categories
EXPLOIT_CATEGORIES = {
    "command_injection": [
        r";\s*(?:cat|id|whoami|uname|pwd|ls|dir|echo|wget|curl|nc|bash|sh|python|perl|ruby|php)",
        r"\|\s*(?:cat|id|whoami|uname|pwd|ls|dir|echo|wget|curl|nc|bash|sh)",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"\$\{[^}]+\}",
        r"(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
    ],
    "sql_injection": [
        r"(?:union\s+(?:all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
        r"(?:'\s*or\s*'|'\s*and\s*'|or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
        r"(?:--|#|/\*|\*/)",
        r"(?:benchmark|sleep|waitfor\s+delay)\s*\(",
        r"(?:extractvalue|updatexml|floor\(rand)",
        r"information_schema",
    ],
    "path_traversal": [
        r"(?:\.\./|\.\.\\){2,}",
        r"(?:/etc/passwd|/etc/shadow|/proc/self|/windows/system32|boot\.ini)",
        r"(?:%2e%2e[/%5c]|%252e%252e)",
    ],
    "xss": [
        r"<script[^>]*>",
        r"javascript\s*:",
        r"on(?:error|load|click|mouseover|focus|blur)=",
        r"<(?:img|svg|iframe)[^>]+(?:on\w+=|src\s*=\s*['\"]?(?:javascript|data):)",
    ],
    "ssrf": [
        r"(?:http|https|ftp|gopher|dict|file)://(?:localhost|127\.|0\.0\.0\.0|169\.254\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)",
        r"@(?:localhost|127\.0\.0\.1)",
        r"(?:metadata\.google|169\.254\.169\.254)",
    ],
    "xxe": [
        r"<!(?:DOCTYPE|ENTITY)[^>]+(?:SYSTEM|PUBLIC)",
        r"<!ENTITY\s+\w+\s+SYSTEM",
        r"file:///",
    ],
    "lfi": [
        r"(?:php://filter|php://input|expect://|data://)",
        r"(?:/var/log/|/var/www/|/tmp/)",
        r"\.(?:log|conf|ini|htaccess|htpasswd)$",
    ],
    "rce": [
        r"(?:eval|assert|create_function|call_user_func|preg_replace.*e)\s*\(",
        r"(?:\{\{|\$\{).*(?:\}\}|\})",  # SSTI patterns
        r"Runtime\.getRuntime\(\)\.exec",
        r"ProcessBuilder",
    ],
    
    # React Server Components / Next.js RCE (CVE-2025-55182 & CVE-2025-66478)
    "nextjs_rce": [
        r"__proto__",
        r"\$\d+:__proto__",
        r"resolved_model",
        r"_response.*_prefix",
        r"process\.mainModule",
        r"child_process",
        r"execSync",
        r"spawnSync",
        r"NEXT_REDIRECT",
        r"constructor:constructor",
        r"\$@\d+",
        r"\$Q\d+",
        r"\$B\d+",
        r"throw\s+Object\.assign",
        r"new\s+Error.*NEXT_REDIRECT",
        r"digest.*NEXT_REDIRECT",
    ],
    
    # Prototype pollution patterns
    "prototype_pollution": [
        r"__proto__",
        r"constructor\s*\[",
        r"prototype\s*\[",
        r"\[\"__proto__\"\]",
        r"\[\"constructor\"\]",
        r"\[\"prototype\"\]",
    ],
}


def match_patterns(text: str, patterns: List[str]) -> Tuple[bool, float]:
    """Check if text matches any pattern and return match confidence."""
    if not text:
        return False, 0.0
    
    matches = 0
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                matches += 1
        except re.error:
            continue
    
    if matches > 0:
        # More matches = higher confidence
        confidence = min(0.5 + (matches * 0.15), 0.95)
        return True, confidence
    return False, 0.0


def detect_scanner_signature(metadata: RequestMetadata) -> Optional[Tuple[str, ScannerFamily, float]]:
    """Detect scanner based on signatures."""
    user_agent = metadata.headers.get("User-Agent", "")
    
    for scanner_name, signatures in SCANNER_SIGNATURES.items():
        confidence_scores = []
        
        # Check User-Agent patterns
        if "user_agents" in signatures:
            for pattern in signatures["user_agents"]:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    confidence_scores.append(0.9)
                    break
        
        # Check header patterns
        if "headers" in signatures:
            for header_name, header_pattern in signatures["headers"].items():
                for req_header, req_value in metadata.headers.items():
                    if re.match(header_name, req_header, re.IGNORECASE):
                        if re.search(header_pattern, req_value, re.IGNORECASE):
                            confidence_scores.append(0.85)
                            break
        
        # Check path patterns
        if "path_patterns" in signatures:
            full_path = metadata.path
            if metadata.query_params:
                full_path += "?" + "&".join(f"{k}={v}" for k, v in metadata.query_params.items())
            
            for pattern in signatures["path_patterns"]:
                if re.search(pattern, full_path, re.IGNORECASE):
                    confidence_scores.append(0.75)
                    break
        
        # Check body patterns
        if "body_patterns" in signatures and metadata.body:
            for pattern in signatures["body_patterns"]:
                if re.search(pattern, metadata.body, re.IGNORECASE):
                    confidence_scores.append(0.8)
                    break
        
        if confidence_scores:
            max_confidence = max(confidence_scores)
            return scanner_name, signatures["family"], max_confidence
    
    return None


def detect_exploit_patterns(metadata: RequestMetadata) -> Tuple[bool, str, float]:
    """Detect exploit patterns in request."""
    # Combine all text to search
    search_text = f"{metadata.path} {metadata.body or ''}"
    for k, v in metadata.query_params.items():
        search_text += f" {k}={v}"
    for k, v in metadata.headers.items():
        search_text += f" {v}"
    
    for category, patterns in EXPLOIT_CATEGORIES.items():
        matched, confidence = match_patterns(search_text, patterns)
        if matched:
            return True, category, confidence
    
    return False, "", 0.0


def analyze_behavioral_patterns(metadata: RequestMetadata) -> Tuple[bool, float]:
    """Analyze behavioral patterns that indicate automated scanning."""
    indicators = []
    
    # Empty or generic User-Agent
    user_agent = metadata.headers.get("User-Agent", "")
    if not user_agent:
        indicators.append(0.6)
    elif user_agent in ["", "-", "Mozilla/5.0"]:
        indicators.append(0.5)
    
    # Missing common headers
    if "Accept" not in metadata.headers:
        indicators.append(0.3)
    if "Accept-Language" not in metadata.headers:
        indicators.append(0.2)
    
    # Suspicious paths
    suspicious_paths = [
        r"^/\.\w+",  # Hidden files
        r"\.(bak|backup|old|orig|save|swp|tmp)$",
        r"^/(?:admin|manager|phpmyadmin|wp-admin|wp-login)",
        r"^/(?:cgi-bin|scripts|bin)/?",
        r"(?:\.git|\.svn|\.env|\.config)/?",
        r"(?:web\.config|\.htaccess|\.htpasswd)",
    ]
    for pattern in suspicious_paths:
        if re.search(pattern, metadata.path, re.IGNORECASE):
            indicators.append(0.5)
            break
    
    # Rapid scanning indicators (many query params or unusual chars)
    if len(metadata.query_params) > 10:
        indicators.append(0.4)
    
    # Method-based indicators
    if metadata.method in ["OPTIONS", "TRACE", "TRACK"]:
        indicators.append(0.5)
    
    if indicators:
        # Combine indicators with diminishing returns
        total = sum(indicators)
        confidence = min(total / (1 + total * 0.3), 0.75)
        return True, confidence
    
    return False, 0.0


async def detect(request: web.Request) -> web.Response:
    """Main detection endpoint."""
    try:
        data = await request.json()
        metadata = RequestMetadata(**data)
        
        # Try signature-based detection first
        sig_result = detect_scanner_signature(metadata)
        if sig_result:
            scanner_name, family, confidence = sig_result
            return web.json_response(
                ScannerDetectionResult(
                    is_scanner=True,
                    tool=scanner_name,
                    family=family,
                    confidence=confidence
                ).model_dump()
            )
        
        # Check for exploit patterns
        is_exploit, exploit_category, exploit_confidence = detect_exploit_patterns(metadata)
        if is_exploit and exploit_confidence > 0.6:
            return web.json_response(
                ScannerDetectionResult(
                    is_scanner=True,
                    tool=f"custom_{exploit_category}",
                    family=ScannerFamily.CUSTOM_PROBE,
                    confidence=exploit_confidence
                ).model_dump()
            )
        
        # Behavioral analysis
        is_suspicious, behavioral_confidence = analyze_behavioral_patterns(metadata)
        if is_suspicious and behavioral_confidence > 0.5:
            return web.json_response(
                ScannerDetectionResult(
                    is_scanner=True,
                    tool="unknown_scanner",
                    family=ScannerFamily.UNKNOWN,
                    confidence=behavioral_confidence
                ).model_dump()
            )
        
        # No scanner detected
        return web.json_response(
            ScannerDetectionResult(
                is_scanner=False,
                tool="none",
                family=ScannerFamily.UNKNOWN,
                confidence=0.0
            ).model_dump()
        )
    
    except Exception as e:
        logger.error(f"Detection error: {e}", exc_info=True)
        return web.json_response(
            ScannerDetectionResult().model_dump(),
            status=200  # Don't fail, return default
        )


async def health_check(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.Response(text="OK")


def create_app() -> web.Application:
    """Create the application."""
    app = web.Application()
    app.router.add_get("/_health", health_check)
    app.router.add_post("/detect", detect)
    return app


if __name__ == "__main__":
    logger.info(f"Scanner detector starting on port {LISTEN_PORT}")
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT)
