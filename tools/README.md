# HoneyKube Exploit Scanners

These are real-world exploit scanners for testing HoneyKube honeypots. They simulate actual attack tools and techniques to generate realistic malicious traffic for analysis.

## Prerequisites

```bash
pip install requests tqdm
```

Or with `uv`:
```bash
uv run <scanner>.py -u <target>
```

## Available Scanners

### 1. React2Shell Scanner (CVE-2025-55182)

Next.js React Server Components RCE scanner based on Assetnote research.

```bash
# Basic scan
python react2shell_scanner.py -u http://localhost:3000

# Safe check (side-channel detection only)
python react2shell_scanner.py -u http://localhost:3000 --safe-check

# With WAF bypass
python react2shell_scanner.py -u http://localhost:3000 --waf-bypass

# Windows target
python react2shell_scanner.py -u http://localhost:3000 --windows

# Save output
python react2shell_scanner.py -u http://localhost:3000 -o results.json -v
```

**Exploits tested:**
- CVE-2025-55182: React Server Components deserialization RCE
- CVE-2025-66478: Prototype pollution via RSC payloads
- Vercel/Netlify WAF bypass techniques

### 2. WordPress Scanner

Comprehensive WordPress vulnerability scanner.

```bash
# Basic scan
python wordpress_scanner.py -u http://localhost:8000

# Verbose output
python wordpress_scanner.py -u http://localhost:8000 -v

# Save results
python wordpress_scanner.py -u http://localhost:8000 -o wp_results.json
```

**Exploits tested:**
- XML-RPC Pingback DDoS (CVE-2013-0235)
- XML-RPC Brute Force (system.multicall amplification)
- User Enumeration (/?author=N, REST API)
- wp-config.php backup exposure
- Debug.log exposure
- SQL Injection in plugins
- Path Traversal attacks
- wp-login.php brute force

### 3. Apache Scanner

Apache server vulnerability scanner with RCE exploits.

```bash
# Basic scan
python apache_scanner.py -u http://localhost:80

# Verbose output
python apache_scanner.py -u http://localhost:80 -v

# Save results
python apache_scanner.py -u http://localhost:80 -o apache_results.json
```

**Exploits tested:**
- CVE-2021-41773: Path traversal (Apache 2.4.49)
- CVE-2021-42013: Path traversal bypass (Apache 2.4.50)
- mod_cgi RCE via path traversal
- ShellShock (CVE-2014-6271)
- Apache Struts RCE (S2-045, S2-046)
- server-status/server-info exposure
- .htaccess/.htpasswd exposure
- HTTP TRACE (XST)
- mod_proxy SSRF
- ETag inode disclosure

## Testing Against HoneyKube

1. Start HoneyKube locally:
```bash
docker-compose up -d
```

2. Run scanners against honeypots:
```bash
# Test Next.js honeypot
python tools/react2shell_scanner.py -u http://localhost:3000 -v

# Test WordPress honeypot  
python tools/wordpress_scanner.py -u http://localhost:8000 -v

# Test Apache honeypot
python tools/apache_scanner.py -u http://localhost:80 -v
```

3. Check artifacts in the sink:
```bash
curl http://localhost:8083/stats
docker exec honeykube-artifact-sink ls -la /logs/
docker exec honeykube-artifact-sink cat /logs/honeypot-*.json | jq .
```

## Output Format

All scanners output JSON results with:

```json
{
  "target": "http://example.com",
  "timestamp": "2025-12-07T15:00:00Z",
  "vulnerabilities": [
    {
      "name": "Vulnerability Name",
      "severity": "HIGH|MEDIUM|LOW|CRITICAL",
      "details": "Description of the finding",
      "payload": "The actual exploit payload used"
    }
  ],
  "errors": []
}
```

## Adding Custom Scanners

Create a new Python file following the pattern:

```python
#!/usr/bin/env python3
"""
Custom Scanner - Description
"""

import requests
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    args = parser.parse_args()
    
    # Your exploit logic here
    resp = requests.get(f"{args.url}/vulnerable-endpoint", 
                       headers={"X-Evil": "payload"})
    
    if "success_indicator" in resp.text:
        print("[VULNERABLE]")
    else:
        print("[NOT VULNERABLE]")

if __name__ == "__main__":
    main()
```

## Disclaimer

These tools are for authorized security testing only. Only use against systems you own or have explicit permission to test.
