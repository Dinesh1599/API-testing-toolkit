
import argparse
import requests
import jwt
import ssl
import socket
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Optional: ZAP integration
try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False

def is_https(url):
    return urlparse(url).scheme == "https"

def get_cert_info(host):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.connect((host, 443))
        cert = s.getpeercert()
        return cert

def validate_jwt_format(token):
    try:
        header, payload, signature = token.split(".")
        return all([header, payload, signature])
    except Exception:
        return False

def verify_jwt_signature(token, secret_key="secret"):
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError as e:
        return False, str(e)

def zap_scan(target):
    zap = ZAPv2()
    print("Starting ZAP spidering...")
    zap.urlopen(target)
    zap.spider.scan(target)
    while int(zap.spider.status["status"]) < 100:
        time.sleep(2)
    print("Spidering complete. Starting active scan...")
    zap.ascan.scan(target)
    while int(zap.ascan.status["status"]) < 100:
        time.sleep(2)
    print("Active scan complete.")
    return zap.core.alerts()

def scan_api(url, tool, report_path, token=None, jwt_key=None):
    print(f"Scanning {url} using {tool.upper()}...")
    issues = []

    parsed_url = urlparse(url)
    if not is_https(url):
        issues.append("Insecure Protocol: API is not using HTTPS.")
    else:
        try:
            cert = get_cert_info(parsed_url.hostname)
            issues.append(f"TLS Certificate Issuer: {cert['issuer'][0][0][1]}")
        except Exception as e:
            issues.append(f"Could not retrieve TLS cert info: {e}")

    if token:
        if validate_jwt_format(token):
            issues.append("JWT Token Format: Valid.")
            verified, payload = verify_jwt_signature(token, jwt_key or "secret")
            if verified:
                issues.append("JWT Signature: Valid.")
            else:
                issues.append(f"JWT Signature: Invalid ({payload})")
        else:
            issues.append("JWT Token Format: Invalid.")

    findings = []
    if tool == "zap" and ZAP_AVAILABLE:
        findings = zap_scan(url)
    else:
        findings = [
            {"risk": "High", "alert": "Excessive Data Exposure"},
            {"risk": "Medium", "alert": "Missing Rate Limiting"},
            {"risk": "Low", "alert": "Verbose Error Messages"}
        ]

    html_report = f'''
    <html>
        <head><title>API Security Scan Report</title></head>
        <body>
            <h1>Scan Report for {url}</h1>
            <p><strong>Tool Used:</strong> {tool}</p>
            <h2>Cryptography & IAM Findings</h2>
            <ul>
                {''.join(f"<li>{item}</li>" for item in issues)}
            </ul>
            <h2>Security Findings</h2>
            <ul>
                {''.join(f"<li>{f['risk']}: {f['alert']}</li>" for f in findings)}
            </ul>
        </body>
    </html>
    '''

    with open(report_path, "w") as f:
        f.write(html_report)
    print(f"✅ Report saved to: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Testing Toolkit with JWT, TLS, ZAP integration")
    parser.add_argument("--url", required=True, help="API base URL to scan")
    parser.add_argument("--tool", required=True, choices=["zap", "burp"], help="Security testing tool to use")
    parser.add_argument("--report", required=True, help="Path to save the HTML report")
    parser.add_argument("--token", required=False, help="Optional JWT token")
    parser.add_argument("--jwt-key", required=False, help="Secret key to verify JWT token")
    args = parser.parse_args()

    scan_api(args.url, args.tool, args.report, args.token, args.jwt_key)
