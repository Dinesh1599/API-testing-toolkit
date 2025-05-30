
# 🔐 API Security Testing Toolkit

This is a Python-based command-line toolkit designed to assess the security of REST APIs. It performs checks for cryptographic standards (TLS), JWT token validation, and optional dynamic scanning using OWASP ZAP. It generates an HTML report summarizing the findings.

---

## 🚀 Features

- 🔒 HTTPS/TLS validation (certificate issuer, protocol check)
- 🛂 JWT format & signature verification (HS256 supported)
- 🧪 Mock vulnerability testing (based on OWASP Top 10)
- ⚡ Optional integration with OWASP ZAP for real active scans
- 📄 Generates clean HTML reports with categorized findings

---

## 📦 Requirements

Install Python packages from `requirements.txt`:

```bash
pip install -r requirements.txt
```

Dependencies:
- `requests`
- `pyjwt`
- `beautifulsoup4`
- `python-owasp-zap-v2.4` *(optional, only for ZAP scanning)*

---

## 🧪 Usage

```bash
python scan.py [OPTIONS]
```

### ✅ Available Options

| Option         | Required | Description |
|----------------|----------|-------------|
| `--url`        | ✅ Yes   | The base URL of the API you want to scan |
| `--tool`       | ✅ Yes   | Choose `zap` (real scan) or `burp` (mock scan) |
| `--report`     | ✅ Yes   | File name/path to save the HTML scan report |
| `--token`      | ❌ No    | JWT token to validate (format + signature) |
| `--jwt-key`    | ❌ No    | Secret key used to verify the JWT signature |

---

### 🔹 Example 1: Basic Scan with Mock Findings

```bash
python scan.py --url https://jsonplaceholder.typicode.com --tool burp --report scan_result.html
```

### 🔹 Example 2: Scan with JWT Token

```bash
python scan.py --url https://jsonplaceholder.typicode.com \
  --tool burp \
  --report scan_result.html \
  --token YOUR.JWT.TOKEN \
  --jwt-key yourSecretKey
```

### 🔹 Example 3: Real Active Scan with OWASP ZAP

```bash
python scan.py --url https://yourapi.com --tool zap --report result.html
```

> 📝 Ensure ZAP is running (localhost:8080) before using `--tool zap`.

---

## 📂 Output

- An HTML file like `scan_result.html` with:
  - TLS info
  - JWT validation results
  - List of mock or actual vulnerabilities
  - Recommendations section

---

## 🔧 Future Improvements

- ✅ Add Swagger/OpenAPI spec parsing for endpoint auto-discovery
- ✅ Support JWT `RS256` with public key validation
- ✅ Add Bandit or other tools for Static Application Security Testing (SAST)
- ✅ Export scan results to PDF/CSV
- ✅ Dockerize the project with ZAP pre-configured
- ✅ Add a web UI version of this toolkit

---

## 🛡️ License

MIT License

---

## 👨‍💻 Maintainer

Built by [Dinesh Udayan](https://github.com/Dinesh1599) — Master's in Cyber Forensics & Security
