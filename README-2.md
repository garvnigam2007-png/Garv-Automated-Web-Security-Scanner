# Automated Web Security Scanner

## Overview
A beginner-friendly Python project that checks basic HTTP security headers and the `Access-Control-Allow-Origin` response header for a website you own or are authorized to assess. It prints a readable summary and saves a JSON report.

## Features
- Adds `https://` when no scheme is provided.
- Checks six common browser security headers.
- Observes the CORS allow-origin header returned for one GET request.
- Saves results to `scan_report.json`.
- Handles common URL and network errors.

## Technology
- Python 3.9+
- `requests`

## Setup
1. Install Python 3.9 or newer.
2. Open a terminal in this folder.
3. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

## Run
```bash
python Garv_AutomatedWebSecurityScanner.py https://example.com
```

Optional arguments:
```bash
python Garv_AutomatedWebSecurityScanner.py https://example.com --timeout 15 --output my_report.json
```

## Output
The terminal displays the status of each check. A JSON file stores the URL, response status, findings, recommendations, and limitations.

## Dataset
This project does not require a dataset. It checks live response headers. For a reproducible demonstration, use a local test site or a domain you control and save the JSON output.

## Important limitations
- Missing headers do not automatically mean a site is vulnerable.
- CORS behavior depends on request origin, credentials, and browser enforcement; this project does not test every case.
- This is not a full vulnerability scanner or penetration test.
- Only test websites you own or have explicit permission to assess.
