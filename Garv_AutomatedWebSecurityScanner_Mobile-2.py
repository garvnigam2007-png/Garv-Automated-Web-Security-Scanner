"""
Garv's Automated Web Security Scanner - Android/Pydroid 3 version
Educational header checker. Scan only websites you own or have permission to test.
"""
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Restricts which content sources a browser may load.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risk.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Controls access to selected browser features.",
}

def normalize_url(value):
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Please enter a valid http:// or https:// URL.")
    return value

def scan(url):
    response = requests.get(
        url,
        timeout=15,
        allow_redirects=True,
        headers={"User-Agent": "Garv-Educational-Web-Security-Scanner/1.0"},
    )
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings = []

    for header, meaning in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        findings.append({
            "check": header,
            "status": "PRESENT" if value else "MISSING",
            "value": value,
            "meaning": meaning,
            "recommendation": (
                "Review whether the configured value is appropriate."
                if value else f"Consider configuring {header}, after compatibility testing."
            ),
        })

    cors = headers.get("access-control-allow-origin")
    findings.append({
        "check": "Access-Control-Allow-Origin (CORS)",
        "status": "PRESENT" if cors else "NOT RETURNED",
        "value": cors,
        "meaning": "Shows the origin policy returned in this response.",
        "recommendation": (
            "Review the allowed origin in context; wildcard is not automatically a vulnerability."
            if cors else "No CORS allow-origin header was returned; this may be expected."
        ),
    })

    return {
        "scanner": "Garv's Automated Web Security Scanner",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "transport_note": "HTTPS used." if url.startswith("https://") else "HTTP used; HTTPS is recommended.",
        "findings": findings,
        "limitations": [
            "Missing headers do not prove an exploitable vulnerability.",
            "Only response headers from this request are checked.",
            "This is a basic educational checker, not a full penetration test.",
        ],
    }

def main():
    print("=" * 42)
    print(" GARV - AUTOMATED WEB SECURITY SCANNER")
    print("=" * 42)
    print("Use only on a website you own or are authorized to test.")
    url_input = input("Enter website URL (example: https://example.com): ")

    try:
        url = normalize_url(url_input)
        report = scan(url)
        print("\nSCAN RESULTS")
        print("-" * 42)
        print("Final URL:", report["final_url"])
        print("HTTP Status:", report["http_status"])
        print("\nSecurity checks:")
        for item in report["findings"]:
            print(f"[{item['status']}] {item['check']}")
            if item["value"]:
                print("  Value:", item["value"])
            print("  Note:", item["recommendation"])

        output_file = "Garv_scan_report.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print("\nJSON report saved as:", output_file)
        print("Note: Results are preliminary; review them manually.")
    except ValueError as error:
        print("Input error:", error)
    except requests.RequestException as error:
        print("Network/scan error:", error)
        print("Check internet, URL, and try again.")

if __name__ == "__main__":
    main()
