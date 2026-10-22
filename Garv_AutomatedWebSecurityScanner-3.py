"""
Automated Web Security Scanner
Educational project for checking basic HTTP security headers and CORS behavior.

Use only on websites you own or are explicitly authorized to assess.
This tool sends ordinary HTTP GET requests; it does not exploit vulnerabilities.
"""
import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Restricts which content sources a browser may load.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risk in older browser controls.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Controls access to selected browser features.",
}


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return value


def scan(url: str, timeout: int = 10) -> dict:
    """Check basic response headers for a site you are authorized to test."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        transport_note = "Target URL uses HTTP; HTTPS is recommended for production sites."
    else:
        transport_note = "Target URL uses HTTPS."

    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "Educational-Web-Security-Scanner/1.0"},
    )
    headers = {key.lower(): value for key, value in response.headers.items()}

    findings = []
    for header, explanation in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        findings.append({
            "check": header,
            "status": "PRESENT" if value else "MISSING",
            "value": value or None,
            "meaning": explanation,
            "recommendation": (
                "Review the value and confirm it matches the site's needs."
                if value else f"Consider configuring {header}, after testing compatibility."
            ),
        })

    cors_value = headers.get("access-control-allow-origin")
    findings.append({
        "check": "Access-Control-Allow-Origin (CORS)",
        "status": "PRESENT" if cors_value else "NOT RETURNED",
        "value": cors_value,
        "meaning": "Indicates which origins the server says may access responses through browsers.",
        "recommendation": (
            "Review the allowed origin. A wildcard is not automatically a vulnerability; "
            "consider the resource, credentials, and intended access policy."
            if cors_value else
            "No CORS allow-origin header was returned for this request; this may be expected."
        ),
    })

    return {
        "scanner": "Educational Web Security Scanner",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "transport_note": transport_note,
        "content_type": response.headers.get("Content-Type"),
        "findings": findings,
        "limitations": [
            "A missing header is not proof of an exploitable vulnerability.",
            "Only response headers from this request are checked.",
            "This is a basic educational checker, not a full penetration test.",
        ],
    }


def print_report(report: dict) -> None:
    print("\n=== WEB SECURITY SCAN REPORT ===")
    print(f"Requested URL : {report['requested_url']}")
    print(f"Final URL     : {report['final_url']}")
    print(f"HTTP status   : {report['http_status']}")
    print(f"Transport     : {report['transport_note']}")
    print("\nChecks:")
    for item in report["findings"]:
        print(f"- [{item['status']}] {item['check']}")
        if item["value"]:
            print(f"    Value: {item['value']}")
        print(f"    Note : {item['recommendation']}")
    print("\nNote: Findings require manual review; this tool does not prove exploitability.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check basic HTTP security headers on an authorized website."
    )
    parser.add_argument("url", help="Website URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--output", default="scan_report.json", help="JSON report output path")
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
        report = scan(url, timeout=max(1, min(args.timeout, 60)))
        print_report(report)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.output}")
    except (ValueError, requests.RequestException) as exc:
        raise SystemExit(f"Scan failed: {exc}")


if __name__ == "__main__":
    main()
