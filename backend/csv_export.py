from __future__ import annotations

import csv
import io
import re


FINDING_COLUMNS = (
    ("IP Address", "ipAddress"),
    ("DNS Name", "dnsName"),
    ("Asset Owner", "assetOwner"),
    ("Vulnerability Name", "vulnerabilityName"),
    ("CVE", "cve"),
    ("Severity", "severity"),
    ("Exploit?", lambda row: "Yes" if row.get("exploitAvailable") else "No"),
    ("Patch Priority", "patchPriority"),
    ("Asset Exposure (on 1000)", "assetExposure"),
    ("Vulnerability Finding", "vulnerabilityFinding"),
    ("Summary", "summary"),
    ("Description", "description"),
    ("Remediation", "remediation"),
    ("KB Links", "kbLinks"),
    ("Platform Details", "platformDetails"),
    ("Namespace", "namespace"),
    ("Deployment", "deployment"),
    ("Image", "image"),
    ("Component", "component"),
    ("Fixable", lambda row: "Yes" if row.get("fixable") else "No"),
    ("CVE Fixed In", "fixedIn"),
    ("CVSS", "cvssScore"),
    ("First Discovered", "firstDiscovered"),
    ("Last Observed", "lastObserved"),
)


def finding_csv(rows: list[dict]):
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    writer.writerow([column[0] for column in FINDING_COLUMNS])
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    for row in rows:
        values = []
        for _, accessor in FINDING_COLUMNS:
            value = accessor(row) if callable(accessor) else row.get(accessor)
            text = "" if value is None else str(value)
            if text.startswith(("=", "+", "-", "@")):
                text = f"'{text}"
            values.append(text)
        writer.writerow(values)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def finding_filename(customer_slug: str, report_period: str) -> str:
    return f"mva-{_safe(customer_slug, 'customer')}-{_safe(report_period, 'current')}-vulnerabilities.csv"


def _safe(value: str, fallback: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", str(value or fallback).lower()).strip("-")[:80]
    return normalized or fallback
