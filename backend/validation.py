from __future__ import annotations

import json
import math
import re
import unicodedata
from datetime import date

from .errors import MVAError

WORKFLOWS = {"adhoc", "monthly", "quarterly", "quarterly-scan"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}
PRIORITIES = {"P1", "P2", "P3", "P4"}
ROLES = {"owner", "analyst", "viewer"}
ASSET_TYPES = (
    "Network Device",
    "Linux Server",
    "Windows Server",
    "Endpoint",
    "Database",
    "Cloud Asset",
    "Security Appliance",
    "Virtualization Host",
    "Container Platform",
    "OT Device",
    "Other",
)
UUID_PATTERN = re.compile(r"^[0-9a-f-]{36}$", re.I)


def clean_text(value: object, maximum: int) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()[:maximum]


def normalize_create_payload(payload: dict | None, customer_name: str) -> dict:
    payload = payload or {}
    workflow = clean_text(payload.get("workflow"), 40).lower()
    ingestion_key = clean_text(payload.get("ingestionKey"), 128)
    expected_findings = positive_integer(payload.get("expectedFindings"))
    expected_chunks = positive_integer(payload.get("expectedChunks"))
    if workflow not in WORKFLOWS:
        raise MVAError("Unsupported workflow.")
    if not ingestion_key or not re.fullmatch(r"[a-zA-Z0-9:_-]+", ingestion_key):
        raise MVAError("A valid ingestion key is required.")
    if not expected_findings or not expected_chunks:
        raise MVAError("Expected findings and chunks must be positive integers.")
    return {
        "customerName": clean_text(customer_name, 180) or "Local Organization",
        "ingestionKey": ingestion_key,
        "workflow": workflow,
        "sourceTool": clean_text(payload.get("sourceTool"), 80) or "unknown",
        "sourceLabel": clean_text(payload.get("sourceLabel"), 180) or "Unknown source",
        "reportPeriod": clean_text(payload.get("reportPeriod"), 120) or "Unspecified period",
        "fileNames": clean_string_array(payload.get("fileNames"), 120, 500),
        "sourceIds": clean_string_array(payload.get("sourceIds"), 20, 80),
        "expectedFindings": expected_findings,
        "expectedChunks": expected_chunks,
        "dashboard": plain_object(payload.get("dashboard")),
        "inputSummary": plain_object(payload.get("inputSummary")),
    }


def normalize_chunk_payload(payload: dict | None, expected_findings: int) -> dict:
    payload = payload or {}
    chunk_index = non_negative_integer(payload.get("chunkIndex"))
    start_index = non_negative_integer(payload.get("startIndex"))
    findings = payload.get("findings")
    if chunk_index is None or start_index is None:
        raise MVAError("Chunk index and start index must be non-negative integers.")
    if not isinstance(findings, list) or not 1 <= len(findings) <= 1000:
        raise MVAError("Each chunk must contain between 1 and 1,000 findings.")
    if start_index + len(findings) > expected_findings:
        raise MVAError("Chunk exceeds the declared finding count.")
    return {
        "chunkIndex": chunk_index,
        "startIndex": start_index,
        "findings": [normalize_finding(finding, start_index + offset) for offset, finding in enumerate(findings)],
    }


def normalize_finding(finding: dict | None, row_index: int) -> dict:
    finding = finding if isinstance(finding, dict) else {}
    severity = finding.get("severity") if finding.get("severity") in SEVERITIES else "Unknown"
    priority = finding.get("patchPriority") if finding.get("patchPriority") in PRIORITIES else "P4"
    source_tool = clean_text(finding.get("sourceTool"), 80) or "unknown"
    source_tools = clean_string_array(finding.get("sourceTools"), 20, 80) or [source_tool]
    fallback = "|".join(
        clean_text(finding.get(key), 500).lower()
        for key in ("ipAddress", "dnsName", "cve", "vulnerabilityName", "protocol", "port")
    )
    report_period = clean_text(finding.get("reportPeriod"), 120) or "Unspecified period"
    return {
        "rowIndex": row_index,
        "reportPeriod": report_period,
        "reportPeriodDate": report_period_date(report_period),
        "findingKey": clean_text(finding.get("findingKey"), 1000) or fallback or f"row-{row_index}",
        "sourceTool": source_tool,
        "sourceTools": source_tools,
        "sourceDisplay": clean_text(finding.get("sourceDisplay"), 500),
        "sourceVulnerabilityId": clean_text(finding.get("sourceVulnerabilityId"), 500),
        "ipAddress": clean_text(finding.get("ipAddress"), 500),
        "dnsName": clean_text(finding.get("dnsName"), 1000),
        "vulnerabilityName": clean_text(finding.get("vulnerabilityName"), 4000),
        "cve": clean_text(finding.get("cve"), 2000),
        "severity": severity,
        "exploitAvailable": bool(finding.get("exploitAvailable")),
        "exploitSignal": clean_text(finding.get("exploitSignal"), 4000),
        "epssScore": probability(finding.get("epssScore")),
        "patchPriority": priority,
        "assetExposure": bounded_integer(finding.get("assetExposure"), 0, 1000, 0),
        "vulnerabilityFinding": clean_text(finding.get("vulnerabilityFinding"), 100_000),
        "summary": clean_text(finding.get("summary"), 20_000),
        "description": clean_text(finding.get("description"), 200_000),
        "remediation": clean_text(finding.get("remediation"), 200_000),
        "kbLinks": clean_text(finding.get("kbLinks"), 20_000),
        "platformDetails": clean_text(finding.get("platformDetails"), 20_000),
        "firstDiscovered": iso_date(finding.get("firstDiscovered")),
        "lastObserved": iso_date(finding.get("lastObserved")),
        "vulnerabilityAgeDays": nullable_non_negative_integer(finding.get("vulnerabilityAgeDays")),
        "protocol": clean_text(finding.get("protocol"), 100),
        "port": clean_text(finding.get("port"), 100),
        "recordCount": positive_integer(finding.get("recordCount")) or 1,
        "datacentre": clean_text(finding.get("datacentre"), 1000),
        "timesDetected": positive_integer(finding.get("timesDetected")) or 1,
        "vendorSeverityLabel": clean_text(finding.get("vendorSeverityLabel"), 1000),
        "vulnerabilityStatus": clean_text(finding.get("status") or finding.get("vulnerabilityStatus"), 1000),
        "vulnerabilityConfidence": clean_text(finding.get("vulnerabilityConfidence"), 1000),
        "exploitEvidenceSource": clean_text(finding.get("exploitEvidenceSource"), 1000),
        "threat": clean_text(finding.get("threat"), 20_000),
        "impact": clean_text(finding.get("impact"), 20_000),
        "product": clean_text(finding.get("product"), 4000),
        "assetCriticality": clean_text(finding.get("assetCriticality"), 1000),
        "internetExposed": bool(finding.get("internetExposed")),
        "internetExposureKnown": bool(finding.get("internetExposureKnown")),
        "cisaKev": bool(finding.get("cisaKev")),
        "namespace": clean_text(finding.get("namespace"), 1000),
        "deployment": clean_text(finding.get("deployment"), 1000),
        "image": clean_text(finding.get("image"), 4000),
        "component": clean_text(finding.get("component"), 4000),
        "fixable": bool(finding.get("fixable")),
        "fixableSignal": clean_text(finding.get("fixableSignal"), 1000),
        "fixedIn": clean_text(finding.get("fixedIn"), 4000),
        "cvssScore": nullable_bounded_number(finding.get("cvssScore"), 0, 10),
        "payload": json_safe(finding),
    }


def normalize_customer(payload: dict | None) -> dict:
    payload = payload or {}
    name = clean_text(payload.get("name"), 180)
    requested = clean_text(payload.get("slug"), 120).lower()
    slug = slugify(requested or name)[:80]
    if len(name) < 2:
        raise MVAError("Customer name must contain at least two characters.")
    if not slug:
        raise MVAError("A valid customer identifier is required.")
    return {
        "name": name,
        "slug": slug,
        "assetScopeMode": "inventory" if payload.get("assetScopeMode") == "inventory" else "observed",
        "status": "inactive" if payload.get("status") == "inactive" else "active",
        "notes": clean_text(payload.get("notes"), 4000),
    }


def normalize_team(payload: dict | None) -> dict:
    payload = payload or {}
    name = clean_text(payload.get("name"), 180)
    code = slugify(clean_text(payload.get("code"), 80) or name)[:60]
    if len(name) < 2:
        raise MVAError("Team name must contain at least two characters.")
    if not code:
        raise MVAError("A valid team code is required.")
    return {"name": name, "code": code, "description": clean_text(payload.get("description"), 2000)}


def normalize_asset_payloads(payload: dict | None) -> list[dict]:
    payload = payload or {}
    rows = payload.get("assets")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10_000:
        raise MVAError("Upload between 1 and 10,000 assets per request.")
    normalized: dict[str, dict] = {}
    for index, source in enumerate(rows):
        source = source if isinstance(source, dict) else {}
        ip_address = clean_text(source.get("ipAddress"), 500)
        dns_name = clean_text(source.get("dnsName"), 1000).lower()
        host_name = clean_text(source.get("hostName"), 1000).lower()
        external_id = clean_text(source.get("externalId"), 500)
        asset_key = clean_text(source.get("assetKey"), 1000).lower() or next(
            (value.lower() for value in (ip_address, dns_name, host_name, external_id) if value),
            "",
        )
        if not asset_key:
            raise MVAError(f"Asset row {index + 1} has no IP address, DNS name, host name, or external ID.")
        team_id = clean_text(source.get("teamId"), 36)
        normalized[asset_key] = {
            "assetKey": asset_key,
            "ipAddress": ip_address,
            "dnsName": dns_name,
            "hostName": host_name,
            "externalId": external_id,
            "assetType": normalize_asset_type(source.get("assetType"), source.get("platform")),
            "onboardingTool": normalize_onboarding_tool(source.get("onboardingTool")),
            "teamId": team_id if UUID_PATTERN.fullmatch(team_id) else None,
            "platform": clean_text(source.get("platform"), 2000),
            "businessUnit": clean_text(source.get("businessUnit"), 1000),
            "criticality": clean_text(source.get("criticality"), 1000),
            "internetExposed": nullable_boolean(source.get("internetExposed")),
            "inScope": True,
        }
    owners: dict[str, str] = {}
    for asset in normalized.values():
        aliases = {
            str(value).lower()
            for value in (asset["assetKey"], asset["ipAddress"], asset["dnsName"], asset["hostName"], asset["externalId"])
            if value
        }
        for alias in aliases:
            if alias in owners and owners[alias] != asset["assetKey"]:
                raise MVAError(f"Asset identity '{alias}' is assigned to more than one inventory record.")
            owners[alias] = asset["assetKey"]
    return list(normalized.values())


def normalize_onboarding_tool(value: object) -> str:
    normalized = re.sub(r"\s+", " ", re.sub(r"[._-]+", " ", clean_text(value, 120).lower())).strip()
    aliases = {
        "": "manual",
        "manual": "manual",
        "manual inventory": "manual",
        "tenable sc": "tenable-sc",
        "tenable security center": "tenable-sc",
        "tenable io": "tenable-io",
        "tenable vulnerability management": "tenable-io",
        "qualys": "qualys",
        "qualys vmdr": "qualys",
        "crowdstrike": "crowdstrike",
        "crowdstrike exposure management": "crowdstrike",
        "openshift": "openshift",
        "red hat openshift": "openshift",
        "openshift container platform": "openshift",
        "mdvm": "mdvm",
        "microsoft defender vm": "mdvm",
        "microsoft defender vulnerability management": "mdvm",
        "multi tool": "multi-tool",
        "multiple tools": "multi-tool",
        "other": "other",
        "other tool": "other",
    }
    if normalized not in aliases:
        raise MVAError("Select a valid onboarding tool.")
    return aliases[normalized]


def normalize_asset_ids(payload: dict | None) -> list[str]:
    values = (payload or {}).get("assetIds")
    ids = list(dict.fromkeys(clean_text(value, 36) for value in values)) if isinstance(values, list) else []
    if not 1 <= len(ids) <= 10_000:
        raise MVAError("Select between 1 and 10,000 assets.")
    if any(not UUID_PATTERN.fullmatch(value) for value in ids):
        raise MVAError("One or more selected assets are invalid.")
    return ids


def normalize_threat_import(payload: dict | None) -> dict:
    payload = payload or {}
    key = clean_text(payload.get("ingestionKey"), 128)
    count = positive_integer(payload.get("expectedRecords"))
    if not key or not re.fullmatch(r"[a-zA-Z0-9:_-]+", key):
        raise MVAError("A valid threat-intelligence ingestion key is required.")
    if not count or count > 200_000:
        raise MVAError("Threat-intelligence imports must contain between 1 and 200,000 records.")
    return {
        "ingestionKey": key,
        "sourceLabel": clean_text(payload.get("sourceLabel"), 180) or "Uploaded scanner data",
        "fileNames": clean_string_array(payload.get("fileNames"), 100, 500),
        "expectedRecords": count,
    }


def normalize_threat_chunk(payload: dict | None, expected_records: int) -> dict:
    payload = payload or {}
    start = non_negative_integer(payload.get("startIndex"))
    records = payload.get("records")
    if start is None:
        raise MVAError("Threat-intelligence chunk start index must be a non-negative integer.")
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise MVAError("Each threat-intelligence chunk must contain between 1 and 1,000 records.")
    if start + len(records) > expected_records:
        raise MVAError("Threat-intelligence chunk exceeds the declared record count.")
    return {
        "startIndex": start,
        "records": [normalize_threat_record(record, start + offset) for offset, record in enumerate(records)],
    }


def normalize_threat_query(value: object) -> str:
    query = clean_text(value, 500)
    if len(query) < 2:
        raise MVAError("Enter at least two characters to search threat intelligence.")
    return query


def normalize_ai_remediation(payload: dict | None) -> dict:
    payload = payload or {}
    prompt = clean_text(payload.get("prompt"), 2_000_000)
    if len(prompt) < 20:
        raise MVAError("Generate a normalized remediation prompt before requesting local AI.")
    return {
        "prompt": prompt,
        "targetPeriod": clean_text(payload.get("targetPeriod"), 120) or "Current period",
        "sourceLabel": clean_text(payload.get("sourceLabel"), 180) or "Uploaded scanner data",
    }


def normalize_memberships(value: object) -> list[dict]:
    rows = value if isinstance(value, list) else []
    memberships: dict[str, dict] = {}
    for row in rows:
        row = row if isinstance(row, dict) else {}
        customer_id = clean_text(row.get("customerId"), 36)
        if not UUID_PATTERN.fullmatch(customer_id):
            continue
        role = row.get("role") if row.get("role") in ROLES else "viewer"
        asset_types = list(dict.fromkeys(item for item in row.get("assetTypes", []) if item in ASSET_TYPES))
        memberships[customer_id] = {"customerId": customer_id, "role": role, "assetTypes": asset_types}
    return list(memberships.values())


def normalize_uuid_filter(value: object, message: str) -> str | None:
    normalized = clean_text(value, 36)
    if not normalized:
        return None
    if not UUID_PATTERN.fullmatch(normalized):
        raise MVAError(message)
    return normalized


def normalize_asset_type(value: object, platform: object = "") -> str:
    requested = clean_text(value, 200).lower()
    for asset_type in ASSET_TYPES:
        if requested == asset_type.lower():
            return asset_type
    evidence = f"{requested} {clean_text(platform, 2000).lower()}"
    patterns = (
        (r"\b(router|switch|wireless|network|load balancer)\b", "Network Device"),
        (r"\b(firewall|waf|ids|ips|security appliance)\b", "Security Appliance"),
        (r"\b(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)\b", "Linux Server"),
        (r"\bwindows server\b", "Windows Server"),
        (r"\b(windows 10|windows 11|macos|desktop|laptop|workstation|endpoint)\b", "Endpoint"),
        (r"\b(postgres|postgresql|mysql|oracle database|sql server|database|db)\b", "Database"),
        (r"\b(aws|azure|gcp|cloud)\b", "Cloud Asset"),
        (r"\b(vmware|esxi|hyper-v|virtualization|hypervisor)\b", "Virtualization Host"),
        (r"\b(kubernetes|openshift|container|k8s)\b", "Container Platform"),
        (r"\b(scada|plc|industrial|ot device|operational technology)\b", "OT Device"),
    )
    return next((label for pattern, label in patterns if re.search(pattern, evidence)), "Other")


def normalize_threat_record(record: dict | None, row_index: int) -> dict:
    record = record if isinstance(record, dict) else {}
    return {
        "rowIndex": row_index,
        "cve": clean_text(record.get("cve"), 2000),
        "vulnerabilityName": clean_text(record.get("vulnerabilityName"), 4000),
        "sourceTool": clean_text(record.get("sourceTool"), 80),
        "sourceVulnerabilityId": clean_text(record.get("sourceVulnerabilityId"), 500),
        "ipAddress": clean_text(record.get("ipAddress"), 500),
        "dnsName": clean_text(record.get("dnsName"), 1000).lower(),
        "severity": record.get("severity") if record.get("severity") in SEVERITIES else "Unknown",
        "patchPriority": record.get("patchPriority") if record.get("patchPriority") in PRIORITIES else "P4",
        "exploitAvailable": bool(record.get("exploitAvailable")),
        "vulnerabilityConfidence": clean_text(record.get("vulnerabilityConfidence"), 1000),
        "exploitEvidence": clean_text(record.get("exploitEvidence") or record.get("exploitSignal"), 4000),
        "description": clean_text(record.get("description") or record.get("summary"), 100_000),
        "remediation": clean_text(record.get("remediation"), 100_000),
        "kbLinks": clean_text(record.get("kbLinks"), 20_000),
        "product": clean_text(record.get("product"), 4000),
        "platformDetails": clean_text(record.get("platformDetails"), 20_000),
        "namespace": clean_text(record.get("namespace"), 1000),
        "deployment": clean_text(record.get("deployment"), 1000),
        "image": clean_text(record.get("image"), 4000),
        "component": clean_text(record.get("component"), 4000),
        "fixable": bool(record.get("fixable")),
        "fixedIn": clean_text(record.get("fixedIn"), 4000),
        "cvssScore": nullable_bounded_number(record.get("cvssScore"), 0, 10),
        "firstObserved": iso_date(record.get("firstObserved") or record.get("firstDiscovered")),
        "lastObserved": iso_date(record.get("lastObserved")),
        "payload": json_safe(record),
    }


def report_period_date(value: object) -> str | None:
    text = clean_text(value, 120)
    month_match = re.search(
        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d{2})\b",
        text,
        re.I,
    )
    if month_match:
        months = (
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
        )
        return f"{month_match.group(2)}-{months.index(month_match.group(1).lower()) + 1:02d}-01"
    quarter = re.search(r"\bQ([1-4])\s+(20\d{2})\b", text, re.I)
    if quarter:
        return f"{quarter.group(2)}-{(int(quarter.group(1)) - 1) * 3 + 1:02d}-01"
    return None


def slugify(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-zA-Z0-9]+", "-", normalized).strip("-").lower()


def clean_string_array(value: object, maximum_items: int, maximum_length: int) -> list[str]:
    rows = value if isinstance(value, list) else []
    return list(dict.fromkeys(clean_text(item, maximum_length) for item in rows if clean_text(item, maximum_length)))[:maximum_items]


def plain_object(value: object) -> dict:
    return json_safe(value) if isinstance(value, dict) else {}


def json_safe(value: object):
    return json.loads(json.dumps(value or {}, default=str))


def positive_integer(value: object) -> int | None:
    try:
        number = int(value)
        return number if number > 0 and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def non_negative_integer(value: object) -> int | None:
    try:
        number = int(value)
        return number if number >= 0 and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def nullable_non_negative_integer(value: object) -> int | None:
    return None if value in (None, "") else non_negative_integer(value)


def bounded_integer(value: object, minimum: int, maximum: int, fallback: int) -> int:
    try:
        number = round(float(value))
        return max(minimum, min(maximum, number)) if math.isfinite(number) else fallback
    except (TypeError, ValueError):
        return fallback


def nullable_bounded_number(value: object, minimum: float, maximum: float) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
        return max(minimum, min(maximum, number)) if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def probability(value: object) -> float | None:
    number = nullable_bounded_number(value, 0, 1)
    return number


def nullable_boolean(value: object) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"yes", "true", "1", "y"}:
        return True
    if normalized in {"no", "false", "0", "n"}:
        return False
    return None


def iso_date(value: object) -> str | None:
    if not value:
        return None
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", str(value).strip())
    if not match:
        return None
    normalized = "-".join(match.groups())
    try:
        return date.fromisoformat(normalized).isoformat()
    except ValueError:
        return None
