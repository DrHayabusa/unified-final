const SEVERITY_RANK = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0 };
const PRIORITY_RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };

export function findingsForAnalysis(analysis) {
  if (!analysis) return [];
  if (analysis.workflow === "monthly" || analysis.workflow === "quarterly") return analysis.currentFindings ?? [];
  return analysis.findings ?? [];
}

export function buildLocalThreatIntel(analysis, query) {
  const needle = String(query ?? "").trim().toLowerCase();
  if (needle.length < 2) throw new Error("Enter a vulnerability name, CVE, QID, or plugin identifier.");
  const findings = findingsForAnalysis(analysis);
  if (!findings.length) throw new Error("Upload and analyze scanner data before using local threat intelligence.");

  const matches = findings.filter((finding) => searchableFinding(finding).includes(needle));
  if (!matches.length) throw new Error(`No analyzed finding matched "${query}".`);

  const highestSeverity = [...matches].sort((left, right) => (SEVERITY_RANK[right.severity] ?? 0) - (SEVERITY_RANK[left.severity] ?? 0))[0]?.severity ?? "Unknown";
  const priorities = countValues(matches, "patchPriority", PRIORITY_RANK);
  const severities = countValues(matches, "severity", SEVERITY_RANK, true);
  const assets = unique(matches.map((finding) => finding.dnsName || finding.ipAddress));
  const affectedProducts = unique(matches.flatMap((finding) => splitValues(finding.product || finding.platformDetails)));
  const cves = unique(matches.flatMap((finding) => splitValues(finding.cve)));
  const references = unique(matches.flatMap((finding) => extractLinks(finding.kbLinks)));
  const remediationSteps = unique(matches.flatMap((finding) => splitRemediation(finding.remediation)));
  const exploitMatches = matches.filter((finding) => finding.exploitAvailable);

  return {
    query: String(query).trim(),
    source: analysis.sourceLabel || "Uploaded scanner data",
    summary: `${weightedTotal(matches).toLocaleString()} matching open findings across ${assets.length.toLocaleString()} affected assets. Highest observed severity is ${highestSeverity}.`,
    highestSeverity,
    matchedFindings: weightedTotal(matches),
    affectedAssetCount: assets.length,
    affectedAssets: assets.slice(0, 20),
    affectedProducts: affectedProducts.slice(0, 20),
    cves: cves.slice(0, 30),
    exploitAvailable: exploitMatches.length > 0,
    exploitEvidence: exploitMatches.length
      ? `${weightedTotal(exploitMatches).toLocaleString()} matching findings contain an exploit-availability signal from the scanner export.`
      : "No exploit-availability signal was present in the analyzed export.",
    patchPriorities: priorities,
    severities,
    remediationSteps: remediationSteps.slice(0, 20),
    patches: remediationSteps.slice(0, 20),
    references: references.slice(0, 30),
    firstObserved: earliestDate(matches.map((finding) => finding.firstDiscovered)),
    lastObserved: latestDate(matches.map((finding) => finding.lastObserved)),
  };
}

export function buildThreatIntelPrompt(query, localContext = null) {
  return `Investigate the vulnerability or security issue: ${String(query).trim()}

Return one valid JSON object only, with these keys:
summary, highestSeverity, cvss, cves, affectedProducts, affectedVersions, exploitAvailable, exploitEvidence, attackPath, patches, remediationSteps, detectionSteps, references.

Requirements:
- Explain who and what is affected.
- State whether exploitation is known, likely, or unconfirmed and explain the evidence.
- Describe the attack path at a defensive level without exploit payloads.
- List vendor-supported patches or mitigations and validation steps.
- Include authoritative HTTPS references when known.
- Never invent CVEs, versions, patch identifiers, exploitation status, or links. Use "Unknown" when evidence is unavailable.
${localContext ? `\nLocal scanner context:\n${JSON.stringify(localContext, null, 2)}` : ""}`;
}

export function parseThreatIntelResponse(content, source = "AI threat intelligence") {
  const text = String(content ?? "").trim();
  const cleaned = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  try {
    const parsed = JSON.parse(cleaned);
    return normalizeThreatIntel(parsed, source);
  } catch {
    return normalizeThreatIntel({ summary: text || "The provider returned no threat-intelligence content." }, source);
  }
}

export function normalizeThreatIntel(value, source = "Threat intelligence service") {
  const data = value?.result ?? value?.intel ?? value ?? {};
  return {
    source: data.source || source,
    summary: String(data.summary || data.description || "No summary was returned."),
    highestSeverity: String(data.highestSeverity || data.severity || "Unknown"),
    cvss: String(data.cvss || data.cvssScore || "Unknown"),
    cves: toList(data.cves || data.cve),
    affectedProducts: toList(data.affectedProducts || data.products || data.affected),
    affectedVersions: toList(data.affectedVersions || data.versions),
    exploitAvailable: Boolean(data.exploitAvailable ?? data.exploitable),
    exploitEvidence: String(data.exploitEvidence || data.exploitation || "Unknown"),
    attackPath: String(data.attackPath || data.impact || "Unknown"),
    patches: toList(data.patches || data.patch || data.mitigations),
    remediationSteps: toList(data.remediationSteps || data.remediation || data.solution),
    detectionSteps: toList(data.detectionSteps || data.validationSteps || data.validation),
    references: toReferences(data.references || data.links),
    matchedFindings: Number(data.matchedFindings) || 0,
    affectedAssetCount: Number(data.affectedAssetCount) || 0,
    affectedAssets: toList(data.affectedAssets || data.assets),
    patchPriorities: data.patchPriorities || {},
    severities: data.severities || {},
    firstObserved: data.firstObserved || "",
    lastObserved: data.lastObserved || "",
  };
}

function searchableFinding(finding) {
  return [finding.vulnerabilityName, finding.cve, finding.sourceVulnerabilityId, finding.summary, finding.description, finding.vulnerabilityFinding]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function weightedTotal(findings) {
  return findings.reduce((sum, finding) => sum + (Number(finding.recordCount) || 1), 0);
}

function countValues(findings, key, order, reverse = false) {
  const counts = {};
  findings.forEach((finding) => {
    const value = finding[key] || "Unknown";
    counts[value] = (counts[value] ?? 0) + (Number(finding.recordCount) || 1);
  });
  return Object.fromEntries(Object.entries(counts).sort((left, right) => {
    const comparison = (order[left[0]] ?? 99) - (order[right[0]] ?? 99);
    return reverse ? -comparison : comparison;
  }));
}

function splitValues(value) {
  return String(value || "").split(/[|,;]/).map((item) => item.trim()).filter(Boolean);
}

function splitRemediation(value) {
  return String(value || "").split(/\s*\|\s*/).map((item) => item.trim()).filter(Boolean);
}

function extractLinks(value) {
  return String(value || "").match(/https?:\/\/[^\s,|;]+/gi) ?? [];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function toList(value) {
  const values = Array.isArray(value) ? value : [value];
  return unique(values.flatMap((item) => {
    if (item && typeof item === "object") return [structuredListItem(item)].filter(Boolean);
    return String(item || "").split(/\r?\n|\s*\|\s*|\s*;\s*/).map((entry) => entry.replace(/^[-*]\s*/, "").trim());
  }));
}

function structuredListItem(value) {
  const preferredKeys = ["title", "name", "patch", "version", "id", "action", "description", "details", "notes", "url", "link"];
  const parts = preferredKeys
    .filter((key) => value[key] !== undefined && value[key] !== null && value[key] !== "")
    .map((key) => String(value[key]).trim())
    .filter(Boolean);
  if (parts.length) return unique(parts).join(" - ");
  return Object.entries(value)
    .filter(([, entry]) => ["string", "number", "boolean"].includes(typeof entry))
    .map(([key, entry]) => `${humanizeKey(key)}: ${String(entry).trim()}`)
    .join("; ");
}

function toReferences(value) {
  const values = Array.isArray(value) ? value : [value];
  return unique(values.flatMap((item) => {
    if (item && typeof item === "object") {
      return [item.url, item.link, item.href, item.reference].filter((entry) => typeof entry === "string");
    }
    return String(item || "").split(/\r?\n|\s*\|\s*|\s*;\s*/);
  }).map((item) => item.trim()).filter((item) => /^https:\/\//i.test(item)));
}

function humanizeKey(value) {
  return String(value).replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

function earliestDate(values) {
  return sortedDates(values)[0] ?? "";
}

function latestDate(values) {
  return sortedDates(values).at(-1) ?? "";
}

function sortedDates(values) {
  return values.filter(Boolean).map((value) => String(value).slice(0, 10)).sort();
}
