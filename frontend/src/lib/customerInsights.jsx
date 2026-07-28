const PRIORITY_ORDER = { P1: 1, P2: 2, P3: 3, P4: 4 };
const SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0 };

export function buildCustomerValueInsights(findings, options = {}) {
  const currentFindings = [...indexFindings(findings).values()];
  const reportDate = options.reportDate ?? inferReportDate(currentFindings);
  return {
    threatPriority: buildThreatPriority(currentFindings),
    remediationCampaigns: buildRemediationCampaigns(currentFindings),
    verification: buildVerification(options.snapshots),
    dataQuality: buildDataQuality(currentFindings, reportDate),
  };
}

function buildThreatPriority(findings) {
  const counts = {
    totalOpen: weightedTotal(findings),
    reviewQueue: 0,
    exploitAvailable: 0,
    internetExposed: 0,
    internetExposureObserved: 0,
    internetExposureUnknown: 0,
    epssObserved: 0,
    epssAbove50: 0,
  };
  const queue = [];

  for (const finding of findings) {
    const weight = findingWeight(finding);
    const epss = numericProbability(finding.epssScore);
    const elevated = Boolean(
      finding.cisaKev
      || (finding.exploitAvailable && ["Critical", "High"].includes(finding.severity))
      || (finding.internetExposed && ["P1", "P2"].includes(finding.patchPriority))
      || (epss != null && epss >= 0.5),
    );
    if (elevated) counts.reviewQueue += weight;
    if (finding.exploitAvailable) counts.exploitAvailable += weight;
    if (finding.internetExposed) counts.internetExposed += weight;
    if (finding.internetExposureKnown) counts.internetExposureObserved += weight;
    else counts.internetExposureUnknown += weight;
    if (epss != null) counts.epssObserved += weight;
    if (epss != null && epss >= 0.5) counts.epssAbove50 += weight;

    if (elevated) {
      queue.push({
        asset: assetLabel(finding),
        service: serviceLabel(finding),
        vulnerability: finding.vulnerabilityName || finding.cve || "Unknown vulnerability",
        cve: finding.cve || "",
        priority: finding.patchPriority,
        severity: finding.severity,
        exposure: Number(finding.assetExposure) || 0,
        epss,
        count: weight,
        signals: threatSignals(finding, epss),
      });
    }
  }

  queue.sort(compareRiskRows);
  return {
    ...counts,
    queue,
  };
}

function threatSignals(finding, epss) {
  const signals = [];
  if (finding.cisaKev) signals.push("Active exploitation evidence");
  if (finding.exploitAvailable) signals.push("Exploit available");
  if (finding.internetExposed) signals.push("Internet exposed");
  if (epss != null) signals.push(`EPSS ${(epss * 100).toFixed(1)}%`);
  if (["Critical", "High"].includes(finding.severity)) signals.push(finding.severity);
  return signals;
}

function buildRemediationCampaigns(findings) {
  const campaignMap = new Map();
  for (const finding of findings) {
    const identity = primaryCve(finding.cve) || normalizeText(finding.vulnerabilityName) || finding.findingKey;
    const campaign = campaignMap.get(identity) ?? {
      id: identity,
      title: finding.vulnerabilityName || finding.cve || "Remediation action",
      cve: finding.cve || "",
      action: finding.remediation || "",
      references: new Set(),
      assets: new Set(),
      sources: new Set(),
      findingCount: 0,
      immediatePatch: 0,
      exploitAvailable: 0,
      maxExposure: 0,
      priorities: { P1: 0, P2: 0, P3: 0, P4: 0 },
      severity: finding.severity,
    };
    const weight = findingWeight(finding);
    campaign.findingCount += weight;
    campaign.assets.add(assetLabel(finding));
    sourceLabels(finding).forEach((source) => campaign.sources.add(source));
    if (["P1", "P2"].includes(finding.patchPriority)) campaign.immediatePatch += weight;
    if (finding.exploitAvailable) campaign.exploitAvailable += weight;
    campaign.priorities[finding.patchPriority] = (campaign.priorities[finding.patchPriority] ?? 0) + weight;
    campaign.maxExposure = Math.max(campaign.maxExposure, Number(finding.assetExposure) || 0);
    campaign.severity = moreSevere(campaign.severity, finding.severity);
    if ((finding.remediation || "").length > campaign.action.length) campaign.action = finding.remediation;
    extractLinks(finding.kbLinks).forEach((link) => campaign.references.add(link));
    campaignMap.set(identity, campaign);
  }

  const campaigns = [...campaignMap.values()].map((campaign) => ({
    ...campaign,
    assets: [...campaign.assets],
    sources: [...campaign.sources],
    references: [...campaign.references],
    primaryPriority: Object.keys(campaign.priorities).sort((a, b) => PRIORITY_ORDER[a] - PRIORITY_ORDER[b]).find((priority) => campaign.priorities[priority] > 0) ?? "P4",
    actionReady: Boolean(campaign.action),
    referenceReady: campaign.references.size > 0,
  }));
  campaigns.sort(compareCampaigns);

  return {
    campaignCount: campaigns.length,
    multiAssetCampaigns: campaigns.filter((campaign) => campaign.assets.length > 1).length,
    actionReady: campaigns.filter((campaign) => campaign.actionReady).length,
    referenceReady: campaigns.filter((campaign) => campaign.referenceReady).length,
    immediatePatchFindings: campaigns.reduce((sum, campaign) => sum + campaign.immediatePatch, 0),
    campaigns,
  };
}

function buildVerification(snapshots = []) {
  if (!Array.isArray(snapshots) || snapshots.length < 2) {
    return {
      available: false,
      message: "Upload at least two reporting periods to compare persistence, new detections, reappearances, and findings no longer observed.",
      currentPeriod: "",
      previousPeriod: "",
      persistent: 0,
      newFindings: 0,
      reappeared: 0,
      noLongerObserved: 0,
      previousTotal: 0,
      currentTotal: 0,
      reconciled: true,
      closureCandidates: [],
      reappearedFindings: [],
    };
  }

  const periodMaps = snapshots.map((snapshot) => indexFindings(snapshot.findings));
  const previousMap = periodMaps.at(-2);
  const currentMap = periodMaps.at(-1);
  const earlierMaps = periodMaps.slice(0, -2);
  const keys = new Set([...previousMap.keys(), ...currentMap.keys()]);
  let persistent = 0;
  let newFindings = 0;
  let reappeared = 0;
  let noLongerObserved = 0;
  const closureCandidates = [];
  const reappearedFindings = [];

  for (const key of keys) {
    const previousFinding = previousMap.get(key);
    const currentFinding = currentMap.get(key);
    const before = previousFinding ? findingWeight(previousFinding) : 0;
    const after = currentFinding ? findingWeight(currentFinding) : 0;
    persistent += Math.min(before, after);
    const reduction = Math.max(0, before - after);
    const addition = Math.max(0, after - before);
    noLongerObserved += reduction;
    const seenEarlier = before === 0 && earlierMaps.some((periodMap) => periodMap.has(key));
    if (seenEarlier) reappeared += addition;
    else newFindings += addition;

    if (reduction > 0 && previousFinding) closureCandidates.push(verificationRow(previousFinding, reduction));
    if (seenEarlier && addition > 0 && currentFinding) reappearedFindings.push(verificationRow(currentFinding, addition));
  }

  const previousTotal = weightedTotal(previousMap.values());
  const currentTotal = weightedTotal(currentMap.values());
  closureCandidates.sort(compareRiskRows);
  reappearedFindings.sort(compareRiskRows);
  return {
    available: true,
    message: "No longer observed is a scan comparison result, not proof that a patch was installed. Validate scan coverage and retain change evidence before closure.",
    previousPeriod: snapshots.at(-2).month ?? snapshots.at(-2).period,
    currentPeriod: snapshots.at(-1).month ?? snapshots.at(-1).period,
    persistent,
    newFindings,
    reappeared,
    noLongerObserved,
    previousTotal,
    currentTotal,
    persistenceRate: previousTotal ? roundPercent(persistent / previousTotal) : 0,
    reconciled: previousTotal === persistent + noLongerObserved && currentTotal === persistent + newFindings + reappeared,
    closureCandidates,
    reappearedFindings,
  };
}

function verificationRow(finding, count) {
  return {
    asset: assetLabel(finding),
    service: serviceLabel(finding),
    vulnerability: finding.vulnerabilityName || finding.cve || "Unknown vulnerability",
    cve: finding.cve || "",
    priority: finding.patchPriority,
    severity: finding.severity,
    exposure: Number(finding.assetExposure) || 0,
    count,
    signals: finding.exploitAvailable ? ["Exploit available"] : [],
  };
}

function buildDataQuality(findings, reportDate) {
  const fields = [
    ["Asset identity", (finding) => Boolean(finding.ipAddress || finding.dnsName)],
    ["Vulnerability identity", (finding) => Boolean(finding.vulnerabilityName || finding.cve || finding.sourceVulnerabilityId)],
    ["Severity", (finding) => Boolean(finding.severity && finding.severity !== "Unknown")],
    ["Remediation", (finding) => Boolean(finding.remediation)],
    ["KB / advisory reference", (finding) => Boolean(extractLinks(finding.kbLinks).length || finding.kbLinks)],
    ["First discovered", (finding) => Boolean(finding.firstDiscovered)],
    ["Last observed", (finding) => Boolean(finding.lastObserved)],
    ["CVE", (finding) => Boolean(finding.cve)],
  ];
  const total = weightedTotal(findings);
  const completeness = fields.map(([label, predicate]) => {
    const present = findings.filter(predicate).reduce((sum, finding) => sum + findingWeight(finding), 0);
    return { label, present, missing: Math.max(0, total - present), percent: total ? roundPercent(present / total) : 0 };
  });
  const totalPresent = completeness.reduce((sum, row) => sum + row.present, 0);
  const corePredicates = fields.slice(0, 4).map(([, predicate]) => predicate);
  const completeCore = findings
    .filter((finding) => corePredicates.every((predicate) => predicate(finding)))
    .reduce((sum, finding) => sum + findingWeight(finding), 0);
  const staleObservations = findings
    .filter((finding) => isOlderThanDays(finding.lastObserved, reportDate, 30))
    .reduce((sum, finding) => sum + findingWeight(finding), 0);

  return {
    totalFindings: total,
    evidenceCompleteness: total ? roundPercent(totalPresent / (total * fields.length)) : 0,
    completeCore,
    staleObservations,
    completeness,
    issues: completeness.filter((row) => row.missing > 0).sort((a, b) => b.missing - a.missing),
  };
}

function indexFindings(findings = []) {
  const indexed = new Map();
  for (const finding of findings ?? []) {
    const key = finding.findingKey || `${assetLabel(finding)}|${finding.cve || finding.vulnerabilityName}|${finding.protocol}|${finding.port}`;
    const existing = indexed.get(key);
    if (!existing) indexed.set(key, { ...finding, recordCount: findingWeight(finding) });
    else {
      const additiveAggregate = finding.sourceTool === "crowdstrike-remediation-assets"
        && existing.sourceTool === "crowdstrike-remediation-assets";
      indexed.set(key, {
        ...existing,
        recordCount: additiveAggregate
          ? findingWeight(existing) + findingWeight(finding)
          : Math.max(findingWeight(existing), findingWeight(finding)),
      });
    }
  }
  return indexed;
}

function compareRiskRows(a, b) {
  return (PRIORITY_ORDER[a.priority] ?? 9) - (PRIORITY_ORDER[b.priority] ?? 9)
    || (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
    || b.exposure - a.exposure
    || b.count - a.count
    || a.vulnerability.localeCompare(b.vulnerability);
}

function compareCampaigns(a, b) {
  return (PRIORITY_ORDER[a.primaryPriority] ?? 9) - (PRIORITY_ORDER[b.primaryPriority] ?? 9)
    || b.immediatePatch - a.immediatePatch
    || b.maxExposure - a.maxExposure
    || b.findingCount - a.findingCount
    || a.title.localeCompare(b.title);
}

function sourceLabels(finding) {
  if (finding.sourceDisplay) return String(finding.sourceDisplay).split(" + ").map((value) => value.trim()).filter(Boolean);
  return (finding.sourceTools?.length ? finding.sourceTools : [finding.sourceTool]).filter(Boolean);
}

function extractLinks(value) {
  return [...new Set(String(value ?? "").match(/https?:\/\/[^\s,;|]+/gi) ?? [])];
}

function primaryCve(value) {
  return String(value ?? "").match(/CVE-\d{4}-\d{4,}/i)?.[0]?.toUpperCase() ?? "";
}

function normalizeText(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function assetLabel(finding) {
  return finding.dnsName || finding.ipAddress || "Unknown asset";
}

function serviceLabel(finding) {
  const protocol = String(finding.protocol || "").toLowerCase();
  const port = String(finding.port || "");
  if (protocol && port) return `${protocol}/${port}`;
  return port || protocol || "Asset-level";
}

function findingWeight(finding) {
  return Math.max(1, Number(finding?.recordCount) || 1);
}

function weightedTotal(findings) {
  let total = 0;
  for (const finding of findings ?? []) total += findingWeight(finding);
  return total;
}

function numericProbability(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 && numeric <= 1 ? numeric : null;
}

function moreSevere(left, right) {
  return (SEVERITY_ORDER[right] ?? 0) > (SEVERITY_ORDER[left] ?? 0) ? right : left;
}

function inferReportDate(findings) {
  let latestTimestamp = null;
  for (const finding of findings) {
    for (const value of [finding.lastObserved, finding.firstDiscovered]) {
      const timestamp = Date.parse(value);
      if (Number.isFinite(timestamp) && (latestTimestamp == null || timestamp > latestTimestamp)) {
        latestTimestamp = timestamp;
      }
    }
  }
  return latestTimestamp == null ? null : new Date(latestTimestamp);
}

function isOlderThanDays(value, reportDate, days) {
  if (!value || !reportDate) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && reportDate.getTime() - timestamp > days * 86_400_000;
}

function roundPercent(value) {
  return Math.round(value * 1000) / 10;
}
