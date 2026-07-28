import { buildQualysInsights } from "./vulnerabilityEngine.jsx";

const NAVY = [20, 33, 61];
const INK = [15, 23, 42];
const MUTED = [100, 116, 139];
const PALE = [248, 250, 252];
const BORDER = [203, 213, 225];
const RED = [220, 38, 38];
const PRIORITY_COLORS = {
  P1: [220, 38, 38],
  P2: [234, 88, 12],
  P3: [202, 138, 4],
  P4: [22, 163, 74],
};
const SEVERITY_COLORS = {
  Critical: [220, 38, 38],
  High: [234, 88, 12],
  Medium: [202, 138, 4],
  Low: [22, 163, 74],
  Info: [2, 132, 199],
  Unknown: [100, 116, 139],
};
const AGE_BUCKETS = [">7 days", ">30 days", ">60 days", ">180 days"];

export async function downloadExecutiveDashboardPdf({ analysis, targetPeriod }) {
  const doc = await createExecutiveDashboardPdfDocument({ analysis, targetPeriod });
  doc.save(`MVA_${safeName(analysis?.sourceLabel)}_${safeName(targetPeriod)}_Executive_Dashboard.pdf`);
}

export async function createExecutiveDashboardPdfDocument({ analysis, targetPeriod }) {
  if (!analysis) throw new Error("Analyze an export before generating the executive dashboard PDF.");
  const { jsPDF } = await import("jspdf");
  const model = buildExecutiveReportModel(analysis, targetPeriod);
  const doc = new jsPDF({ unit: "mm", format: "a4", orientation: "landscape", compress: true });
  doc.setProperties({
    title: "Vulnerability Analysis Report",
    subject: `${model.sourceLabel} executive vulnerability dashboard for ${model.targetPeriod}`,
    creator: "MVA Vulnerability Agent",
  });

  drawCover(doc, model);
  doc.addPage();
  drawExecutiveSummary(doc, model);
  if (model.qualys) {
    doc.addPage();
    drawQualysPage(doc, model);
  }
  if (model.trend.length > 1 || model.quarterlyDiscoveryTrend.length > 1 || model.adhocLineSeries?.points?.length > 1) {
    doc.addPage();
    drawTrendPage(doc, model);
  }
  doc.addPage();
  drawOpenPage(doc, model);
  doc.addPage();
  drawPriorityPage(doc, model);
  doc.addPage();
  drawAgePage(doc, model);
  doc.addPage();
  drawRankingsPage(doc, model);
  doc.addPage();
  drawMethodologyPage(doc, model);
  addFooters(doc);
  return doc;
}

export function buildExecutiveReportModel(analysis, targetPeriod) {
  const snapshots = analysis.snapshots ?? [];
  const targetIndex = snapshots.findIndex((snapshot) => snapshot.month === targetPeriod || snapshot.period === targetPeriod);
  const selectedIndex = targetIndex >= 0 ? targetIndex : snapshots.length - 1;
  const selectedSnapshot = selectedIndex >= 0 ? snapshots[selectedIndex] : null;
  const findings = selectedSnapshot?.findings ?? analysis.currentFindings ?? analysis.findings ?? [];
  const reportDate = selectedSnapshot?.reportDate ?? inferReportDate(findings);
  const totalOpen = weightedTotal(findings);
  const severityCounts = weightedCounts(findings, "severity", ["Critical", "High", "Medium", "Low", "Info", "Unknown"]);
  const priorityCounts = weightedCounts(findings, "patchPriority", ["P1", "P2", "P3", "P4"]);
  const movement = comparisonMovement(snapshots, selectedIndex, totalOpen);
  const trend = snapshots.length
    ? snapshots.slice(Math.max(0, selectedIndex - 2), selectedIndex + 1).map((snapshot, index, selected) => {
      const originalIndex = snapshots.indexOf(snapshot);
      const currentMap = findingMap(snapshot.findings);
      const previousMap = originalIndex > 0 ? findingMap(snapshots[originalIndex - 1].findings) : new Map();
      return {
        period: snapshot.month,
        totalOpen: weightedTotal(currentMap.values()),
        discovered: discoveredInPeriod(snapshot.findings, snapshot.reportDate),
        remediated: originalIndex > 0 ? removedCount(previousMap, currentMap) : 0,
        isBaseline: index === 0 && originalIndex === 0,
      };
    })
    : [];
  const quarterlyDiscoveryTrend = analysis.dashboard?.quarterlyDiscoveryTrend ?? [];
  const adhocLineSeries = analysis.dashboard?.adhocLineSeries ?? null;
  const ageMatrix = buildAgeMatrix(findings, reportDate);
  const sourceBreakdown = selectedSnapshot?.sourceBreakdown ?? analysis.dashboard?.sourceBreakdown ?? [];
  const openshift = analysis.dashboard?.openshiftInsights;
  const qualys = buildQualysInsights(findings);
  return {
    sourceLabel: analysis.sourceLabel || "MVA",
    targetPeriod: targetPeriod || selectedSnapshot?.month || analysis.reportPeriod || analysis.reportMonth || "Current report",
    workflow: analysis.workflow || "adhoc",
    totalOpen,
    distinctAssets: new Set(findings.map(assetLabel)).size,
    immediatePatch: (priorityCounts.P1 ?? 0) + (priorityCounts.P2 ?? 0),
    exploitAvailable: findings.filter((finding) => finding.exploitAvailable).reduce((sum, finding) => sum + weight(finding), 0),
    severityCounts,
    priorityCounts,
    ageMatrix,
    movement,
    trend,
    quarterlyDiscoveryTrend,
    adhocLineSeries,
    topAssets: buildTopAssets(findings),
    topVulnerabilities: buildTopVulnerabilities(findings),
    sourceBreakdown,
    openshift,
    qualys,
    generatedAt: new Date(),
  };
}

function drawCover(doc, model) {
  const { width, height } = pageSize(doc);
  doc.setFillColor(...NAVY);
  doc.rect(0, 0, width, height, "F");
  doc.setFillColor(...RED);
  doc.rect(0, 0, 9, height, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(17);
  doc.text("HELP AG", 23, 25);
  doc.setFontSize(10);
  doc.text("MVA UNIFIED VULNERABILITY MANAGEMENT", 23, 34);
  doc.setDrawColor(239, 68, 68);
  doc.setLineWidth(0.8);
  doc.line(23, 47, width - 23, 47);

  doc.setFontSize(29);
  doc.text("Vulnerability Analysis Report", 23, 83);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(13);
  doc.setTextColor(203, 213, 225);
  doc.text(model.sourceLabel, 23, 96);

  metadataBlock(doc, "REPORTING PERIOD", model.targetPeriod, 23, 117, 74);
  metadataBlock(doc, "REPORT TYPE", "Executive dashboard", 103, 117, 74);
  metadataBlock(doc, "OPEN FINDINGS", formatNumber(model.totalOpen), 183, 117, 74);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(255, 255, 255);
  doc.text("Contents", 23, 155);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(203, 213, 225);
  const sections = [
    "Executive summary",
    ...(model.qualys ? ["Qualys rating and Datacentre analysis"] : []),
    ...(model.trend.length > 1 || model.quarterlyDiscoveryTrend.length > 1 || model.adhocLineSeries?.points?.length > 1 ? ["Vulnerability line chart"] : []),
    "Total open vulnerabilities",
    "Patch priority distribution",
    "Age and patch priority",
    "Top affected assets and vulnerabilities",
    "Definitions and calculation logic",
  ];
  sections.forEach((section, index) => doc.text(`${index + 1}. ${section}`, 23 + (index >= 4 ? 118 : 0), 168 + (index % 4) * 8));
}

function drawExecutiveSummary(doc, model) {
  pageHeader(doc, "Executive Summary", `${model.sourceLabel} | ${model.targetPeriod}`);
  const cards = [
    ["Total open", model.totalOpen, "Current unresolved findings", NAVY],
    ["Critical", model.severityCounts.Critical, "Critical severity findings", SEVERITY_COLORS.Critical],
    ["High", model.severityCounts.High, "High severity findings", SEVERITY_COLORS.High],
    ["P1 + P2", model.immediatePatch, "Immediate patch population", RED],
    ["Affected assets", model.distinctAssets, "Unique normalized identities", [2, 132, 199]],
    ["Exploit available", model.exploitAvailable, "Positive source evidence", [124, 58, 237]],
  ];
  cards.forEach((card, index) => drawKpiCard(doc, card, 14 + index * 45, 31, 41, 31));

  sectionTitle(doc, "Severity posture", 14, 72);
  drawHorizontalBars(doc, model.severityCounts, SEVERITY_COLORS, 14, 80, 128, 76);
  sectionTitle(doc, "Patch priority posture", 154, 72);
  drawHorizontalBars(doc, model.priorityCounts, PRIORITY_COLORS, 154, 80, 128, 76);

  const observations = [];
  observations.push(`${formatNumber(model.immediatePatch)} of ${formatNumber(model.totalOpen)} open findings require P1 or P2 handling.`);
  observations.push(`${formatNumber(model.exploitAvailable)} findings contain positive exploit-availability evidence from the selected source exports.`);
  if (model.movement.comparable) observations.push(`${formatNumber(model.movement.patched)} findings were no longer observed since ${model.movement.previousPeriod}.`);
  if (model.openshift) observations.push(`${formatNumber(model.openshift.fixable)} OpenShift findings have fix availability evidence; ${formatNumber(model.openshift.noFixedVersion)} have no fixed version supplied.`);
  drawNarrativeBox(doc, "Executive observations", observations, 14, 159, 268, 36);
}

function drawQualysPage(doc, model) {
  pageHeader(doc, "Qualys Operational Analysis", `${model.sourceLabel} | ${model.targetPeriod}`);
  const customProfile = model.sourceLabel.toLowerCase().includes("custom qualys");
  const ratings = orderedQualysRatings(model.qualys.vendorRatings, customProfile);
  const ratingValues = Object.fromEntries(ratings.map((row) => [row.rating, row.vulnerabilityCount]));
  const datacentres = Object.fromEntries(model.qualys.datacentres.map((row) => [row.datacentre, row.vulnerabilityCount]));

  drawKpiCard(doc, ["Open findings", model.qualys.totalOpen, "Current Qualys findings", NAVY], 14, 31, 61, 31);
  drawKpiCard(doc, ["Repeated findings", model.qualys.repeatedFindings, "Times Detected greater than 1", SEVERITY_COLORS.High], 82, 31, 61, 31);
  drawKpiCard(doc, ["Detection events", model.qualys.detectionEvents, "Sum of Times Detected", [2, 132, 199]], 150, 31, 61, 31);
  drawKpiCard(
    doc,
    ["Datacentres", model.qualys.datacentres.filter((row) => row.datacentre !== "Not supplied").length, "Distinct supplied categories", [15, 118, 110]],
    218,
    31,
    64,
    31,
  );

  sectionTitle(doc, customProfile ? "Custom Qualys source ratings" : "Qualys source ratings", 14, 75);
  drawHorizontalBars(doc, ratingValues, {}, 14, 83, 128, 78);
  sectionTitle(doc, "Datacentre distribution", 154, 75);
  drawHorizontalBars(doc, datacentres, {}, 154, 83, 128, 78);
  drawNarrativeBox(doc, "Interpretation", [
    customProfile
      ? "Source ratings are retained exactly as 5 Urgent, 4 Critical, 3 Serious, 2 Medium, and 1 Minimal."
      : "Qualys source ratings are retained separately from MVA normalized severity.",
    "Datacentre categories are taken directly from the supplied export; blank values are reported as Not supplied.",
    "Normalized severity continues to drive the approved exploit-aware P1-P4 priority matrix.",
  ], 14, 169, 268, 26);
}

function orderedQualysRatings(rows = [], customProfile = false) {
  const counts = new Map(rows.map((row) => [String(row.rating), Number(row.vulnerabilityCount) || 0]));
  const labels = customProfile
    ? ["5 - Urgent", "4 - Critical", "3 - Serious", "2 - Medium", "1 - Minimal"]
    : ["5 - Critical", "4 - High", "3 - Medium", "2 - Low", "1 - Minimal"];
  return labels.map((rating) => ({ rating, vulnerabilityCount: counts.get(rating) ?? 0 }));
}

function drawTrendPage(doc, model) {
  if (model.trend.length > 1) {
    pageHeader(doc, "Vulnerability Trend", "Discovered and remediated findings - latest three reporting periods");
    sectionTitle(doc, "Vulnerabilities discovered", 14, 33);
    drawLineChart(doc, model.trend, "discovered", [220, 38, 38], 14, 42, 128, 94);
    sectionTitle(doc, "Vulnerabilities remediated", 154, 33);
    drawLineChart(doc, model.trend, "remediated", [22, 163, 74], 154, 42, 128, 94);
    drawNarrativeBox(doc, "Calculation", [
      "Discovered: findings whose First Discovered date falls in the reporting period.",
      "Remediated: findings present in the previous report and absent from the current report.",
      "A missing historical file is not treated as remediation evidence.",
    ], 14, 148, 268, 42);
    return;
  }

  const datedTrend = model.quarterlyDiscoveryTrend.length > 1
    ? model.quarterlyDiscoveryTrend.map((row) => ({ period: row.month, value: row.discoveredCount }))
    : null;
  const sourceSeries = datedTrend ?? model.adhocLineSeries?.points?.map((point) => ({ period: point.label, value: point.value })) ?? [];
  const title = datedTrend || model.adhocLineSeries?.basis === "first-discovered"
    ? "Vulnerabilities Discovered - Last 3 Months"
    : "Current Open Findings by Severity";
  pageHeader(doc, "Vulnerability Line Chart", title);
  sectionTitle(doc, title, 14, 33);
  drawLineChart(doc, sourceSeries, "value", [220, 38, 38], 14, 42, 268, 104);
  drawNarrativeBox(doc, "Calculation", datedTrend || model.adhocLineSeries?.basis === "first-discovered"
    ? [
      "Each point counts findings whose First Discovered date falls in that month.",
      "This is discovery movement derived from the current export; it does not claim that absent findings were remediated.",
    ]
    : [
      "The source export does not provide sufficient dated history for a time trend.",
      "The line therefore displays the current Critical, High, Medium, and Low finding profile without inventing historical values.",
    ], 14, 158, 268, 32);
}

function drawOpenPage(doc, model) {
  pageHeader(doc, "Total Open Vulnerabilities", "New findings plus findings not closed from the previous report");
  const values = model.movement.comparable
    ? { New: model.movement.newFindings, "Not closed": model.movement.carried }
    : { "Current open": model.totalOpen };
  drawDonutSummary(doc, values, 19, 43, 92, 105);
  drawKpiCard(doc, ["Total open", model.totalOpen, "New + not closed", NAVY], 128, 48, 69, 42);
  drawKpiCard(doc, ["New", model.movement.newFindings, model.movement.comparable ? `Since ${model.movement.previousPeriod}` : "Comparison not available", [2, 132, 199]], 205, 48, 69, 42);
  drawKpiCard(doc, ["Not closed", model.movement.carried, model.movement.comparable ? "Persisting from prior report" : "Current report baseline", [234, 88, 12]], 128, 101, 69, 42);
  drawKpiCard(doc, ["Patched", model.movement.patched, model.movement.comparable ? "No longer observed" : "Comparison not available", [22, 163, 74]], 205, 101, 69, 42);
  drawNarrativeBox(doc, "Reconciliation", [
    model.movement.comparable
      ? `${formatNumber(model.movement.previousOpen)} previous open + ${formatNumber(model.movement.newFindings)} new - ${formatNumber(model.totalOpen)} current open = ${formatNumber(model.movement.patched)} patched.`
      : "A single ad hoc or quarterly scan provides current-state totals. New and patched counts require a previous comparable report.",
  ], 128, 154, 146, 34);
}

function drawPriorityPage(doc, model) {
  pageHeader(doc, "Open Vulnerabilities by Patch Priority", "Approved severity and exploit-availability matrix");
  drawVerticalBars(doc, model.priorityCounts, PRIORITY_COLORS, 14, 39, 150, 111);
  drawPriorityMatrix(doc, 177, 39, 105, 85);
  drawNarrativeBox(doc, "Priority interpretation", [
    "P1 and P2 are included in Immediate Patch Needed.",
    "Exploit availability must be supported by a source field. When that field is absent, OpenShift follows severity directly: Critical P1, High P2, Medium P3, Low P4.",
    "Different vulnerabilities on the same asset remain separate findings.",
  ], 177, 135, 105, 53);
}

function drawAgePage(doc, model) {
  pageHeader(doc, "Open Findings by Age and Patch Priority", "Cumulative thresholds: >7, >30, >60, and >180 days");
  drawAgeMatrix(doc, model.ageMatrix, 14, 39, 268, 103);
  drawNarrativeBox(doc, "How to read this page", [
    "Thresholds are cumulative. A finding older than 180 days is also counted in >60, >30, and >7 days.",
    "Age uses the scanner vulnerability-age field when supplied; otherwise it is calculated from First Discovered to the report date.",
    "Missing age evidence is not assigned to a threshold.",
  ], 14, 153, 268, 36);
}

function drawRankingsPage(doc, model) {
  pageHeader(doc, "Risk Concentration", "Top affected assets and highest-volume vulnerabilities");
  drawRankingTable(doc, "Top affected assets", model.topAssets, [
    ["Asset", "asset"],
    ["Open", "open"],
    ["P1/P2", "immediate"],
    ["Critical", "critical"],
  ], 14, 35, 130, 148);
  drawRankingTable(doc, "Top vulnerabilities", model.topVulnerabilities, [
    ["Vulnerability", "name"],
    ["Open", "open"],
    ["Assets", "assets"],
    ["Priority", "priority"],
  ], 153, 35, 129, 148);
}

function drawMethodologyPage(doc, model) {
  pageHeader(doc, "Definitions and Calculation Logic", "Source-neutral rules used by MVA");
  const rows = [
    ["Measure", "Definition"],
    ["Total open", "New findings plus findings still open from the previous comparable report."],
    ["New", "Finding key is present in the current report but not the previous report."],
    ["Patched", "Previous open + new - current open, reconciled against finding-key removal."],
    ["Finding identity", "Asset identity + vulnerability identity + protocol + port/service. Different vulnerabilities on one asset are never deduplicated."],
    ["Exploit available", "Positive evidence from the scanner exploit field. Empty, unavailable, unproven, or negative values are false."],
    ["P1-P4", "Severity crossed with exploit availability using the approved priority matrix."],
    ["Age thresholds", "Cumulative >7, >30, >60, and >180 day counts by patch priority."],
    ["OpenShift Fixable", "Remediation availability only; it does not change exploit availability."],
  ];
  drawDefinitionTable(doc, rows, 14, 35, 268, 110);
  if (model.sourceBreakdown.length) {
    sectionTitle(doc, "Source contribution", 14, 155);
    const contribution = Object.fromEntries(model.sourceBreakdown.slice(0, 8).map((row) => [row.sourceLabel, row.openFindings]));
    drawHorizontalBars(doc, contribution, {}, 14, 162, 268, 27);
  } else {
    drawNarrativeBox(doc, "Source", [`The report was generated from ${model.sourceLabel} normalized findings.`], 14, 158, 268, 30);
  }
}

function drawKpiCard(doc, [label, value, detail, color], x, y, width, height) {
  doc.setFillColor(...PALE);
  doc.setDrawColor(...BORDER);
  doc.roundedRect(x, y, width, height, 2, 2, "FD");
  doc.setFillColor(...color);
  doc.rect(x, y, 2.4, height, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  doc.setTextColor(...MUTED);
  doc.text(label.toUpperCase(), x + 6, y + 8);
  doc.setFontSize(19);
  doc.setTextColor(...INK);
  doc.text(formatNumber(value), x + 6, y + 20);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(6.8);
  doc.setTextColor(...MUTED);
  doc.text(doc.splitTextToSize(detail, width - 12).slice(0, 2), x + 6, y + 27);
}

function drawHorizontalBars(doc, values, colors, x, y, width, height) {
  const entries = Object.entries(values).filter(([, value]) => Number(value) >= 0);
  const maximum = Math.max(1, ...entries.map(([, value]) => Number(value)));
  const rowHeight = height / Math.max(1, entries.length);
  entries.forEach(([label, value], index) => {
    const rowY = y + index * rowHeight;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(...INK);
    doc.text(shortText(doc, label, 34), x, rowY + 5);
    doc.setFillColor(226, 232, 240);
    doc.roundedRect(x + 38, rowY + 1.2, width - 52, 5, 1.2, 1.2, "F");
    doc.setFillColor(...(colors[label] ?? NAVY));
    doc.roundedRect(x + 38, rowY + 1.2, Math.max(1.5, (Number(value) / maximum) * (width - 52)), 5, 1.2, 1.2, "F");
    doc.text(formatNumber(value), x + width, rowY + 5, { align: "right" });
  });
}

function drawVerticalBars(doc, values, colors, x, y, width, height) {
  const entries = Object.entries(values);
  const maximum = Math.max(1, ...entries.map(([, value]) => Number(value)));
  const plotBottom = y + height - 15;
  const barWidth = Math.min(24, (width - 25) / entries.length);
  const gap = (width - barWidth * entries.length) / (entries.length + 1);
  doc.setDrawColor(226, 232, 240);
  doc.line(x + 8, plotBottom, x + width - 4, plotBottom);
  entries.forEach(([label, value], index) => {
    const barX = x + gap + index * (barWidth + gap);
    const barHeight = (Number(value) / maximum) * (height - 28);
    doc.setFillColor(...(colors[label] ?? NAVY));
    doc.roundedRect(barX, plotBottom - barHeight, barWidth, barHeight, 2, 2, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(...INK);
    doc.text(formatNumber(value), barX + barWidth / 2, plotBottom - barHeight - 3, { align: "center" });
    doc.text(label, barX + barWidth / 2, plotBottom + 7, { align: "center" });
  });
}

function drawLineChart(doc, rows, field, color, x, y, width, height) {
  const values = rows.map((row) => Number(row[field]) || 0);
  const maximum = Math.max(1, ...values);
  const left = x + 12;
  const right = x + width - 7;
  const top = y + 8;
  const bottom = y + height - 16;
  doc.setDrawColor(226, 232, 240);
  for (let line = 0; line <= 4; line += 1) {
    const lineY = top + ((bottom - top) / 4) * line;
    doc.line(left, lineY, right, lineY);
    doc.setFontSize(6);
    doc.setTextColor(...MUTED);
    doc.text(formatNumber(Math.round(maximum * (1 - line / 4))), left - 2, lineY + 2, { align: "right" });
  }
  const points = rows.map((row, index) => ({
    x: rows.length === 1 ? (left + right) / 2 : left + (index / (rows.length - 1)) * (right - left),
    y: bottom - ((Number(row[field]) || 0) / maximum) * (bottom - top),
    label: row.period || row.month,
    value: Number(row[field]) || 0,
  }));
  doc.setDrawColor(...color);
  doc.setLineWidth(1);
  for (let index = 1; index < points.length; index += 1) doc.line(points[index - 1].x, points[index - 1].y, points[index].x, points[index].y);
  points.forEach((point) => {
    doc.setFillColor(...color);
    doc.circle(point.x, point.y, 1.8, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(...INK);
    doc.text(formatNumber(point.value), point.x, point.y - 4, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.5);
    doc.setTextColor(...MUTED);
    doc.text(shortText(doc, point.label, 29), point.x, bottom + 8, { align: "center" });
  });
}

function drawDonutSummary(doc, values, x, y, width, height) {
  const entries = Object.entries(values);
  const total = Math.max(1, entries.reduce((sum, [, value]) => sum + Number(value), 0));
  const centerX = x + width / 2;
  const centerY = y + height / 2 - 4;
  const radius = 31;
  let start = -Math.PI / 2;
  entries.forEach(([label, value], index) => {
    const angle = (Number(value) / total) * Math.PI * 2;
    doc.setDrawColor(...(index === 0 ? [2, 132, 199] : [234, 88, 12]));
    doc.setLineWidth(8);
    drawArc(doc, centerX, centerY, radius, start, start + angle);
    start += angle;
  });
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(...INK);
  doc.text(formatNumber(total), centerX, centerY + 2, { align: "center" });
  doc.setFontSize(7);
  doc.setTextColor(...MUTED);
  doc.text("TOTAL OPEN", centerX, centerY + 10, { align: "center" });
  entries.forEach(([label, value], index) => {
    const rowY = y + height - 16 + index * 8;
    doc.setFillColor(...(index === 0 ? [2, 132, 199] : [234, 88, 12]));
    doc.rect(x + 5, rowY - 3, 3, 3, "F");
    doc.setTextColor(...INK);
    doc.setFontSize(7);
    doc.text(`${label}: ${formatNumber(value)}`, x + 11, rowY);
  });
}

function drawPriorityMatrix(doc, x, y, width, height) {
  sectionTitle(doc, "Priority matrix", x, y);
  const startY = y + 10;
  const labelWidth = 27;
  const columnWidth = (width - labelWidth) / 2;
  const rowHeight = 14;
  const rows = [
    ["Severity", "Exploit available", "No exploit"],
    ["Critical", "P1", "P2"],
    ["High", "P1", "P2"],
    ["Medium", "P2", "P3"],
    ["Low", "P2", "P4"],
  ];
  rows.forEach((row, rowIndex) => {
    let currentX = x;
    row.forEach((value, columnIndex) => {
      const cellWidth = columnIndex === 0 ? labelWidth : columnWidth;
      const priorityColor = PRIORITY_COLORS[value];
      doc.setFillColor(...(rowIndex === 0 ? NAVY : priorityColor ?? PALE));
      doc.setDrawColor(...BORDER);
      doc.rect(currentX, startY + rowIndex * rowHeight, cellWidth, rowHeight, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(columnIndex === 0 ? 6.5 : 8);
      doc.setTextColor(...(rowIndex === 0 || priorityColor ? [255, 255, 255] : INK));
      doc.text(value, currentX + cellWidth / 2, startY + rowIndex * rowHeight + 8.5, { align: "center" });
      currentX += cellWidth;
    });
  });
}

function drawAgeMatrix(doc, matrix, x, y, width, height) {
  const labelWidth = 30;
  const columnWidth = (width - labelWidth) / AGE_BUCKETS.length;
  const rowHeight = height / 5;
  const maximum = Math.max(1, ...Object.values(matrix).flatMap((row) => Object.values(row)));
  const header = ["Priority", ...AGE_BUCKETS];
  header.forEach((value, index) => {
    const cellX = x + (index === 0 ? 0 : labelWidth + (index - 1) * columnWidth);
    const cellWidth = index === 0 ? labelWidth : columnWidth;
    doc.setFillColor(...NAVY);
    doc.setDrawColor(...BORDER);
    doc.rect(cellX, y, cellWidth, rowHeight, "FD");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.text(value, cellX + cellWidth / 2, y + rowHeight / 2 + 2, { align: "center" });
  });
  Object.entries(matrix).forEach(([priority, values], rowIndex) => {
    const rowY = y + (rowIndex + 1) * rowHeight;
    doc.setFillColor(...PRIORITY_COLORS[priority]);
    doc.rect(x, rowY, labelWidth, rowHeight, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(10);
    doc.text(priority, x + labelWidth / 2, rowY + rowHeight / 2 + 2, { align: "center" });
    AGE_BUCKETS.forEach((bucket, columnIndex) => {
      const value = Number(values[bucket]) || 0;
      const intensity = value / maximum;
      const base = PRIORITY_COLORS[priority];
      const fill = base.map((channel) => Math.round(248 - (248 - channel) * Math.max(0.14, intensity)));
      const cellX = x + labelWidth + columnIndex * columnWidth;
      doc.setFillColor(...fill);
      doc.setDrawColor(...BORDER);
      doc.rect(cellX, rowY, columnWidth, rowHeight, "FD");
      doc.setTextColor(...INK);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.text(formatNumber(value), cellX + columnWidth / 2, rowY + rowHeight / 2 + 2, { align: "center" });
    });
  });
}

function drawRankingTable(doc, titleText, rows, columns, x, y, width, height) {
  sectionTitle(doc, titleText, x, y);
  const startY = y + 9;
  const rowHeight = Math.min(12, (height - 10) / 11);
  const firstWidth = width * 0.55;
  const remaining = (width - firstWidth) / (columns.length - 1);
  const widths = columns.map((_, index) => index === 0 ? firstWidth : remaining);
  let currentX = x;
  columns.forEach(([label], index) => {
    doc.setFillColor(...NAVY);
    doc.setDrawColor(...BORDER);
    doc.rect(currentX, startY, widths[index], rowHeight, "FD");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.5);
    doc.text(label, currentX + 2, startY + 7);
    currentX += widths[index];
  });
  rows.slice(0, 10).forEach((row, rowIndex) => {
    const rowY = startY + (rowIndex + 1) * rowHeight;
    currentX = x;
    columns.forEach(([, key], columnIndex) => {
      doc.setFillColor(...(rowIndex % 2 === 0 ? PALE : [241, 245, 249]));
      doc.setDrawColor(...BORDER);
      doc.rect(currentX, rowY, widths[columnIndex], rowHeight, "FD");
      doc.setTextColor(...INK);
      doc.setFont("helvetica", columnIndex === 0 ? "bold" : "normal");
      doc.setFontSize(6.5);
      const value = typeof row[key] === "number" ? formatNumber(row[key]) : row[key];
      doc.text(shortText(doc, value, widths[columnIndex] - 4), currentX + 2, rowY + 7);
      currentX += widths[columnIndex];
    });
  });
}

function drawDefinitionTable(doc, rows, x, y, width, height) {
  const firstWidth = 52;
  const secondWidth = width - firstWidth;
  let currentY = y;
  rows.forEach((row, index) => {
    const wrapped = doc.splitTextToSize(row[1], secondWidth - 6);
    const rowHeight = index === 0 ? 11 : Math.max(10, wrapped.length * 4 + 4);
    doc.setFillColor(...(index === 0 ? NAVY : index % 2 ? PALE : [241, 245, 249]));
    doc.setDrawColor(...BORDER);
    doc.rect(x, currentY, firstWidth, rowHeight, "FD");
    doc.rect(x + firstWidth, currentY, secondWidth, rowHeight, "FD");
    doc.setTextColor(...(index === 0 ? [255, 255, 255] : INK));
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.text(row[0], x + 3, currentY + 6.5);
    doc.setFont("helvetica", index === 0 ? "bold" : "normal");
    doc.text(wrapped, x + firstWidth + 3, currentY + 6.5);
    currentY += rowHeight;
  });
  return Math.min(currentY, y + height);
}

function drawNarrativeBox(doc, titleText, lines, x, y, width, height) {
  doc.setFillColor(...PALE);
  doc.setDrawColor(...BORDER);
  doc.roundedRect(x, y, width, height, 2, 2, "FD");
  doc.setFillColor(...RED);
  doc.rect(x, y, 2.2, height, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(...INK);
  doc.text(titleText, x + 7, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(...MUTED);
  let lineY = y + 16;
  lines.forEach((line) => {
    const wrapped = doc.splitTextToSize(`- ${line}`, width - 14);
    doc.text(wrapped, x + 7, lineY);
    lineY += wrapped.length * 3.6 + 2;
  });
}

function pageHeader(doc, titleText, subtitle) {
  const { width } = pageSize(doc);
  doc.setFillColor(...NAVY);
  doc.rect(0, 0, width, 22, "F");
  doc.setFillColor(...RED);
  doc.rect(0, 0, 5, 22, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text(titleText, 14, 14);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(203, 213, 225);
  doc.text(subtitle, width - 14, 14, { align: "right" });
}

function sectionTitle(doc, value, x, y) {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(...INK);
  doc.text(value, x, y);
  doc.setDrawColor(...RED);
  doc.setLineWidth(0.5);
  doc.line(x, y + 2.5, x + 24, y + 2.5);
}

function metadataBlock(doc, label, value, x, y, width) {
  doc.setFillColor(30, 46, 76);
  doc.setDrawColor(71, 85, 105);
  doc.roundedRect(x, y, width, 25, 2, 2, "FD");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(6.5);
  doc.setTextColor(148, 163, 184);
  doc.text(label, x + 5, y + 8);
  doc.setFontSize(11);
  doc.setTextColor(255, 255, 255);
  doc.text(shortText(doc, value, width - 10), x + 5, y + 18);
}

function addFooters(doc) {
  const { width, height } = pageSize(doc);
  const pages = doc.getNumberOfPages();
  for (let page = 1; page <= pages; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(226, 232, 240);
    doc.line(14, height - 11, width - 14, height - 11);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.5);
    doc.setTextColor(...MUTED);
    doc.text("MVA Vulnerability Analysis Report", 14, height - 6);
    doc.text(`Page ${page} of ${pages}`, width - 14, height - 6, { align: "right" });
  }
}

function comparisonMovement(snapshots, selectedIndex, currentTotal) {
  if (!snapshots.length || selectedIndex <= 0) {
    return { comparable: false, previousPeriod: "", previousOpen: 0, newFindings: 0, carried: currentTotal, patched: 0 };
  }
  const previous = snapshots[selectedIndex - 1];
  const current = snapshots[selectedIndex];
  const previousMap = findingMap(previous.findings);
  const currentMap = findingMap(current.findings);
  let newFindings = 0;
  let carried = 0;
  for (const [key, finding] of currentMap) {
    const before = previousMap.get(key);
    newFindings += Math.max(0, weight(finding) - weight(before));
    carried += Math.min(weight(finding), weight(before));
  }
  const previousOpen = weightedTotal(previousMap.values());
  return {
    comparable: true,
    previousPeriod: previous.month,
    previousOpen,
    newFindings,
    carried,
    patched: Math.max(0, previousOpen + newFindings - currentTotal),
  };
}

function buildAgeMatrix(findings, reportDate) {
  const matrix = Object.fromEntries(Object.keys(PRIORITY_COLORS).map((priority) => [priority, Object.fromEntries(AGE_BUCKETS.map((bucket) => [bucket, 0]))]));
  for (const finding of findings) {
    const days = finding.vulnerabilityAgeDays != null
      ? Math.max(0, Number(finding.vulnerabilityAgeDays) || 0)
      : ageDays(finding.firstDiscovered, reportDate);
    if (days == null || !matrix[finding.patchPriority]) continue;
    if (days > 7) matrix[finding.patchPriority][">7 days"] += weight(finding);
    if (days > 30) matrix[finding.patchPriority][">30 days"] += weight(finding);
    if (days > 60) matrix[finding.patchPriority][">60 days"] += weight(finding);
    if (days > 180) matrix[finding.patchPriority][">180 days"] += weight(finding);
  }
  return matrix;
}

function buildTopAssets(findings) {
  const map = new Map();
  for (const finding of findings) {
    const key = assetLabel(finding);
    const row = map.get(key) ?? { asset: key, open: 0, immediate: 0, critical: 0 };
    row.open += weight(finding);
    if (["P1", "P2"].includes(finding.patchPriority)) row.immediate += weight(finding);
    if (finding.severity === "Critical") row.critical += weight(finding);
    map.set(key, row);
  }
  return [...map.values()].sort((left, right) => right.open - left.open || left.asset.localeCompare(right.asset)).slice(0, 10);
}

function buildTopVulnerabilities(findings) {
  const map = new Map();
  for (const finding of findings) {
    const key = finding.cve || finding.vulnerabilityName || finding.findingKey;
    const row = map.get(key) ?? { name: finding.vulnerabilityName || key, open: 0, assets: new Set(), priority: finding.patchPriority };
    row.open += weight(finding);
    row.assets.add(assetLabel(finding));
    if (priorityRank(finding.patchPriority) < priorityRank(row.priority)) row.priority = finding.patchPriority;
    map.set(key, row);
  }
  return [...map.values()]
    .map((row) => ({ ...row, assets: row.assets.size }))
    .sort((left, right) => right.open - left.open || priorityRank(left.priority) - priorityRank(right.priority) || left.name.localeCompare(right.name))
    .slice(0, 10);
}

function findingMap(findings = []) {
  const map = new Map();
  for (const finding of findings) {
    const existing = map.get(finding.findingKey);
    if (!existing) map.set(finding.findingKey, finding);
    else map.set(finding.findingKey, { ...existing, recordCount: weight(existing) + weight(finding) });
  }
  return map;
}

function removedCount(previousMap, currentMap) {
  let total = 0;
  for (const [key, finding] of previousMap) total += Math.max(0, weight(finding) - weight(currentMap.get(key)));
  return total;
}

function discoveredInPeriod(findings, reportDate) {
  if (!(reportDate instanceof Date) || Number.isNaN(reportDate.getTime())) return 0;
  return findings.filter((finding) => {
    const date = parseDate(finding.firstDiscovered);
    return date && date.getUTCFullYear() === reportDate.getUTCFullYear() && date.getUTCMonth() === reportDate.getUTCMonth();
  }).reduce((sum, finding) => sum + weight(finding), 0);
}

function weightedCounts(findings, key, labels) {
  const result = Object.fromEntries(labels.map((label) => [label, 0]));
  findings.forEach((finding) => {
    const label = labels.includes(finding[key]) ? finding[key] : labels.at(-1);
    result[label] += weight(finding);
  });
  return result;
}

function weightedTotal(findings) {
  let total = 0;
  for (const finding of findings) total += weight(finding);
  return total;
}

function weight(finding) {
  if (!finding) return 0;
  return Math.max(0, Number(finding.recordCount) || 1);
}

function assetLabel(finding) {
  return finding?.dnsName || finding?.ipAddress || finding?.image || "Unknown asset";
}

function ageDays(value, reportDate) {
  const date = parseDate(value);
  if (!date || !(reportDate instanceof Date) || Number.isNaN(reportDate.getTime())) return null;
  return Math.max(0, Math.floor((reportDate.getTime() - date.getTime()) / 86_400_000));
}

function inferReportDate(findings) {
  const values = findings.map((finding) => parseDate(finding.lastObserved || finding.firstDiscovered)).filter(Boolean).sort((left, right) => right - left);
  return values[0] ?? new Date();
}

function parseDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function priorityRank(priority) {
  return { P1: 1, P2: 2, P3: 3, P4: 4 }[priority] ?? 9;
}

function pageSize(doc) {
  return { width: doc.internal.pageSize.getWidth(), height: doc.internal.pageSize.getHeight() };
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function shortText(doc, value, width) {
  const text = String(value ?? "");
  if (doc.getTextWidth(text) <= width) return text;
  let output = text;
  while (output.length > 3 && doc.getTextWidth(`${output}...`) > width) output = output.slice(0, -1);
  return `${output}...`;
}

function drawArc(doc, centerX, centerY, radius, start, end) {
  const segments = Math.max(4, Math.ceil(Math.abs(end - start) * 16));
  let previous = { x: centerX + Math.cos(start) * radius, y: centerY + Math.sin(start) * radius };
  for (let index = 1; index <= segments; index += 1) {
    const angle = start + ((end - start) * index) / segments;
    const next = { x: centerX + Math.cos(angle) * radius, y: centerY + Math.sin(angle) * radius };
    doc.line(previous.x, previous.y, next.x, next.y);
    previous = next;
  }
}

function safeName(value) {
  return String(value || "MVA").replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "");
}
