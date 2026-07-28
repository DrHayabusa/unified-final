const COLORS = {
  navy: "14213D",
  slate: "334155",
  pale: "F8FAFC",
  border: "CBD5E1",
  white: "FFFFFF",
  teal: "0F766E",
  critical: "DC2626",
  high: "EA580C",
  medium: "CA8A04",
  low: "16A34A",
  P1: "DC2626",
  P2: "EA580C",
  P3: "CA8A04",
  P4: "16A34A",
};

const FINDING_COLUMNS = [
  ["IP Address", "ipAddress", 17],
  ["DNS Name", "dnsName", 30],
  ["Vulnerability Name", "vulnerabilityName", 44],
  ["CVE", "cve", 20],
  ["Severity", "severity", 12],
  ["Exploit Available", "exploitAvailable", 17],
  ["Patch Priority", "patchPriority", 14],
  ["Asset Exposure (on 1000)", "assetExposure", 23],
  ["Vulnerability Finding", "vulnerabilityFinding", 44],
  ["Summary", "summary", 40],
  ["Description", "description", 48],
  ["Remediation", "remediation", 48],
  ["KB Links", "kbLinks", 46],
  ["Platform Details", "platformDetails", 34],
  ["Namespace", "namespace", 20],
  ["Deployment", "deployment", 24],
  ["Image", "image", 42],
  ["Component", "component", 28],
  ["Fixable", "fixable", 12],
  ["CVE Fixed In", "fixedIn", 24],
  ["CVSS", "cvssScore", 11],
  ["First Discovered", "firstDiscovered", 17],
  ["Last Observed", "lastObserved", 17],
  ["Source Tools", "sourceDisplay", 34],
  ["Record Count", "recordCount", 14],
  ["Datacentre", "datacentre", 16],
  ["Times Detected", "timesDetected", 15],
  ["Vulnerability Status", "status", 20],
  ["Vendor Severity Rating", "vendorSeverityLabel", 22],
  ["Threat", "threat", 42],
  ["Impact", "impact", 42],
  ["Vulnerability Confidence", "vulnerabilityConfidence", 24],
  ["Exploit Evidence Source", "exploitEvidenceSource", 24],
];
const FINDING_COLUMN_INDEX = Object.fromEntries(FINDING_COLUMNS.map(([, key], index) => [key, index + 1]));

export async function downloadAnalysisWorkbook(analysis) {
  if (!analysis) throw new Error("Analyze an export before generating the Excel report.");
  const workbook = await buildAnalysisWorkbook(analysis);
  const buffer = await workbook.xlsx.writeBuffer();
  const suffix = isComparisonWorkflow(analysis)
    ? (analysis.dashboard.uploadedPeriods ?? analysis.dashboard.uploadedMonths).at(-1).replaceAll(" ", "_")
    : analysis.workflow === "quarterly-scan" ? "Quarterly_3_Month" : "Adhoc";
  saveBlob(new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `MVA_${safeName(analysis.sourceLabel)}_${suffix}_Report.xlsx`);
}

export async function buildAnalysisWorkbook(analysis) {
  if (!analysis) throw new Error("Analyze an export before generating the Excel report.");
  const { default: ExcelJS } = await import("exceljs");
  const workbook = new ExcelJS.Workbook();
  workbook.creator = "MVA Unified Agent";
  workbook.created = new Date();
  workbook.modified = new Date();
  workbook.subject = `${analysis.sourceLabel} vulnerability report`;

  await buildCoverSheet(workbook, analysis);
  await buildExecutiveDashboardSheet(workbook, analysis);
  if (analysis.dashboard?.unifiedInsights) await buildUnifiedDashboardSheet(workbook, analysis);
  if (analysis.dashboard?.qualysInsights) await buildQualysAnalysisSheet(workbook, analysis);
  if (isComparisonWorkflow(analysis)) await buildMonthlySheet(workbook, analysis);
  else await buildAdhocSheet(workbook, analysis);
  buildBriefingSheet(workbook, analysis);
  await buildTopAssetsSheet(workbook, analysis);
  await buildTopVulnerabilitiesSheet(workbook, analysis);
  buildFindingsSheet(workbook, isComparisonWorkflow(analysis) ? analysis.currentFindings : analysis.findings);
  if ((analysis.sourceIds?.length ?? analysis.inputSummary?.sourceCount ?? 0) > 1) buildSourceAuditSheet(workbook, analysis);
  return workbook;
}

async function buildCoverSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Cover Page", {
    properties: { tabColor: { argb: `FF${COLORS.critical}` } },
    views: [{ showGridLines: false }],
  });
  prepareSheet(sheet, 12);
  sheet.pageSetup = {
    orientation: "landscape",
    paperSize: 9,
    fitToPage: true,
    fitToWidth: 1,
    fitToHeight: 1,
    printArea: "A1:L32",
    margins: { left: 0.25, right: 0.25, top: 0.25, bottom: 0.25, header: 0.1, footer: 0.1 },
  };
  for (let row = 1; row <= 30; row += 1) {
    sheet.getRow(row).height = row <= 12 ? 26 : 22;
    for (let col = 1; col <= 12; col += 1) sheet.getCell(row, col).fill = solid(COLORS.navy);
  }
  await addWorkbookBrandLogo(workbook, sheet);
  sheet.mergeCells("I2:L3");
  const productCell = sheet.getCell("I2");
  productCell.value = "MVA";
  productCell.font = { name: "Aptos Display", bold: true, size: 26, color: { argb: `FF${COLORS.white}` } };
  productCell.alignment = { horizontal: "right", vertical: "middle" };

  sheet.mergeCells("A6:L8");
  const heading = sheet.getCell("A6");
  heading.value = "Vulnerability Analysis Report";
  heading.font = { name: "Aptos Display", bold: true, size: 30, color: { argb: `FF${COLORS.white}` } };
  heading.alignment = { vertical: "middle", horizontal: "left" };
  sheet.mergeCells("A9:L10");
  const subtitle = sheet.getCell("A9");
  subtitle.value = `${reportSourceLabel(analysis.sourceLabel)} | ${reportPeriodLabel(analysis)}`;
  subtitle.font = { name: "Aptos", size: 13, color: { argb: "FFCBD5E1" } };
  subtitle.alignment = { vertical: "middle" };
  for (let col = 1; col <= 12; col += 1) {
    sheet.getCell(11, col).fill = solid(COLORS.critical);
    sheet.getCell(11, col).border = {};
  }
  sheet.getRow(11).height = 5;

  sheet.mergeCells("A14:L14");
  const contentsHeading = sheet.getCell("A14");
  contentsHeading.value = "REPORT CONTENTS";
  contentsHeading.font = { name: "Aptos", bold: true, size: 10, color: { argb: "FFFCA5A5" } };
  contentsHeading.alignment = { vertical: "middle" };

  const contents = [
    ["Executive Dashboard", "Executive Dashboard"],
    ...(analysis.dashboard?.unifiedInsights ? [["Consolidated Analysis", "Unified Dashboard"]] : []),
    ...(analysis.dashboard?.qualysInsights ? [["Qualys Operational Analysis", "Qualys Analysis"]] : []),
    [isComparisonWorkflow(analysis) ? `${analysis.workflow === "quarterly" ? "Quarterly" : "Monthly"} Report` : analysis.workflow === "quarterly-scan" ? "Quarterly Report" : "Adhoc Report", reportSheetName(analysis)],
    ["Briefing", "Briefing"],
    ["Top Vulnerable Assets", "Top Vulnerable Assets"],
    ["Top Vulnerabilities", "Top Vulnerabilities"],
    ["Normalized Report Data", "Report Data"],
    ...((analysis.sourceIds?.length ?? analysis.inputSummary?.sourceCount ?? 0) > 1 ? [["Source Audit", "Source Audit"]] : []),
  ];
  const targets = contents.map(([label, sheetName], index) => [String(index + 1).padStart(2, "0"), label, sheetName]);
  targets.forEach(([number, label], index) => {
    const row = 16 + index * 2;
    sheet.mergeCells(row, 1, row, 2);
    sheet.getCell(row, 1).value = number;
    sheet.getCell(row, 1).font = { name: "Aptos Display", bold: true, size: 15, color: { argb: "FFFCA5A5" } };
    sheet.getCell(row, 1).alignment = { vertical: "middle" };
    sheet.mergeCells(row, 3, row, 12);
    const link = sheet.getCell(row, 3);
    link.value = label;
    link.font = { name: "Aptos", bold: true, size: 12, color: { argb: `FF${COLORS.white}` } };
    link.alignment = { vertical: "middle" };
    for (let col = 1; col <= 12; col += 1) {
      sheet.getCell(row + 1, col).border = { bottom: { style: "hair", color: { argb: "FF475569" } } };
    }
  });
}

async function buildExecutiveDashboardSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Executive Dashboard", {
    properties: { tabColor: { argb: `FF${COLORS.teal}` } },
    views: [{ state: "frozen", ySplit: 3, showGridLines: false }],
  });
  const summary = workbookSummary(analysis);
  prepareSheet(sheet, 12);
  sheet.pageSetup = {
    orientation: "landscape",
    paperSize: 9,
    fitToPage: true,
    fitToWidth: 1,
    fitToHeight: 1,
    horizontalCentered: true,
    printArea: "A1:L40",
    margins: { left: 0.2, right: 0.2, top: 0.35, bottom: 0.35, header: 0.15, footer: 0.15 },
  };
  title(sheet, "Executive Dashboard", `${reportSourceLabel(analysis.sourceLabel)} | ${reportPeriodLabel(analysis)}`, 12);
  kpi(sheet, "A4:C7", "TOTAL OPEN", summary.totalOpen, "Current unresolved findings", COLORS.navy);
  kpi(sheet, "D4:F7", "CRITICAL", summary.severity.Critical, "Critical severity findings", COLORS.critical);
  kpi(sheet, "G4:I7", "HIGH", summary.severity.High, "High severity findings", COLORS.high);
  kpi(sheet, "J4:L7", "IMMEDIATE PATCH", summary.immediatePatch, "P1 + P2 findings", COLORS.critical);

  section(sheet, "A9:F9", "Severity Distribution");
  writeTable(sheet, 10, 1, ["Severity", "Open Findings"], Object.entries(summary.severity).filter(([, count]) => count > 0));
  section(sheet, "G9:L9", "Patch Priority Distribution");
  writeTable(sheet, 10, 7, ["Patch Priority", "Open Findings"], Object.entries(summary.priority), true);
  await addBarChartImage(
    workbook,
    sheet,
    Object.entries(summary.severity).filter(([, value]) => value > 0).map(([label, value]) => ({ label, value, color: `#${COLORS[label.toLowerCase()] ?? COLORS.slate}` })),
    "Open Findings by Severity",
    { col: 0.3, row: 16, width: 560, height: 220 },
  );
  await addBarChartImage(
    workbook,
    sheet,
    Object.entries(summary.priority).map(([label, value]) => ({ label, value, color: `#${COLORS[label]}` })),
    "Open Findings by Patch Priority",
    { col: 6.2, row: 16, width: 560, height: 220 },
  );
  section(sheet, "A29:L29", "Executive Observations");
  const observations = [
    `${summary.immediatePatch.toLocaleString()} of ${summary.totalOpen.toLocaleString()} open findings require P1 or P2 handling.`,
    `${summary.exploitAvailable.toLocaleString()} findings contain positive exploit-availability evidence in the selected scanner exports.`,
    `${summary.distinctAssets.toLocaleString()} unique normalized assets or workloads are affected.`,
  ];
  if (analysis.dashboard?.openshiftInsights) {
    observations.push(`${analysis.dashboard.openshiftInsights.fixable.toLocaleString()} OpenShift findings have fix availability evidence; Fixable is not treated as exploit evidence.`);
  }
  observations.forEach((observation, index) => {
    sheet.mergeCells(31 + index * 2, 1, 31 + index * 2, 12);
    const cell = sheet.getCell(31 + index * 2, 1);
    cell.value = `- ${observation}`;
    cell.font = { name: "Aptos", size: 11, color: { argb: `FF${COLORS.slate}` } };
    cell.fill = solid(index % 2 === 0 ? "F8FAFC" : "F1F5F9");
    cell.alignment = { vertical: "middle", wrapText: true };
  });
}

async function buildQualysAnalysisSheet(workbook, analysis) {
  const insights = analysis.dashboard.qualysInsights;
  const customProfile = String(analysis.sourceLabel).toLowerCase().includes("custom qualys");
  const ratings = orderedQualysRatings(insights.vendorRatings, customProfile);
  const datacentres = insights.datacentres ?? [];
  const statuses = insights.statuses ?? [];
  const sheet = workbook.addWorksheet("Qualys Analysis", {
    properties: { tabColor: { argb: `FF${COLORS.high}` } },
    views: [{ state: "frozen", ySplit: 3, showGridLines: false }],
  });
  prepareSheet(sheet, 12);
  sheet.pageSetup = {
    orientation: "landscape",
    paperSize: 9,
    fitToPage: true,
    fitToWidth: 1,
    fitToHeight: 1,
    printArea: "A1:L40",
    margins: { left: 0.2, right: 0.2, top: 0.35, bottom: 0.35, header: 0.15, footer: 0.15 },
  };
  title(
    sheet,
    customProfile ? "Custom Qualys Operational Analysis" : "Qualys Operational Analysis",
    `${reportPeriodLabel(analysis)} | Source-native categorization`,
    12,
  );
  kpi(sheet, "A4:C7", "OPEN FINDINGS", insights.totalOpen, "Current Qualys findings", COLORS.navy);
  kpi(sheet, "D4:F7", "REPEATED FINDINGS", insights.repeatedFindings, "Times Detected greater than 1", COLORS.high);
  kpi(sheet, "G4:I7", "DETECTION EVENTS", insights.detectionEvents, "Sum of Times Detected", "0284C7");
  kpi(
    sheet,
    "J4:L7",
    "DATACENTRES",
    datacentres.filter((row) => row.datacentre !== "Not supplied").length,
    "Distinct supplied categories",
    COLORS.teal,
  );

  section(sheet, "A9:F9", "Datacentre Distribution");
  writeTable(sheet, 10, 1, ["Datacentre", "Open Findings"], datacentres.map((row) => [row.datacentre, row.vulnerabilityCount]));
  section(sheet, "G9:L9", customProfile ? "Custom Qualys Rating Distribution" : "Qualys Vendor Rating Distribution");
  writeTable(sheet, 10, 7, ["Source Rating", "Open Findings"], ratings.map((row) => [row.rating, row.vulnerabilityCount]));

  await addBarChartImage(
    workbook,
    sheet,
    datacentres.slice(0, 8).map((row) => ({ label: row.datacentre, value: row.vulnerabilityCount, color: "#0284C7" })),
    "Open Findings by Datacentre",
    { col: 0.3, row: 18, width: 560, height: 220 },
  );
  await addBarChartImage(
    workbook,
    sheet,
    ratings.map((row) => ({ label: row.rating, value: row.vulnerabilityCount, color: qualysRatingColor(row.rating) })),
    customProfile ? "5 Urgent / 4 Critical / 3 Serious / 2 Medium / 1 Minimal" : "Open Findings by Qualys Rating",
    { col: 6.2, row: 18, width: 560, height: 220 },
  );

  section(sheet, "A31:L31", "Vulnerability Lifecycle Status");
  writeTable(sheet, 32, 1, ["Vulnerability Status", "Open Findings"], statuses.map((row) => [row.status, row.vulnerabilityCount]));
  sheet.getColumn(1).width = 24;
  sheet.getColumn(2).width = 16;
  sheet.getColumn(7).width = 28;
  sheet.getColumn(8).width = 16;
}

function orderedQualysRatings(rows = [], customProfile = false) {
  const counts = new Map(rows.map((row) => [String(row.rating), Number(row.vulnerabilityCount) || 0]));
  const labels = customProfile
    ? ["5 - Urgent", "4 - Critical", "3 - Serious", "2 - Medium", "1 - Minimal"]
    : ["5 - Critical", "4 - High", "3 - Medium", "2 - Low", "1 - Minimal"];
  return labels.map((rating) => ({ rating, vulnerabilityCount: counts.get(rating) ?? 0 }));
}

function qualysRatingColor(label) {
  if (label.startsWith("5 -") || label.startsWith("4 - Critical")) return `#${COLORS.critical}`;
  if (label.startsWith("4 -") || label.startsWith("3 - Serious")) return `#${COLORS.high}`;
  if (label.startsWith("3 -") || label.startsWith("2 - Medium")) return `#${COLORS.medium}`;
  return `#${COLORS.low}`;
}

function buildBriefingSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Briefing", { views: [{ showGridLines: false }] });
  const summary = workbookSummary(analysis);
  prepareSheet(sheet, 12);
  sheet.pageSetup = { orientation: "landscape", paperSize: 9, fitToPage: true, fitToWidth: 1, fitToHeight: 1, printArea: "A1:L35" };
  title(sheet, "Executive Briefing", `${reportSourceLabel(analysis.sourceLabel)} | ${reportPeriodLabel(analysis)}`, 12);

  section(sheet, "A4:L4", "Priority Summary");
  writeTable(sheet, 5, 1, ["Measure", "Value", "Interpretation"], [
    ["Total open vulnerabilities", summary.totalOpen, "Current unresolved normalized findings"],
    ["Immediate patch needed", summary.immediatePatch, "P1 + P2 findings"],
    ["Critical vulnerabilities", summary.severity.Critical, "Critical source severity"],
    ["Exploit available", summary.exploitAvailable, "Positive scanner evidence"],
    ["Affected assets", summary.distinctAssets, "Unique assets or workloads"],
  ]);
  sheet.getColumn(1).width = 30;
  sheet.getColumn(2).width = 16;
  sheet.getColumn(3).width = 48;

  section(sheet, "A13:F13", "Urgent Actions");
  const urgent = [
    "Prioritize P1 findings, then P2 findings, using approved change windows.",
    "Validate exploit evidence and affected asset identity before remediation.",
    "Retest remediated assets and retain follow-up scan evidence.",
  ];
  urgent.forEach((text, index) => {
    sheet.mergeCells(15 + index * 3, 1, 16 + index * 3, 6);
    const cell = sheet.getCell(15 + index * 3, 1);
    cell.value = `${index + 1}. ${text}`;
    cell.fill = solid(index % 2 === 0 ? "FEF2F2" : "FFF7ED");
    cell.font = { name: "Aptos", bold: true, size: 10, color: { argb: `FF${COLORS.navy}` } };
    cell.alignment = { vertical: "middle", wrapText: true };
  });
  section(sheet, "H13:L13", "Patch Priority Matrix");
  writeTable(sheet, 14, 8, ["Severity", "Exploit Available", "No Exploit"], [
    ["Critical", "P1", "P2"],
    ["High", "P1", "P2"],
    ["Medium", "P2", "P3"],
    ["Low", "P2", "P4"],
  ]);
  ["I", "J"].forEach((letter) => {
    for (let row = 15; row <= 18; row += 1) {
      const cell = sheet.getCell(`${letter}${row}`);
      if (COLORS[cell.value]) {
        cell.fill = solid(COLORS[cell.value]);
        cell.font = { bold: true, color: { argb: `FF${COLORS.white}` } };
        cell.alignment = { horizontal: "center" };
      }
    }
  });
  section(sheet, "A26:L26", "Calculation Notes");
  const notes = [
    "Total Open = New findings + findings not closed from the previous comparable report.",
    "Patched = Previous Open + New - Current Open, reconciled by the normalized finding key.",
    "Finding key = asset + vulnerability + protocol + port/service; different vulnerabilities on the same asset remain separate.",
    "Age thresholds are cumulative. OpenShift Fixable indicates remediation availability and does not change exploit availability.",
  ];
  notes.forEach((text, index) => {
    sheet.mergeCells(28 + index, 1, 28 + index, 12);
    const cell = sheet.getCell(28 + index, 1);
    cell.value = text;
    cell.font = { name: "Aptos", size: 9, color: { argb: `FF${COLORS.slate}` } };
  });
}

async function buildTopAssetsSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Top Vulnerable Assets", { views: [{ state: "frozen", ySplit: 4, showGridLines: false }] });
  const rows = aggregateAssets(workbookFindings(analysis));
  prepareSheet(sheet, 12);
  sheet.pageSetup = { orientation: "landscape", paperSize: 9, fitToPage: true, fitToWidth: 1, fitToHeight: 1, printArea: "A1:L22" };
  title(sheet, "Top Vulnerable Assets", `${reportSourceLabel(analysis.sourceLabel)} | ${reportPeriodLabel(analysis)}`, 12);
  writeTable(sheet, 4, 1, ["IP Address", "DNS / Workload", "Critical", "High", "P1 + P2", "Open Findings", "Max Exposure"], rows.slice(0, 15).map((row) => [
    row.ipAddress || "N/A",
    row.dnsName || row.asset,
    row.critical,
    row.high,
    row.immediatePatch,
    row.totalOpen,
    row.maxExposure,
  ]));
  sheet.getColumn(1).width = 18;
  sheet.getColumn(2).width = 34;
  await addBarChartImage(
    workbook,
    sheet,
    rows.slice(0, 10).map((row, index) => ({ label: `#${index + 1}`, value: row.totalOpen, color: `#${COLORS.critical}` })),
    "Top 10 Affected Assets (ranked as table)",
    { col: 7.2, row: 3.3, width: 470, height: 320 },
  );
}

async function buildTopVulnerabilitiesSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Top Vulnerabilities", { views: [{ state: "frozen", ySplit: 4, showGridLines: false }] });
  const rows = aggregateVulnerabilities(workbookFindings(analysis));
  prepareSheet(sheet, 12);
  sheet.pageSetup = { orientation: "landscape", paperSize: 9, fitToPage: true, fitToWidth: 1, fitToHeight: 1, printArea: "A1:L22" };
  title(sheet, "Top Vulnerabilities", `${reportSourceLabel(analysis.sourceLabel)} | ${reportPeriodLabel(analysis)}`, 12);
  writeTable(sheet, 4, 1, ["Vulnerability", "CVE", "Open Findings", "Affected Assets", "Highest Priority", "Exploit Available", "Max Exposure"], rows.slice(0, 15).map((row) => [
    row.vulnerability,
    row.cve || "N/A",
    row.totalOpen,
    row.affectedAssets,
    row.priority,
    row.exploitAvailable,
    row.maxExposure,
  ]));
  sheet.getColumn(1).width = 44;
  sheet.getColumn(2).width = 20;
  await addBarChartImage(
    workbook,
    sheet,
    rows.slice(0, 10).map((row, index) => ({ label: `#${index + 1}`, value: row.totalOpen, color: `#${COLORS.high}` })),
    "Top 10 Vulnerabilities (ranked as table)",
    { col: 7.2, row: 3.3, width: 470, height: 320 },
  );
}

async function buildUnifiedDashboardSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Unified Dashboard", { views: [{ state: "frozen", ySplit: 3, showGridLines: false }] });
  const dashboard = analysis.dashboard;
  const insights = dashboard.unifiedInsights;
  const historical = (dashboard.unifiedTrend?.length ?? 0) > 1;
  const latestSummary = analysis.snapshots?.at(-1)?.inputSummary ?? analysis.inputSummary ?? {};
  const periodLabel = dashboard.reportRange ?? analysis.reportMonth ?? analysis.reportPeriod ?? "Current report";
  prepareSheet(sheet, 16);
  sheet.pageSetup = { orientation: "landscape", fitToPage: true, fitToWidth: 1, fitToHeight: 0, margins: { left: 0.25, right: 0.25, top: 0.5, bottom: 0.5, header: 0.2, footer: 0.2 } };
  sheet.getColumn(1).width = 28;
  sheet.getColumn(9).width = 32;
  sheet.getColumn(10).width = 20;
  title(sheet, "Unified Multi-Tool Consolidated Analysis", `${periodLabel} | ${analysis.sourceIds?.length ?? latestSummary.sourceCount ?? 0} selected tools`, 16);

  kpi(sheet, "A4:D7", "CONSOLIDATED OPEN", insights.totalOpen, "Unique asset + vulnerability + service", COLORS.teal);
  kpi(sheet, "E4:H7", "AFFECTED ASSETS", insights.distinctAssets, "Unique consolidated assets", "0284C7");
  kpi(sheet, "I4:L7", "IMMEDIATE PATCH", insights.immediatePatch, "P1 + P2 findings", COLORS.critical);
  kpi(sheet, "M4:P7", "EXPLOIT AVAILABLE", insights.exploitAvailable, "Positive exploit evidence", COLORS.high);
  kpi(sheet, "A9:D12", "CONFIRMED BY MULTIPLE TOOLS", insights.crossToolConfirmed, "Same finding reported by 2+ tools", COLORS.low);
  kpi(sheet, "E9:H12", "REPORTED BY ONE TOOL", insights.singleSourceOnly, "Seen in exactly one selected tool", "0284C7");
  kpi(sheet, "I9:L12", "CONFIRMATION RATE", `${insights.confirmationRate}%`, "Multi-tool confirmed / open", "0891B2");
  kpi(sheet, "M9:P12", "REPEATS REMOVED", latestSummary.duplicatesRemoved ?? 0, "Repeated source observations", COLORS.high);

  let detailStartRow;
  if (historical) {
    section(sheet, "A14:P14", "Consolidated Analysis Trend");
    writeTable(
      sheet,
      15,
      1,
      ["Period", "Total Open", "New", "Patched", "P1", "P2", "P3", "P4", "Confirmed by Multiple Tools", "Reported by One Tool", "Exploit Available", "Repeats Removed"],
      dashboard.unifiedTrend.map((row) => [row.period, row.totalOpen, row.newFindings, row.patchedFindings, row.P1, row.P2, row.P3, row.P4, row.crossToolConfirmed, row.singleSourceOnly, row.exploitable, row.repeatsRemoved]),
    );
    const chartRow = 17 + dashboard.unifiedTrend.length;
    await addMultiLineChartImage(
      workbook,
      sheet,
      [
        { name: "Total Open", color: "#DC2626", points: dashboard.unifiedTrend.map((row) => ({ label: row.period, value: row.totalOpen })) },
        { name: "New", color: "#0284C7", points: dashboard.unifiedTrend.map((row) => ({ label: row.period, value: row.newFindings })) },
        { name: "Patched", color: "#16A34A", points: dashboard.unifiedTrend.map((row) => ({ label: row.period, value: row.patchedFindings })) },
      ],
      "Consolidated Vulnerability Trend",
      { col: 0.3, row: chartRow - 0.5, width: 610, height: 250 },
    );
    await addMultiLineChartImage(
      workbook,
      sheet,
      Object.entries(COLORS).filter(([key]) => /^P[1-4]$/.test(key)).map(([priority, color]) => ({
        name: priority,
        color: `#${color}`,
        points: dashboard.unifiedTrend.map((row) => ({ label: row.period, value: row[priority] })),
      })),
      "Patch Priority Movement",
      { col: 8.1, row: chartRow - 0.5, width: 610, height: 250 },
    );
    detailStartRow = chartRow + 14;
  } else {
    section(sheet, "A14:H14", "Findings by Number of Reporting Tools");
    writeTable(sheet, 15, 1, ["Reporting Tool Count", "Open Findings"], insights.sourceAgreementDistribution.map((row) => [row.label, row.findingCount]));
    section(sheet, "I14:P14", "Consolidated Priority Distribution");
    writeTable(sheet, 15, 9, ["Patch Priority", "Open Findings"], Object.entries(insights.patchPriorityCounts), true);
    const chartRow = 21;
    await addBarChartImage(workbook, sheet, insights.sourceAgreementDistribution.map((row) => ({ label: row.label, value: row.findingCount, color: "#16A34A" })), "Findings by Number of Reporting Tools", { col: 0.3, row: chartRow - 0.5, width: 610, height: 250 });
    await addBarChartImage(workbook, sheet, Object.entries(insights.patchPriorityCounts).map(([label, value]) => ({ label, value, color: `#${COLORS[label]}` })), "Consolidated Priority Distribution", { col: 8.1, row: chartRow - 0.5, width: 610, height: 250 });
    detailStartRow = chartRow + 14;
  }

  section(sheet, `A${detailStartRow}:G${detailStartRow}`, "Highest-Risk Assets");
  writeTable(
    sheet,
    detailStartRow + 1,
    1,
    ["Asset", "Open", "P1 + P2", "Critical", "Exploit Available", "Sources", "Exposure"],
    insights.topRiskAssets.map((row) => [row.asset, row.totalOpen, row.immediatePatch, row.critical, row.exploitAvailable, row.sourceCount, row.maxExposure]),
  );
  section(sheet, `I${detailStartRow}:P${detailStartRow}`, "Highest-Impact Vulnerabilities");
  writeTable(
    sheet,
    detailStartRow + 1,
    9,
    ["Vulnerability", "CVE", "Open", "Assets", "P1 + P2", "Exploit Available", "Sources", "Exposure"],
    insights.topVulnerabilities.map((row) => [row.vulnerability, row.cve || "N/A", row.totalOpen, row.affectedAssets, row.immediatePatch, row.exploitAvailable, row.sourceCount, row.maxExposure]),
  );

  const sourceStartRow = detailStartRow + Math.max(insights.topRiskAssets.length, insights.topVulnerabilities.length) + 3;
  section(sheet, `A${sourceStartRow}:H${sourceStartRow}`, "Tool Contribution");
  writeTable(
    sheet,
    sourceStartRow + 1,
    1,
    ["Tool", "Observed", "Assets", "P1 + P2", "Critical", "Exploit Available", "Confirmed by Multiple Tools", "Reported Only by This Tool"],
    (dashboard.sourceBreakdown ?? []).map((source) => [source.sourceLabel, source.openFindings, source.affectedAssets, source.immediatePatch, source.criticalFindings, source.exploitAvailable, source.crossToolConfirmed, source.exclusiveFindings]),
  );
  section(sheet, `J${sourceStartRow}:P${sourceStartRow}`, "Tool Pair Confirmation");
  writeTable(sheet, sourceStartRow + 1, 10, ["Tool Pair", "Confirmed Findings"], insights.sourcePairOverlap.map((row) => [row.sourcePair, row.findingCount]));
}

export function downloadNormalizedCsv(analysis) {
  if (!analysis) throw new Error("Analyze an export before downloading normalized findings.");
  const findings = isComparisonWorkflow(analysis) ? analysis.currentFindings : analysis.findings;
  const rows = [FINDING_COLUMNS.map(([header]) => header)];
  for (const finding of findings) {
    rows.push(FINDING_COLUMNS.map(([, key]) => ["exploitAvailable", "fixable"].includes(key) ? (finding[key] ? "Yes" : "No") : finding[key] ?? ""));
  }
  const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  saveBlob(new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" }), `MVA_${safeName(analysis.sourceLabel)}_Normalized_Findings.csv`);
}

async function buildMonthlySheet(workbook, analysis) {
  const quarterly = analysis.workflow === "quarterly";
  const singular = quarterly ? "Quarter" : "Month";
  const plural = quarterly ? "Quarters" : "Months";
  const sheet = workbook.addWorksheet(`${singular}ly Report`, { views: [{ state: "frozen", ySplit: 3, showGridLines: false }] });
  const dashboard = analysis.dashboard;
  const open = dashboard.totalOpenVulnerabilities;
  const patched = dashboard.totalVulnerabilitiesPatchedLastPeriod ?? dashboard.totalVulnerabilitiesPatchedLastMonth;
  prepareSheet(sheet, 12);
  sheet.pageSetup = {
    orientation: "landscape",
    paperSize: 9,
    fitToPage: true,
    fitToWidth: 1,
    fitToHeight: 1,
    horizontalCentered: true,
    printArea: "A1:L41",
    margins: { left: 0.2, right: 0.2, top: 0.35, bottom: 0.35, header: 0.15, footer: 0.15 },
  };
  sheet.getColumn(7).width = 24;
  sheet.getColumn(8).width = 16;
  sheet.getColumn(9).width = 20;
  title(sheet, `${reportSourceLabel(analysis.sourceLabel)} ${singular}ly Vulnerability Report`, dashboard.reportRange, 12);

  kpi(sheet, "A4:C7", "TOTAL OPEN", open.totalOpen, "New + not closed", COLORS.teal);
  kpi(sheet, "D4:F7", `NEW THIS ${singular.toUpperCase()}`, open.newVulnerabilities, "Identified in current report", "0284C7");
  kpi(sheet, "G4:I7", "NOT CLOSED", open.notClosedFromPreviousMonths, "Carried from previous report", COLORS.high);
  kpi(sheet, "J4:L7", `PATCHED LAST ${singular.toUpperCase()}`, patched.patchedCount, `${patched.previousPeriod} to ${patched.currentPeriod}`, COLORS.low);

  const discoveredTrend = (dashboard.trendDiscoveredLast3Periods ?? dashboard.trendDiscoveredLast3Months).map((row) => ({ label: row.period ?? row.month, value: row.discoveredCount }));
  const remediatedTrend = (dashboard.trendRemediatedLast3Periods ?? dashboard.trendRemediatedLast3Months).map((row) => ({ label: row.period ?? row.month, value: row.remediatedCount }));
  section(sheet, "A9:C9", `Vulnerability Trend - Last 3 ${plural}`);
  writeTable(
    sheet,
    10,
    1,
    [singular, "Discovered", "Remediated"],
    discoveredTrend.map((row, index) => [row.label, row.value, remediatedTrend[index]?.value ?? 0]),
  );
  await addLineChartImage(workbook, sheet, discoveredTrend, "Vulnerabilities Discovered", "#2563EB", { col: 3, row: 8, width: 490, height: 220 });
  await addLineChartImage(workbook, sheet, remediatedTrend, "Vulnerabilities Remediated", "#16A34A", { col: 8, row: 8, width: 390, height: 220 });

  section(sheet, "A21:L21", "Total Open by Patch Priority");
  ["P1", "P2", "P3", "P4"].forEach((priority, index) => {
    const start = 1 + index * 3;
    kpi(sheet, `${column(start)}22:${column(start + 2)}25`, priority, dashboard.totalOpenByPatchPriority[priority], "Open findings", COLORS[priority]);
  });

  section(sheet, "A27:F27", "Total Open by Age and Patch Priority");
  writeTable(
    sheet,
    28,
    1,
    ["Patch Priority", ">7 days", ">30 days", ">60 days", ">180 days"],
    ["P1", "P2", "P3", "P4"].map((priority) => [
      priority,
      dashboard.totalOpenByAgeAndPatchPriority[priority][">7 days"],
      dashboard.totalOpenByAgeAndPatchPriority[priority][">30 days"],
      dashboard.totalOpenByAgeAndPatchPriority[priority][">60 days"],
      dashboard.totalOpenByAgeAndPatchPriority[priority][">180 days (6+ months)"],
    ]),
    true,
  );

  section(sheet, "G27:L27", `Vulnerabilities Patched in Last ${singular}`);
  writeTable(sheet, 28, 7, ["Measure", "Count", `Report ${singular}`], [
    [`Previous ${singular} Open`, patched.previousPeriodOpen, patched.previousPeriod],
    [`New This ${singular}`, patched.newVulnerabilitiesIdentifiedThisPeriod, patched.currentPeriod],
    [`Current ${singular} Open`, patched.currentPeriodOpen, patched.currentPeriod],
    [`Patched Last ${singular}`, patched.patchedCount, patched.currentPeriod],
  ]);

  section(sheet, "A35:L35", `Uploaded ${singular} Summary`);
  writeTable(
    sheet,
    36,
    1,
    [singular, "Critical", "High", "Medium", "Low", "Total Open", "New", "Patched"],
    dashboard.severityTrend.map((row, index) => [
      row.month,
      row.Critical,
      row.High,
      row.Medium,
      row.Low,
      row.totalOpen,
      dashboard.openTrend[index].newThisMonth,
      dashboard.openTrend[index].patchedSinceLastMonth,
    ]),
  );

}

function isComparisonWorkflow(analysis) {
  return analysis?.workflow === "monthly" || analysis?.workflow === "quarterly";
}

async function buildAdhocSheet(workbook, analysis) {
  const quarterly = analysis.workflow === "quarterly-scan";
  const sheet = workbook.addWorksheet(quarterly ? "Quarterly Report" : "Adhoc Report", { views: [{ state: "frozen", ySplit: 3, showGridLines: false }] });
  const dashboard = analysis.dashboard;
  prepareSheet(sheet, 12);
  sheet.pageSetup = {
    orientation: "landscape",
    paperSize: 9,
    fitToPage: true,
    fitToWidth: 1,
    fitToHeight: 1,
    horizontalCentered: true,
    printArea: "A1:L50",
    margins: { left: 0.2, right: 0.2, top: 0.35, bottom: 0.35, header: 0.15, footer: 0.15 },
  };
  title(sheet, `${reportSourceLabel(analysis.sourceLabel)} ${quarterly ? "Quarterly 3-Month" : "Adhoc"} Vulnerability Report`, `${quarterly ? `${analysis.reportPeriod} | ` : ""}${analysis.exportType} | ${analysis.fileName}`, 12);
  kpi(sheet, "A4:C7", "TOTAL VULNERABILITIES", dashboard.totalVulnerabilities, "Open findings", COLORS.teal);
  kpi(sheet, "D4:F7", "DISTINCT ASSETS", dashboard.distinctAssets, "Affected assets", "0284C7");
  kpi(sheet, "G4:I7", "EXPLOIT AVAILABLE", dashboard.exploitAvailable, "Known exploit signal", COLORS.high);
  kpi(sheet, "J4:L7", "IMMEDIATE PATCH", (dashboard.patchPriorityCounts.P1 ?? 0) + (dashboard.patchPriorityCounts.P2 ?? 0), "P1 + P2", COLORS.critical);

  section(sheet, "A9:F9", "Severity Distribution");
  writeTable(sheet, 10, 1, ["Severity", "Count"], Object.entries(dashboard.severityCounts));
  section(sheet, "G9:L9", "Patch Priority Distribution");
  writeTable(sheet, 10, 7, ["Patch Priority", "Count"], Object.entries(dashboard.patchPriorityCounts), true);

  section(sheet, "A19:F19", "Top 10 Affected Assets");
  const affectedAssets = dashboard.top10AffectedAssets.map((row) => [row.asset, row.vulnerabilityCount]);
  writeAffectedAssetsTable(sheet, 20, affectedAssets);
  section(sheet, "G19:L19", "Affected Asset Concentration");
  writeAssetConcentration(sheet, 20, affectedAssets, COLORS.critical);

  const lineSeries = quarterly
    ? {
      title: "Vulnerabilities Discovered - Last 3 Months",
      points: dashboard.quarterlyDiscoveryTrend.map((row) => ({ label: row.month, value: row.discoveredCount })),
    }
    : dashboard.adhocLineSeries;
  section(sheet, "A32:L32", lineSeries.title);
  await addLineChartImage(
    workbook,
    sheet,
    lineSeries.points,
    lineSeries.title,
    "#DC2626",
    { col: 0.5, row: 32.5, width: 720, height: 288 },
  );
}

function buildFindingsSheet(workbook, findings) {
  const sheet = workbook.addWorksheet("Report Data", { views: [{ state: "frozen", ySplit: 1, xSplit: 2, showGridLines: false }] });
  sheet.columns = FINDING_COLUMNS.map(([header, key, width]) => ({ header, key, width }));
  const rows = findings.map((finding) => Object.fromEntries(FINDING_COLUMNS.map(([, key]) => [key, findingCellValue(finding, key)])));
  sheet.addRows(rows);
  styleHeader(sheet.getRow(1));
  sheet.autoFilter = { from: "A1", to: `${column(FINDING_COLUMNS.length)}${Math.max(1, rows.length + 1)}` };
  sheet.getColumn(FINDING_COLUMN_INDEX.assetExposure).numFmt = "0";
  sheet.getColumn(FINDING_COLUMN_INDEX.cvssScore).numFmt = "0.0";
  sheet.getColumn(FINDING_COLUMN_INDEX.recordCount).numFmt = "0";
  sheet.getColumn(FINDING_COLUMN_INDEX.timesDetected).numFmt = "0";
  sheet.eachRow((row, rowNumber) => {
    if (rowNumber === 1) return;
    row.alignment = { vertical: "top", wrapText: false };
    row.height = 18;
    if (rowNumber % 2 === 0) row.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF8FAFC" } };
    const severity = row.getCell(FINDING_COLUMN_INDEX.severity);
    const severityColor = COLORS[String(severity.value).toLowerCase()] ?? COLORS.slate;
    severity.font = { bold: true, color: { argb: `FF${severityColor}` } };
    const priority = row.getCell(FINDING_COLUMN_INDEX.patchPriority);
    const priorityColor = COLORS[priority.value] ?? COLORS.slate;
    priority.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${priorityColor}` } };
    priority.font = { bold: true, color: { argb: `FF${COLORS.white}` } };
  });
}

function buildSourceAuditSheet(workbook, analysis) {
  const sheet = workbook.addWorksheet("Source Audit", { views: [{ state: "frozen", ySplit: 4, showGridLines: false }] });
  prepareSheet(sheet, 9);
  [24, 18, 18, 15, 15, 18, 22, 18, 14].forEach((width, index) => { sheet.getColumn(index + 1).width = width; });
  title(sheet, "Unified Multi-Tool Source Audit", analysis.dashboard?.reportRange ?? analysis.reportMonth ?? analysis.reportPeriod ?? "Current report", 9);
  const summary = analysis.inputSummary ?? {};
  const latestSummary = analysis.snapshots?.at(-1)?.inputSummary ?? summary;
  kpi(sheet, "A4:B7", "INPUT FILES", summary.fileCount ?? 0, "All uploaded periods", "0284C7");
  kpi(sheet, "C4:D7", "TOOL SOURCES", summary.sourceCount ?? analysis.sourceIds?.length ?? 0, "Selected and detected", COLORS.high);
  kpi(sheet, "E4:G7", "CONSOLIDATED OPEN", latestSummary.consolidatedOpenFindings ?? analysis.dashboard?.totalVulnerabilities ?? analysis.dashboard?.totalOpenVulnerabilities?.totalOpen ?? 0, "Latest/current report", COLORS.teal);
  kpi(sheet, "H4:I7", "REPEATS REMOVED", latestSummary.duplicatesRemoved ?? 0, "Latest/current report", COLORS.critical);

  section(sheet, "A9:I9", "Per-Source Coverage");
  const sourceRows = (analysis.dashboard?.sourceBreakdown ?? []).map((source) => [
    source.sourceLabel,
    source.openFindings,
    source.affectedAssets,
    source.immediatePatch,
    source.criticalFindings,
    source.exploitAvailable,
    source.crossToolConfirmed,
    source.exclusiveFindings,
  ]);
  writeTable(sheet, 10, 1, ["Tool Source", "Observed Findings", "Affected Assets", "P1 + P2", "Critical", "Exploit Available", "Confirmed by Multiple Tools", "Reported Only by This Tool"], sourceRows, true);

  if ((analysis.dashboard?.sourceTrend?.length ?? 0) > 1) {
    section(sheet, "A18:I18", "Historical Consolidation Audit");
    writeTable(
      sheet,
      19,
      1,
      ["Period", "Open", "P1 + P2", "Exploit Available", "Confirmed by Multiple Tools", "Reported by One Tool", "Repeats Removed"],
      analysis.dashboard.sourceTrend.map((row) => [row.period, row.totalOpen, row.immediatePatch, row.exploitable, row.crossToolConfirmed, row.singleSourceOnly, row.duplicatesRemoved]),
      true,
    );
  }
}

function prepareSheet(sheet, columns) {
  for (let index = 1; index <= columns; index += 1) sheet.getColumn(index).width = 14;
  sheet.properties.defaultRowHeight = 20;
}

function workbookFindings(analysis) {
  return isComparisonWorkflow(analysis) ? analysis.currentFindings ?? [] : analysis.findings ?? [];
}

function workbookSummary(analysis) {
  const findings = workbookFindings(analysis);
  const severity = Object.fromEntries(["Critical", "High", "Medium", "Low", "Info", "Unknown"].map((label) => [label, 0]));
  const priority = Object.fromEntries(["P1", "P2", "P3", "P4"].map((label) => [label, 0]));
  const assets = new Set();
  let totalOpen = 0;
  let exploitAvailable = 0;
  findings.forEach((finding) => {
    const count = findingWeight(finding);
    totalOpen += count;
    severity[finding.severity] = (severity[finding.severity] ?? 0) + count;
    priority[finding.patchPriority] = (priority[finding.patchPriority] ?? 0) + count;
    if (finding.exploitAvailable) exploitAvailable += count;
    assets.add(finding.dnsName || finding.ipAddress || finding.image || "Unknown asset");
  });
  return {
    totalOpen,
    severity,
    priority,
    immediatePatch: (priority.P1 ?? 0) + (priority.P2 ?? 0),
    exploitAvailable,
    distinctAssets: assets.size,
  };
}

function aggregateAssets(findings) {
  const assets = new Map();
  findings.forEach((finding) => {
    const asset = finding.dnsName || finding.ipAddress || finding.image || "Unknown asset";
    const row = assets.get(asset) ?? {
      asset,
      ipAddress: finding.ipAddress || "",
      dnsName: finding.dnsName || finding.image || "",
      critical: 0,
      high: 0,
      immediatePatch: 0,
      totalOpen: 0,
      maxExposure: 0,
    };
    const count = findingWeight(finding);
    row.totalOpen += count;
    if (finding.severity === "Critical") row.critical += count;
    if (finding.severity === "High") row.high += count;
    if (["P1", "P2"].includes(finding.patchPriority)) row.immediatePatch += count;
    row.maxExposure = Math.max(row.maxExposure, Number(finding.assetExposure) || 0);
    assets.set(asset, row);
  });
  return [...assets.values()].sort((left, right) => right.totalOpen - left.totalOpen || right.immediatePatch - left.immediatePatch || left.asset.localeCompare(right.asset));
}

function aggregateVulnerabilities(findings) {
  const vulnerabilities = new Map();
  findings.forEach((finding) => {
    const key = String(finding.cve || finding.vulnerabilityName || finding.sourceVulnerabilityId || finding.findingKey);
    const row = vulnerabilities.get(key) ?? {
      vulnerability: finding.vulnerabilityName || key,
      cve: finding.cve || "",
      totalOpen: 0,
      assets: new Set(),
      priority: finding.patchPriority,
      exploitAvailable: 0,
      maxExposure: 0,
    };
    const count = findingWeight(finding);
    row.totalOpen += count;
    row.assets.add(finding.dnsName || finding.ipAddress || finding.image || "Unknown asset");
    if (finding.exploitAvailable) row.exploitAvailable += count;
    if (patchPriorityRank(finding.patchPriority) < patchPriorityRank(row.priority)) row.priority = finding.patchPriority;
    row.maxExposure = Math.max(row.maxExposure, Number(finding.assetExposure) || 0);
    vulnerabilities.set(key, row);
  });
  return [...vulnerabilities.values()]
    .map((row) => ({ ...row, affectedAssets: row.assets.size }))
    .sort((left, right) => right.totalOpen - left.totalOpen || patchPriorityRank(left.priority) - patchPriorityRank(right.priority) || left.vulnerability.localeCompare(right.vulnerability));
}

function findingWeight(finding) {
  return Math.max(1, Number(finding?.recordCount) || 1);
}

function patchPriorityRank(priority) {
  return { P1: 1, P2: 2, P3: 3, P4: 4 }[priority] ?? 9;
}

function reportPeriodLabel(analysis) {
  return analysis.dashboard?.reportRange || analysis.reportPeriod || analysis.reportMonth || "Current report";
}

function reportSheetName(analysis) {
  if (isComparisonWorkflow(analysis)) return analysis.workflow === "quarterly" ? "Quarterly Report" : "Monthly Report";
  return analysis.workflow === "quarterly-scan" ? "Quarterly Report" : "Adhoc Report";
}

async function addWorkbookBrandLogo(workbook, sheet) {
  try {
    const base64 = await workbookBrandLogoData();
    const imageId = workbook.addImage({ base64, extension: "png" });
    sheet.addImage(imageId, { tl: { col: 0.2, row: 0.55 }, ext: { width: 189, height: 56 }, editAs: "oneCell" });
  } catch {
    sheet.mergeCells("A2:D3");
    const cell = sheet.getCell("A2");
    cell.value = "HELP AG";
    cell.font = { name: "Aptos Display", bold: true, size: 21, color: { argb: `FF${COLORS.white}` } };
    cell.alignment = { vertical: "middle" };
  }
}

async function workbookBrandLogoData() {
  const logoUrl = new URL("../assets/helpag-logo-white.png", import.meta.url);
  let bytes;
  if (typeof window !== "undefined" && typeof fetch === "function") {
    const response = await fetch(logoUrl);
    if (!response.ok) throw new Error("Brand image unavailable.");
    bytes = new Uint8Array(await response.arrayBuffer());
  } else {
    const moduleName = "node:fs/promises";
    const { readFile } = await import(/* @vite-ignore */ moduleName);
    bytes = new Uint8Array(await readFile(logoUrl));
  }
  return `data:image/png;base64,${bytesToBase64(bytes)}`;
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function reportSourceLabel(sourceLabel) {
  return String(sourceLabel ?? "MVA").replace(/\s+Monthly$/i, "").replace(/\s+Adhoc$/i, "");
}

function title(sheet, heading, subtitle, columns) {
  sheet.mergeCells(1, 1, 1, columns);
  sheet.getCell("A1").value = heading;
  sheet.getCell("A1").font = { bold: true, size: 20, color: { argb: `FF${COLORS.white}` } };
  sheet.getCell("A1").fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${COLORS.navy}` } };
  sheet.getCell("A1").alignment = { vertical: "middle" };
  sheet.getRow(1).height = 32;
  sheet.mergeCells(2, 1, 2, columns);
  sheet.getCell("A2").value = subtitle;
  sheet.getCell("A2").font = { color: { argb: `FF${COLORS.slate}` }, size: 10 };
  sheet.getCell("A2").fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFE2E8F0" } };
}

function kpi(sheet, range, label, value, helper, color) {
  const [start, end] = range.split(":");
  const startCell = sheet.getCell(start);
  const endCell = sheet.getCell(end);
  sheet.mergeCells(startCell.row, startCell.col, startCell.row, endCell.col);
  sheet.getCell(startCell.row, startCell.col).value = label;
  sheet.getCell(startCell.row, startCell.col).fill = solid(COLORS.navy);
  sheet.getCell(startCell.row, startCell.col).font = { bold: true, size: 9, color: { argb: `FF${COLORS.white}` } };
  sheet.mergeCells(startCell.row + 1, startCell.col, startCell.row + 2, endCell.col);
  const valueCell = sheet.getCell(startCell.row + 1, startCell.col);
  valueCell.value = value;
  valueCell.fill = solid("F8FAFC");
  valueCell.font = { bold: true, size: 22, color: { argb: `FF${color}` } };
  valueCell.alignment = { vertical: "middle", horizontal: "center" };
  sheet.mergeCells(endCell.row, startCell.col, endCell.row, endCell.col);
  const helperCell = sheet.getCell(endCell.row, startCell.col);
  helperCell.value = helper;
  helperCell.fill = solid("F8FAFC");
  helperCell.font = { size: 9, color: { argb: `FF${COLORS.slate}` } };
  helperCell.alignment = { vertical: "middle", horizontal: "center", wrapText: true };
  for (let row = startCell.row; row <= endCell.row; row += 1) {
    for (let col = startCell.col; col <= endCell.col; col += 1) {
      sheet.getCell(row, col).border = { bottom: { style: "thin", color: { argb: `FF${color}` } } };
    }
  }
}

function section(sheet, range, text) {
  sheet.mergeCells(range);
  const cell = sheet.getCell(range.split(":")[0]);
  cell.value = text;
  cell.fill = solid("E2E8F0");
  cell.font = { bold: true, size: 11, color: { argb: `FF${COLORS.navy}` } };
}

function writeTable(sheet, startRow, startColumn, headers, rows, colorPriority = false) {
  headers.forEach((header, offset) => {
    const cell = sheet.getCell(startRow, startColumn + offset);
    cell.value = header;
    cell.fill = solid(COLORS.navy);
    cell.font = { bold: true, size: 9, color: { argb: `FF${COLORS.white}` } };
    cell.alignment = { vertical: "middle", horizontal: "center", wrapText: true };
  });
  sheet.getRow(startRow).height = 24;
  rows.forEach((values, rowOffset) => {
    values.forEach((value, columnOffset) => {
      const cell = sheet.getCell(startRow + rowOffset + 1, startColumn + columnOffset);
      cell.value = value;
      cell.fill = solid(rowOffset % 2 === 0 ? "F8FAFC" : "F1F5F9");
      cell.font = { color: { argb: `FF${COLORS.slate}` } };
      if (colorPriority && columnOffset === 0 && COLORS[value]) {
        cell.fill = solid(COLORS[value]);
        cell.font = { bold: true, color: { argb: `FF${COLORS.white}` } };
      }
    });
  });
}

function writeAffectedAssetsTable(sheet, startRow, rows) {
  sheet.mergeCells(startRow, 1, startRow, 5);
  tableHeaderCell(sheet.getCell(startRow, 1), "Asset");
  tableHeaderCell(sheet.getCell(startRow, 6), "Count");

  rows.forEach(([asset, value], rowOffset) => {
    const row = startRow + rowOffset + 1;
    sheet.mergeCells(row, 1, row, 5);
    const assetCell = sheet.getCell(row, 1);
    assetCell.value = asset;
    assetCell.alignment = { vertical: "middle", shrinkToFit: true };
    assetCell.fill = solid(rowOffset % 2 === 0 ? "F8FAFC" : "F1F5F9");
    assetCell.font = { color: { argb: `FF${COLORS.slate}` } };

    const countCell = sheet.getCell(row, 6);
    countCell.value = value;
    countCell.alignment = { horizontal: "center", vertical: "middle" };
    countCell.fill = solid(rowOffset % 2 === 0 ? "F8FAFC" : "F1F5F9");
    countCell.font = { bold: true, color: { argb: `FF${COLORS.navy}` } };
  });
}

function writeAssetConcentration(sheet, startRow, rows, color) {
  sheet.mergeCells(startRow, 7, startRow, 9);
  tableHeaderCell(sheet.getCell(startRow, 7), "Asset");
  sheet.mergeCells(startRow, 10, startRow, 12);
  tableHeaderCell(sheet.getCell(startRow, 10), "Relative concentration");

  const max = Math.max(1, ...rows.map(([, value]) => Number(value) || 0));
  rows.forEach(([label, value], rowOffset) => {
    const row = startRow + rowOffset + 1;
    sheet.mergeCells(row, 7, row, 9);
    const labelCell = sheet.getCell(row, 7);
    labelCell.value = label;
    labelCell.alignment = { vertical: "middle", shrinkToFit: true };
    labelCell.fill = solid(rowOffset % 2 === 0 ? "F8FAFC" : "F1F5F9");
    labelCell.font = { color: { argb: `FF${COLORS.slate}` } };

    const blocks = Math.max(1, Math.round((Number(value) / max) * 12));
    sheet.mergeCells(row, 10, row, 12);
    const cell = sheet.getCell(row, 10);
    cell.value = `${"■".repeat(blocks)} ${value}`;
    cell.alignment = { vertical: "middle", shrinkToFit: true };
    cell.fill = solid(rowOffset % 2 === 0 ? "F8FAFC" : "F1F5F9");
    cell.font = { bold: true, color: { argb: `FF${color}` } };
  });
}

function tableHeaderCell(cell, value) {
  cell.value = value;
  cell.fill = solid(COLORS.navy);
  cell.font = { bold: true, color: { argb: `FF${COLORS.white}` } };
  cell.alignment = { vertical: "middle" };
}

function findingCellValue(finding, key) {
  if (key === "exploitAvailable") return finding[key] ? "Yes" : "No";
  if (key === "fixable") return finding[key] ? "Yes" : "No";
  if (key === "sourceDisplay") return finding.sourceDisplay || (finding.sourceTools ?? []).join(" + ") || finding.sourceTool;
  const value = finding[key];
  if (value !== undefined && value !== null && value !== "") return value;
  if (key === "firstDiscovered" || key === "lastObserved") return "Not provided by source export";
  return "N/A";
}

async function addLineChartImage(workbook, sheet, points, chartTitle, color, placement) {
  if (!canRenderChartImages() || !points.length) return;
  const image = await renderLineChartPng(points, chartTitle, color);
  const imageId = workbook.addImage({ base64: image, extension: "png" });
  sheet.addImage(imageId, {
    tl: { col: placement.col, row: placement.row },
    ext: { width: placement.width, height: placement.height },
    editAs: "oneCell",
  });
}

async function addMultiLineChartImage(workbook, sheet, series, chartTitle, placement) {
  if (!canRenderChartImages() || !series.length) return;
  const image = await renderMultiLineChartPng(series, chartTitle);
  const imageId = workbook.addImage({ base64: image, extension: "png" });
  sheet.addImage(imageId, { tl: { col: placement.col, row: placement.row }, ext: { width: placement.width, height: placement.height }, editAs: "oneCell" });
}

async function addBarChartImage(workbook, sheet, points, chartTitle, placement) {
  if (!canRenderChartImages() || !points.length) return;
  const image = await renderBarChartPng(points, chartTitle);
  const imageId = workbook.addImage({ base64: image, extension: "png" });
  sheet.addImage(imageId, { tl: { col: placement.col, row: placement.row }, ext: { width: placement.width, height: placement.height }, editAs: "oneCell" });
}

function canRenderChartImages() {
  const browserCanvasAvailable = typeof document !== "undefined"
    && typeof Image !== "undefined"
    && typeof URL?.createObjectURL === "function";
  const nodeRasterizerAvailable = typeof process !== "undefined" && Boolean(process.versions?.node);
  return browserCanvasAvailable || nodeRasterizerAvailable;
}

async function renderLineChartPng(points, chartTitle, color) {
  const width = 900;
  const height = 360;
  const plot = { left: 72, top: 74, right: 72, bottom: 58 };
  const chartWidth = width - plot.left - plot.right;
  const chartHeight = height - plot.top - plot.bottom;
  const values = points.map((point) => Math.max(0, Number(point.value) || 0));
  const maxValue = Math.max(1, ...values);
  const axisMax = Math.max(5, Math.ceil(maxValue / 5) * 5);
  const xFor = (index) => plot.left + (points.length <= 1 ? chartWidth / 2 : (index / (points.length - 1)) * chartWidth);
  const yFor = (value) => plot.top + chartHeight - (value / axisMax) * chartHeight;
  const grid = Array.from({ length: 6 }, (_, index) => {
    const value = Math.round((axisMax * index) / 5);
    const y = yFor(value);
    return `<line x1="${plot.left}" y1="${y}" x2="${width - plot.right}" y2="${y}" stroke="#D7DEE8" stroke-width="1" stroke-dasharray="5 5"/><text x="${plot.left - 14}" y="${y + 5}" text-anchor="end" font-size="17" fill="#64748B">${value}</text>`;
  }).join("");
  const labels = points.map((point, index) => `<text x="${xFor(index)}" y="${height - 22}" text-anchor="middle" font-size="17" font-weight="600" fill="#475569">${escapeXml(point.label)}</text>`).join("");
  const coordinates = points.map((point, index) => `${xFor(index)},${yFor(values[index])}`).join(" ");
  const dots = points.map((point, index) => `<circle cx="${xFor(index)}" cy="${yFor(values[index])}" r="7" fill="#FFFFFF" stroke="${color}" stroke-width="5"/><text x="${xFor(index)}" y="${yFor(values[index]) - 15}" text-anchor="middle" font-size="17" font-weight="700" fill="#334155">${values[index]}</text>`).join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" rx="18" fill="#FFFFFF"/><text x="${width / 2}" y="38" text-anchor="middle" font-family="Aptos,Segoe UI,sans-serif" font-size="26" font-weight="700" fill="#172033">${escapeXml(chartTitle)}</text><g font-family="Aptos,Segoe UI,sans-serif">${grid}${labels}<polyline points="${coordinates}" fill="none" stroke="${color}" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>${dots}</g></svg>`;
  return renderSvgPng(svg, width, height, chartTitle);
}

async function renderMultiLineChartPng(series, chartTitle) {
  const width = 900;
  const height = 360;
  const plot = { left: 72, top: 78, right: 48, bottom: 64 };
  const chartWidth = width - plot.left - plot.right;
  const chartHeight = height - plot.top - plot.bottom;
  const labels = series[0].points.map((point) => point.label);
  const values = series.flatMap((item) => item.points.map((point) => Math.max(0, Number(point.value) || 0)));
  const axisMax = Math.max(5, Math.ceil(Math.max(1, ...values) / 5) * 5);
  const xFor = (index) => plot.left + (labels.length <= 1 ? chartWidth / 2 : (index / (labels.length - 1)) * chartWidth);
  const yFor = (value) => plot.top + chartHeight - (value / axisMax) * chartHeight;
  const grid = chartGridSvg({ axisMax, yFor, left: plot.left, right: width - plot.right });
  const xLabels = labels.map((label, index) => `<text x="${xFor(index)}" y="${height - 22}" text-anchor="middle" font-size="15" font-weight="600" fill="#475569">${escapeXml(label)}</text>`).join("");
  const lines = series.map((item) => {
    const points = item.points.map((point, index) => `${xFor(index)},${yFor(Math.max(0, Number(point.value) || 0))}`).join(" ");
    const dots = item.points.map((point, index) => `<circle cx="${xFor(index)}" cy="${yFor(Math.max(0, Number(point.value) || 0))}" r="5" fill="#FFFFFF" stroke="${item.color}" stroke-width="4"/>`).join("");
    return `<polyline points="${points}" fill="none" stroke="${item.color}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>${dots}`;
  }).join("");
  const legend = series.map((item, index) => `<rect x="${plot.left + index * 150}" y="48" width="18" height="5" rx="2" fill="${item.color}"/><text x="${plot.left + 26 + index * 150}" y="55" font-size="14" font-weight="700" fill="#475569">${escapeXml(item.name)}</text>`).join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" rx="18" fill="#FFFFFF"/><text x="${width / 2}" y="30" text-anchor="middle" font-family="Aptos,Segoe UI,sans-serif" font-size="24" font-weight="700" fill="#172033">${escapeXml(chartTitle)}</text><g font-family="Aptos,Segoe UI,sans-serif">${legend}${grid}${xLabels}${lines}</g></svg>`;
  return renderSvgPng(svg, width, height, chartTitle);
}

async function renderBarChartPng(points, chartTitle) {
  const width = 900;
  const height = 360;
  const plot = { left: 72, top: 70, right: 48, bottom: 64 };
  const chartWidth = width - plot.left - plot.right;
  const chartHeight = height - plot.top - plot.bottom;
  const values = points.map((point) => Math.max(0, Number(point.value) || 0));
  const axisMax = Math.max(5, Math.ceil(Math.max(1, ...values) / 5) * 5);
  const yFor = (value) => plot.top + chartHeight - (value / axisMax) * chartHeight;
  const slot = chartWidth / Math.max(points.length, 1);
  const barWidth = Math.min(90, slot * 0.56);
  const grid = chartGridSvg({ axisMax, yFor, left: plot.left, right: width - plot.right });
  const bars = points.map((point, index) => {
    const value = values[index];
    const x = plot.left + slot * index + (slot - barWidth) / 2;
    const y = yFor(value);
    const barHeight = plot.top + chartHeight - y;
    return `<rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="8" fill="${point.color}"/><text x="${x + barWidth / 2}" y="${Math.max(plot.top + 15, y - 10)}" text-anchor="middle" font-size="17" font-weight="700" fill="#334155">${value}</text><text x="${x + barWidth / 2}" y="${height - 22}" text-anchor="middle" font-size="15" font-weight="600" fill="#475569">${escapeXml(point.label)}</text>`;
  }).join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" rx="18" fill="#FFFFFF"/><text x="${width / 2}" y="34" text-anchor="middle" font-family="Aptos,Segoe UI,sans-serif" font-size="24" font-weight="700" fill="#172033">${escapeXml(chartTitle)}</text><g font-family="Aptos,Segoe UI,sans-serif">${grid}${bars}</g></svg>`;
  return renderSvgPng(svg, width, height, chartTitle);
}

function chartGridSvg({ axisMax, yFor, left, right }) {
  return Array.from({ length: 6 }, (_, index) => {
    const value = Math.round((axisMax * index) / 5);
    const y = yFor(value);
    return `<line x1="${left}" y1="${y}" x2="${right}" y2="${y}" stroke="#D7DEE8" stroke-width="1" stroke-dasharray="5 5"/><text x="${left - 14}" y="${y + 5}" text-anchor="end" font-size="15" fill="#64748B">${value}</text>`;
  }).join("");
}

async function renderSvgPng(svg, width, height, chartTitle) {
  if (typeof document === "undefined" || typeof Image === "undefined") {
    const packageName = "@resvg/resvg-js";
    const { Resvg } = await import(/* @vite-ignore */ packageName);
    const png = new Resvg(svg, {
      fitTo: { mode: "width", value: width },
      font: { loadSystemFonts: true },
    }).render().asPng();
    return `data:image/png;base64,${Buffer.from(png).toString("base64")}`;
  }

  const svgUrl = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml;charset=utf-8" }));
  const image = new Image();
  try {
    await new Promise((resolve, reject) => {
      image.onload = resolve;
      image.onerror = () => reject(new Error(`Could not render ${chartTitle}.`));
      image.src = svgUrl;
    });
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    context.drawImage(image, 0, 0, width, height);
    return canvas.toDataURL("image/png");
  } finally {
    URL.revokeObjectURL(svgUrl);
  }
}

function escapeXml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function styleHeader(row) {
  row.height = 28;
  row.eachCell((cell) => {
    cell.fill = solid(COLORS.navy);
    cell.font = { bold: true, color: { argb: `FF${COLORS.white}` } };
    cell.alignment = { vertical: "middle", wrapText: true };
  });
}

function solid(color) {
  return { type: "pattern", pattern: "solid", fgColor: { argb: `FF${color}` } };
}

function saveBlob(blob, fileName) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function csvCell(value) {
  const text = value == null ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function safeName(value) {
  return String(value).replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "");
}

function column(number) {
  let value = number;
  let label = "";
  while (value > 0) {
    value -= 1;
    label = String.fromCharCode(65 + (value % 26)) + label;
    value = Math.floor(value / 26);
  }
  return label;
}
