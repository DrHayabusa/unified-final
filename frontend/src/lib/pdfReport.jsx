import { buildQualysInsights, buildUnifiedInsights } from "./vulnerabilityEngine.jsx";
import { buildCustomerValueInsights } from "./customerInsights.jsx";

export function buildRemediationPrompt({ analysis, targetMonth }) {
  const findings = groupedPrioritizedFindings(analysis, targetMonth).slice(0, 60).map((group) => ({
    affectedFindings: group.affectedCount,
    affectedAssets: group.assets,
    vulnerabilityName: group.finding.vulnerabilityName,
    cve: group.finding.cve || "N/A",
    severity: group.finding.severity,
    exploitAvailability: group.finding.exploitAvailable ? "Available" : "No known exploit",
    internetExposure: group.finding.internetExposureKnown
      ? (group.finding.internetExposed ? "Confirmed exposed" : "Confirmed not exposed")
      : "Unknown / not supplied",
    epssScore: group.finding.epssScore,
    patchPriority: group.finding.patchPriority,
    product: group.finding.product || group.finding.platformDetails,
    remediation: dedupeSegments(group.finding.remediation),
    advisoryLinks: group.links,
  }));
  const dashboard = analysis?.dashboard ?? {};
  const comparison = isComparisonWorkflow(analysis);
  const portfolio = buildPortfolioContext(analysis, targetMonth);
  const quarterly = analysis?.workflow === "quarterly";
  const periodName = quarterly ? "Quarter" : ["adhoc", "quarterly-scan"].includes(analysis?.workflow) ? "Period" : "Month";
  const summary = buildSelectedPeriodSummary(analysis, targetMonth, periodName);
  const decisionIntelligence = buildSelectedDecisionContext(analysis, targetMonth);
  const qualysContext = buildQualysInsights(selectedReportFindings(analysis, targetMonth));

  return `You are the MVA Remediation Guide generation engine. Return customer-ready Markdown only.

Create an industry-standard document with this exact document identity:
- Title: Remediation Guide
- Report Type: Remediation
- Tool Source: ${analysis?.sourceLabel || "MVA"}
- Reporting ${periodName}: ${targetMonth}
- Do not include a customer name, purpose section, created-by line, or internal implementation wording.

Required structure:
1. A clean Table of Contents.
2. Portfolio Risk Overview with actionable counts, P1-P4 posture, multi-tool confirmation, and tool contribution when consolidated analytics are supplied. When Qualys context is supplied, visibly include the complete source-rating distribution and Datacentre distribution.
3. Trend Analysis with total open, new, patched, P1-P4, findings confirmed by multiple tools, and findings reported by one tool when historical analytics are supplied.
4. Remediation Actions ordered P1, P2, P3, then P4.
5. Group repeated findings by CVE or vulnerability name. For every action include affected finding count, example assets, CVE, severity, patch priority, reference links, prerequisites, numbered remediation steps, command examples, rollback, and validation.
6. Put every command in a fenced code block with a language tag (bash, powershell, sql, or text).
7. Use only commands supported by the supplied remediation text or authoritative link context. Use explicit placeholders where exact product paths or versions are unknown.
8. End with Validation Requirements and References.
9. Do not invent patch versions, KB numbers, CVEs, links, commands, or successful validation evidence.

Dashboard summary:
${JSON.stringify(summary, null, 2)}

Consolidated analytics for the selected reporting period:
${JSON.stringify(portfolio, null, 2)}

Decision intelligence for prioritization and remediation grouping:
${JSON.stringify(decisionIntelligence, null, 2)}

Qualys operational context:
${JSON.stringify(qualysContext, null, 2)}

Prioritized normalized findings:
${JSON.stringify(findings, null, 2)}
`;
}

export function buildTemplateMarkdown({ analysis, targetMonth }) {
  const groups = groupedPrioritizedFindings(analysis, targetMonth).slice(0, 20);
  const dashboard = analysis?.dashboard ?? {};
  const comparison = isComparisonWorkflow(analysis);
  const portfolio = buildPortfolioContext(analysis, targetMonth);
  const qualysContext = buildQualysInsights(selectedReportFindings(analysis, targetMonth));
  const periodName = analysis?.workflow === "quarterly" ? "Quarter" : ["adhoc", "quarterly-scan"].includes(analysis?.workflow) ? "Period" : "Month";
  const total = selectedReportFindings(analysis, targetMonth).reduce((sum, finding) => sum + (Number(finding.recordCount) || 1), 0)
    || (comparison ? dashboard.totalOpenVulnerabilities?.totalOpen : dashboard.totalVulnerabilities);
  const hasTrend = (portfolio?.trend?.length ?? 0) > 1;
  const remediationSection = hasTrend ? 3 : 2;
  const validationSection = remediationSection + 1;
  const referenceSection = validationSection + 1;
  const lines = [
    "# Remediation Guide",
    "",
    "## Table of Contents",
    "",
    "1. Portfolio Risk Overview",
    ...(hasTrend ? ["2. Trend Analysis"] : []),
    `${remediationSection}. Remediation Actions`,
    `${validationSection}. Validation Requirements`,
    `${referenceSection}. References`,
    "",
    "## 1. Portfolio Risk Overview",
    "",
    `Tool Source: ${analysis?.sourceLabel || "MVA"}`,
    `Reporting ${periodName}: ${targetMonth}`,
    `Total Open Findings: ${total ?? 0}`,
  ];
  if (portfolio) {
    lines.push(
      "",
      "| Measure | Value |",
      "| --- | ---: |",
      `| Consolidated Open | ${portfolio.totalOpen} |`,
      `| Affected Assets | ${portfolio.distinctAssets} |`,
      `| Immediate Patch (P1 + P2) | ${portfolio.immediatePatch} |`,
      `| Exploit Available | ${portfolio.exploitAvailable} |`,
      `| Confirmed by Multiple Tools | ${portfolio.crossToolConfirmed} |`,
      `| Reported by One Tool | ${portfolio.singleSourceOnly} |`,
      `| Confirmation Rate | ${portfolio.confirmationRate}% |`,
      "",
      "### Patch Priority Posture",
      "",
      "| Priority | Open Findings |",
      "| --- | ---: |",
      ...Object.entries(portfolio.patchPriorityCounts).map(([priority, count]) => `| ${priority} | ${count} |`),
    );
    if (portfolio.sourceContribution.length) {
      lines.push(
        "",
        "### Tool Contribution",
        "",
        "| Tool | Observed | P1 + P2 | Exploit Available | Confirmed by Multiple Tools | Reported Only by This Tool |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        ...portfolio.sourceContribution.map((source) => `| ${source.sourceLabel} | ${source.openFindings} | ${source.immediatePatch} | ${source.exploitAvailable} | ${source.crossToolConfirmed} | ${source.exclusiveFindings} |`),
      );
    }
    if (portfolio.topRiskAssets.length) {
      lines.push(
        "",
        "### Highest-Risk Assets",
        "",
        "| Asset | Open | P1 + P2 | Critical | Exploit Available | Sources | Exposure |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ...portfolio.topRiskAssets.slice(0, 8).map((asset) => `| ${markdownTableText(asset.asset)} | ${asset.totalOpen} | ${asset.immediatePatch} | ${asset.critical} | ${asset.exploitAvailable} | ${asset.sourceCount} | ${asset.maxExposure} |`),
      );
    }
  }
  if (qualysContext) {
    const customProfile = String(analysis?.sourceLabel).toLowerCase().includes("custom qualys");
    const ratings = orderedQualysRatings(qualysContext.vendorRatings, customProfile);
    lines.push(
      "",
      `### ${customProfile ? "Custom Qualys Rating Distribution" : "Qualys Vendor Rating Distribution"}`,
      "",
      "| Source Rating | Open Findings |",
      "| --- | ---: |",
      ...ratings.map((row) => `| ${row.rating} | ${row.vulnerabilityCount} |`),
      "",
      "### Datacentre Distribution",
      "",
      "| Datacentre | Open Findings |",
      "| --- | ---: |",
      ...qualysContext.datacentres.map((row) => `| ${markdownTableText(row.datacentre)} | ${row.vulnerabilityCount} |`),
    );
  }
  if (hasTrend) {
    lines.push(
      "",
      "## 2. Trend Analysis",
      "",
      "| Period | Total Open | New | Patched | P1 | P2 | P3 | P4 | Confirmed by Multiple Tools | Reported by One Tool |",
      "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
      ...portfolio.trend.map((row) => `| ${row.period} | ${row.totalOpen} | ${row.newFindings} | ${row.patchedFindings} | ${row.P1} | ${row.P2} | ${row.P3} | ${row.P4} | ${row.crossToolConfirmed} | ${row.singleSourceOnly} |`),
    );
  }
  lines.push("", `## ${remediationSection}. Remediation Actions`);
  groups.forEach((group, index) => {
    const finding = group.finding;
    const commands = commandForFinding(finding);
    lines.push(
      "",
      `### ${index + 1}. ${finding.vulnerabilityName || "Recommended Remediation"}`,
      "",
      `- Affected Findings: ${group.affectedCount} across ${group.assets.length} assets`,
      `- Asset Examples: ${group.assets.slice(0, 5).join(", ") || "Not provided"}`,
      `- CVE: ${finding.cve || "N/A"}`,
      `- Severity: ${finding.severity}`,
      `- Patch Priority: ${finding.patchPriority}`,
      ...group.links.map((link) => `- Advisory: ${link}`),
      "",
      "Remediation steps:",
      "",
      `1. ${dedupeSegments(finding.remediation) || "Review the vendor advisory and apply the supported security update."}`,
      "2. Validate application and service health after the change.",
      "3. Run a follow-up vulnerability scan and retain evidence.",
      "",
      `\`\`\`${commands.language}`,
      ...commands.lines,
      "```",
      "",
      "Rollback and validation:",
      "",
      "- Use the approved change rollback procedure if service-health checks fail.",
      "- Confirm the installed version or configuration, validate service health, and verify closure in a follow-up scan.",
    );
  });
  lines.push(
    "",
    `## ${validationSection}. Validation Requirements`,
    "",
    "Confirm service health, review change evidence, and verify closure in a follow-up vulnerability scan.",
    "",
    `## ${referenceSection}. References`,
    "",
    ...[...new Set(groups.flatMap((group) => group.links))].map((link) => `- ${link}`),
  );
  return lines.join("\n");
}

function orderedQualysRatings(rows = [], customProfile = false) {
  const counts = new Map(rows.map((row) => [String(row.rating), Number(row.vulnerabilityCount) || 0]));
  const labels = customProfile
    ? ["5 - Urgent", "4 - Critical", "3 - Serious", "2 - Medium", "1 - Minimal"]
    : ["5 - Critical", "4 - High", "3 - Medium", "2 - Low", "1 - Minimal"];
  return labels.map((rating) => ({ rating, vulnerabilityCount: counts.get(rating) ?? 0 }));
}

export async function downloadRemediationPdf({ markdown, sourceLabel, targetMonth, workflow = "monthly" }) {
  const doc = await createRemediationPdfDocument({ markdown, sourceLabel, targetMonth, workflow });
  doc.save(`MVA_${safeName(sourceLabel)}_${safeName(targetMonth)}_Remediation_Guide.pdf`);
}

export async function createRemediationPdfDocument({ markdown, sourceLabel, targetMonth, workflow = "monthly" }) {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "mm", format: "a4", compress: true });
  doc.setProperties({
    title: "Remediation Guide",
    subject: `${sourceLabel || "MVA"} vulnerability remediation plan for ${targetMonth || "the selected reporting period"}`,
    creator: "MVA Vulnerability Agent",
  });
  const width = doc.internal.pageSize.getWidth();
  const height = doc.internal.pageSize.getHeight();
  const margin = 18;

  doc.setFillColor(20, 33, 61);
  doc.rect(0, 0, width, 54, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(27);
  doc.text("Remediation Guide", margin, 32);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text("Vulnerability remediation plan", margin, 42);

  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11);
  metadataRow(doc, "Report Type", "Remediation", margin, 74, width - margin * 2);
  metadataRow(doc, "Tool Source", sourceLabel || "MVA", margin, 87, width - margin * 2);
  const reportingLabel = workflow === "quarterly" ? "Reporting Quarter" : ["adhoc", "quarterly-scan"].includes(workflow) ? "Reporting Period" : "Reporting Month";
  metadataRow(doc, reportingLabel, targetMonth || "Not provided", margin, 100, width - margin * 2);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text("Table of Contents", margin, 126);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  const contents = extractHeadings(markdown)
    .filter((heading) => heading.level === 2 && !/^(?:table of )?contents$/i.test(heading.text.replace(/^\d+\.\s*/, "")))
    .slice(0, 10);
  let contentsY = 137;
  contents.forEach((heading, index) => {
    doc.text(`${index + 1}. ${heading.text.replace(/^\d+\.\s*/, "")}`, margin + 2, contentsY);
    contentsY += 8;
  });

  doc.addPage();
  renderMarkdown(doc, stripCoverContent(markdown), { margin, width, height });
  addFooters(doc, margin, width, height);
  return doc;
}

function stripCoverContent(markdown) {
  const lines = String(markdown ?? "").replace(/\r/g, "").split("\n");
  const contentsIndex = lines.findIndex((line) => /^##\s+(?:Table of )?Contents\s*$/i.test(line.trim()));
  const firstBodyIndex = contentsIndex >= 0
    ? lines.findIndex((line, index) => index > contentsIndex && /^##\s+/.test(line.trim()))
    : -1;
  const body = firstBodyIndex >= 0 ? lines.slice(firstBodyIndex) : lines.filter((line) => !/^#\s+Remediation Guide\s*$/i.test(line.trim()));
  return body.join("\n").trim();
}

function renderMarkdown(doc, markdown, { margin, width, height }) {
  const lines = String(markdown || "").replace(/\r/g, "").split("\n");
  let y = 22;
  let codeLines = [];
  let inCode = false;

  const ensureSpace = (needed) => {
    if (y + needed <= height - 18) return;
    doc.addPage();
    y = 22;
  };

  const renderCode = () => {
    if (!codeLines.length) return;
    const wrapped = codeLines.flatMap((line) => doc.splitTextToSize(line || " ", width - margin * 2 - 10));
    const boxHeight = Math.max(14, wrapped.length * 4.2 + 8);
    ensureSpace(boxHeight + 5);
    doc.setFillColor(15, 23, 42);
    doc.roundedRect(margin, y, width - margin * 2, boxHeight, 2, 2, "F");
    doc.setTextColor(226, 232, 240);
    doc.setFont("courier", "normal");
    doc.setFontSize(7.5);
    doc.text(wrapped, margin + 5, y + 6);
    y += boxHeight + 5;
    codeLines = [];
  };

  const renderTable = (rows) => {
    if (!rows.length) return;
    const columnCount = Math.max(...rows.map((row) => row.length));
    const availableWidth = width - margin * 2;
    const firstWidth = columnCount <= 3 ? availableWidth * 0.45 : availableWidth * 0.24;
    const remainingWidth = columnCount > 1 ? (availableWidth - firstWidth) / (columnCount - 1) : availableWidth;
    const columnWidths = Array.from({ length: columnCount }, (_, index) => index === 0 ? firstWidth : remainingWidth);
    const fontSize = columnCount >= 8 ? 5.5 : columnCount >= 6 ? 6.2 : 7.3;
    const lineHeight = fontSize * 0.42;

    const drawRow = (values, header, shade) => {
      doc.setFont("helvetica", header ? "bold" : "normal");
      doc.setFontSize(fontSize);
      const wrappedCells = columnWidths.map((columnWidth, index) => doc.splitTextToSize(cleanMarkdown(values[index] ?? ""), columnWidth - 3));
      const rowHeight = Math.max(7, ...wrappedCells.map((cellLines) => cellLines.length * lineHeight + 4));
      if (y + rowHeight > height - 18) {
        doc.addPage();
        y = 22;
      }
      let x = margin;
      wrappedCells.forEach((cellLines, index) => {
        doc.setFillColor(...(header ? [20, 33, 61] : shade ? [248, 250, 252] : [241, 245, 249]));
        doc.setDrawColor(203, 213, 225);
        doc.rect(x, y, columnWidths[index], rowHeight, "FD");
        doc.setTextColor(...(header ? [255, 255, 255] : [51, 65, 85]));
        doc.text(cellLines, x + 1.5, y + 4);
        x += columnWidths[index];
      });
      y += rowHeight;
    };

    drawRow(rows[0], true, false);
    rows.slice(1).forEach((row, index) => drawRow(row, false, index % 2 === 0));
    y += 4;
  };

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const rawLine = lines[lineIndex];
    const line = rawLine.trimEnd();
    if (line.startsWith("```")) {
      if (inCode) renderCode();
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      codeLines.push(rawLine);
      continue;
    }
    if (!line.trim()) {
      y += 3;
      continue;
    }

    // Markdown thematic breaks are structural separators, not report text.
    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      y += 2;
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      const text = cleanMarkdown(heading[2]);
      const size = level === 1 ? 19 : level === 2 ? 15 : level === 3 ? 12 : 10;
      ensureSpace(size + 8);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(size);
      doc.setTextColor(level <= 2 ? 15 : 7, level <= 2 ? 23 : 89, level <= 2 ? 42 : 133);
      const wrapped = doc.splitTextToSize(text, width - margin * 2);
      doc.text(wrapped, margin, y);
      y += wrapped.length * (size * 0.43) + 4;
      continue;
    }

    if (/^\s*\|.*\|\s*$/.test(line)) {
      const tableLines = [];
      let cursor = lineIndex;
      while (cursor < lines.length && /^\s*\|.*\|\s*$/.test(lines[cursor])) {
        tableLines.push(lines[cursor]);
        cursor += 1;
      }
      const rows = tableLines
        .map((tableLine) => tableLine.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim()))
        .filter((row) => !row.every((cell) => /^:?-{3,}:?$/.test(cell)));
      renderTable(rows);
      lineIndex = cursor - 1;
      continue;
    }

    const bullet = line.match(/^[-*]\s+(.+)$/);
    const numbered = line.match(/^\d+\.\s+(.+)$/);
    const prefix = bullet ? "- " : numbered ? `${line.match(/^\d+/)[0]}. ` : "";
    const body = cleanMarkdown(bullet?.[1] ?? numbered?.[1] ?? line);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    const wrapped = doc.splitTextToSize(`${prefix}${body}`, width - margin * 2 - (prefix ? 4 : 0));
    ensureSpace(wrapped.length * 4.5 + 3);
    const textX = margin + (prefix ? 2 : 0);
    doc.text(wrapped, textX, y);
    const url = body.match(/https?:\/\/[^\s)]+/)?.[0];
    if (url) {
      wrapped.forEach((wrappedLine, index) => {
        doc.link(textX, y - 3 + index * 4.5, Math.min(doc.getTextWidth(wrappedLine), width - margin * 2), 4.5, { url });
      });
    }
    y += wrapped.length * 4.5 + 2;
  }
  if (inCode || codeLines.length) renderCode();
}

function metadataRow(doc, label, value, x, y, width) {
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(x, y - 8, width, 10, 1.5, 1.5, "FD");
  doc.setFont("helvetica", "bold");
  doc.text(label, x + 4, y - 2);
  doc.setFont("helvetica", "normal");
  doc.text(String(value), x + 46, y - 2);
}

function addFooters(doc, margin, width, height) {
  const pages = doc.getNumberOfPages();
  for (let page = 1; page <= pages; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, height - 14, width - margin, height - 14);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text("Remediation Guide", margin, height - 8);
    doc.text(`Page ${page} of ${pages}`, width - margin, height - 8, { align: "right" });
  }
}

function buildPortfolioContext(analysis, targetMonth) {
  const comparison = isComparisonWorkflow(analysis);
  const selectedSnapshot = comparison ? analysis.snapshots?.find((snapshot) => snapshot.month === targetMonth) : null;
  const findings = selectedReportFindings(analysis, targetMonth);
  const sourceCount = selectedSnapshot?.inputSummary?.sourceCount
    ?? analysis?.inputSummary?.sourceCount
    ?? analysis?.sourceIds?.length
    ?? 0;
  if (sourceCount < 2 || !findings.length) return null;
  const insights = buildUnifiedInsights(findings, sourceCount);
  const allTrend = analysis?.dashboard?.unifiedTrend ?? [];
  const targetIndex = allTrend.findIndex((row) => row.period === targetMonth || row.month === targetMonth);
  const trend = targetIndex >= 0 ? allTrend.slice(0, targetIndex + 1) : allTrend;
  const inputSummary = selectedSnapshot?.inputSummary ?? analysis?.inputSummary ?? {};
  const sourceContribution = selectedSnapshot?.sourceBreakdown ?? analysis?.dashboard?.sourceBreakdown ?? [];
  return {
    selectedSources: analysis?.sourceIds ?? inputSummary.sourceIds ?? [],
    totalOpen: insights.totalOpen,
    distinctAssets: insights.distinctAssets,
    immediatePatch: insights.immediatePatch,
    exploitAvailable: insights.exploitAvailable,
    crossToolConfirmed: insights.crossToolConfirmed,
    singleSourceOnly: insights.singleSourceOnly,
    confirmationRate: insights.confirmationRate,
    repeatedObservationsRemoved: inputSummary.duplicatesRemoved ?? 0,
    patchPriorityCounts: insights.patchPriorityCounts,
    severityCounts: insights.severityCounts,
    sourceAgreementDistribution: insights.sourceAgreementDistribution,
    sourceContribution,
    sourcePairOverlap: insights.sourcePairOverlap,
    topRiskAssets: insights.topRiskAssets,
    topVulnerabilities: insights.topVulnerabilities,
    trend,
  };
}

function selectedReportFindings(analysis, targetMonth) {
  const comparison = isComparisonWorkflow(analysis);
  const selectedSnapshot = comparison ? analysis.snapshots?.find((snapshot) => snapshot.month === targetMonth) : null;
  return selectedSnapshot?.findings ?? (comparison ? analysis?.currentFindings ?? [] : analysis?.findings ?? []);
}

function buildSelectedDecisionContext(analysis, targetMonth) {
  const findings = selectedReportFindings(analysis, targetMonth);
  const targetIndex = analysis?.snapshots?.findIndex((snapshot) => snapshot.month === targetMonth || snapshot.period === targetMonth) ?? -1;
  const snapshots = targetIndex >= 0 ? analysis.snapshots.slice(0, targetIndex + 1) : [];
  const selectedSnapshot = targetIndex >= 0 ? analysis.snapshots[targetIndex] : null;
  const insights = buildCustomerValueInsights(findings, { snapshots, reportDate: selectedSnapshot?.reportDate });
  return {
    threatPriority: {
      reviewQueue: insights.threatPriority.reviewQueue,
      exploitAvailable: insights.threatPriority.exploitAvailable,
      internetExposed: insights.threatPriority.internetExposed,
      internetExposureObserved: insights.threatPriority.internetExposureObserved,
      internetExposureUnknown: insights.threatPriority.internetExposureUnknown,
      epssAbove50: insights.threatPriority.epssAbove50,
    },
    remediationCampaigns: insights.remediationCampaigns.campaigns.slice(0, 15).map((campaign) => ({
      priority: campaign.primaryPriority,
      vulnerability: campaign.title,
      cve: campaign.cve || "N/A",
      findings: campaign.findingCount,
      assets: campaign.assets.length,
      action: campaign.action,
      references: campaign.references,
    })),
    verification: {
      available: insights.verification.available,
      previousPeriod: insights.verification.previousPeriod,
      currentPeriod: insights.verification.currentPeriod,
      persistent: insights.verification.persistent,
      newFindings: insights.verification.newFindings,
      reappeared: insights.verification.reappeared,
      noLongerObserved: insights.verification.noLongerObserved,
      previousTotal: insights.verification.previousTotal,
      currentTotal: insights.verification.currentTotal,
      reconciled: insights.verification.reconciled,
    },
    dataQuality: {
      evidenceCompleteness: insights.dataQuality.evidenceCompleteness,
      completeCore: insights.dataQuality.completeCore,
      staleObservations: insights.dataQuality.staleObservations,
      missingFields: insights.dataQuality.issues,
    },
  };
}

function buildSelectedPeriodSummary(analysis, targetMonth, periodName) {
  const findings = selectedReportFindings(analysis, targetMonth);
  const summary = {
    totalOpen: weightedFindingTotal(findings),
    patchPriority: weightedFindingCounts(findings, "patchPriority", ["P1", "P2", "P3", "P4"]),
    severity: weightedFindingCounts(findings, "severity", ["Critical", "High", "Medium", "Low", "Info", "Unknown"]),
  };
  if (!isComparisonWorkflow(analysis)) return summary;

  const trend = analysis?.dashboard?.openTrend?.find((row) => row.period === targetMonth || row.month === targetMonth);
  return {
    ...summary,
    [`newThis${periodName}`]: Number(trend?.newThisPeriod ?? trend?.newThisMonth) || 0,
    [`patchedLast${periodName}`]: Number(trend?.patchedSinceLastPeriod ?? trend?.patchedSinceLastMonth) || 0,
  };
}

function weightedFindingTotal(findings) {
  return findings.reduce((sum, finding) => sum + (Number(finding.recordCount) || 1), 0);
}

function weightedFindingCounts(findings, field, labels) {
  const counts = Object.fromEntries(labels.map((label) => [label, 0]));
  findings.forEach((finding) => {
    const label = labels.includes(finding[field]) ? finding[field] : labels.at(-1);
    counts[label] += Number(finding.recordCount) || 1;
  });
  return counts;
}

function prioritizedFindings(analysis, targetMonth) {
  const findings = selectedReportFindings(analysis, targetMonth);
  return [...findings].sort((left, right) => priorityRank(left.patchPriority) - priorityRank(right.patchPriority) || right.assetExposure - left.assetExposure);
}

function isComparisonWorkflow(analysis) {
  return analysis?.workflow === "monthly" || analysis?.workflow === "quarterly";
}

function groupedPrioritizedFindings(analysis, targetMonth) {
  const groups = new Map();
  prioritizedFindings(analysis, targetMonth).forEach((finding) => {
    const key = String(finding.cve || finding.vulnerabilityName || finding.sourceVulnerabilityId || finding.findingKey).trim().toUpperCase();
    if (!groups.has(key)) {
      groups.set(key, { finding, affectedCount: 0, assets: new Set(), links: new Set() });
    }
    const group = groups.get(key);
    group.affectedCount += Number(finding.recordCount) || 1;
    const asset = finding.dnsName || finding.ipAddress;
    if (asset) group.assets.add(asset);
    uniqueLinks(finding.kbLinks).forEach((link) => group.links.add(link));
  });
  return [...groups.values()].map((group) => ({
    finding: group.finding,
    affectedCount: group.affectedCount,
    assets: [...group.assets].sort(),
    links: [...group.links],
  }));
}

function uniqueLinks(value) {
  return [...new Set(String(value || "").replace(/,/g, "|").split("|").map((part) => part.trim()).filter((part) => /^https?:\/\//i.test(part)))];
}

function dedupeSegments(value) {
  const seen = new Set();
  return String(value || "").split("|").map((part) => part.trim().replace(/\s+/g, " ")).filter((part) => {
    const key = part.toLowerCase();
    if (!part || seen.has(key)) return false;
    seen.add(key);
    return true;
  }).join(" ");
}

function commandForFinding(finding) {
  const name = String(finding.vulnerabilityName || "").toLowerCase();
  if (name.includes("chrome")) return { language: "powershell", lines: ["winget upgrade --id Google.Chrome --exact --silent --accept-source-agreements --accept-package-agreements", "(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe').VersionInfo.FileVersion"] };
  if (name.includes("remote desktop")) return { language: "powershell", lines: ["Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10", "# Install the approved Microsoft security update and reboot if required", "Get-Service TermServLicensing"] };
  if (name.includes("log4j")) return { language: "bash", lines: ["find /opt -name 'log4j-core-*.jar' -print", "# Replace the vulnerable JAR through the approved application release", "sudo systemctl restart <affected-service>"] };
  if (name.includes("tomcat")) return { language: "bash", lines: ["/opt/tomcat/bin/version.sh", "grep -n 'Connector.*AJP' /opt/tomcat/conf/server.xml", "# Upgrade Tomcat and disable unused AJP or require a secret", "sudo systemctl restart tomcat"] };
  if (name.includes("openssl")) return { language: "bash", lines: ["openssl version -a", "sudo apt-get update", "sudo apt-get install --only-upgrade openssl", "sudo systemctl restart <affected-service>"] };
  if (name.includes("linux kernel")) return { language: "bash", lines: ["uname -r", "sudo apt-get update", "sudo apt-get install --only-upgrade linux-image-generic", "sudo reboot"] };
  if (name.includes("cisco ios xe")) return { language: "text", lines: ["show version", "show running-config | include ^ip http", "# Stage and activate the vendor-fixed IOS XE image under the approved network change"] };
  if (name.includes("exchange")) return { language: "powershell", lines: ["Get-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion", "# Install the approved Exchange Security Update and reboot if required"] };
  return { language: "text", lines: ["# Replace placeholders with the approved product-specific command", "<apply-approved-security-update>", "<validate-service-health>", "<run-follow-up-scan>"] };
}

function extractHeadings(markdown) {
  return String(markdown || "").split(/\r?\n/).map((line) => {
    const match = line.match(/^(#{1,4})\s+(.+)$/);
    return match ? { level: match[1].length, text: cleanMarkdown(match[2]) } : null;
  }).filter(Boolean);
}

function cleanMarkdown(value) {
  return String(value).replace(/\*\*(.*?)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1").replace(/\[(.*?)\]\((.*?)\)/g, "$1 ($2)");
}

function markdownTableText(value) {
  return String(value ?? "").replaceAll("|", "/").replace(/\s+/g, " ").trim();
}

function priorityRank(priority) {
  return { P1: 1, P2: 2, P3: 3, P4: 4 }[priority] ?? 9;
}

function safeName(value) {
  return String(value || "MVA").replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "");
}
