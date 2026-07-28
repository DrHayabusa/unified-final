import {
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useState } from "react";
import { ArrowLeft, BrainCircuit, CalendarRange, ChevronDown, Download, FileSpreadsheet, FileText, RefreshCcw, Table2, Trash2, UploadCloud, X } from "lucide-react";
import { AGE_BUCKETS, extractMonthFromFilename, extractQuarterFromFilename } from "../lib/vulnerabilityEngine.jsx";
import { downloadAnalysisWorkbook, downloadNormalizedCsv } from "../lib/reportExport.jsx";
import { buildTemplateMarkdown, downloadRemediationPdf } from "../lib/pdfReport.jsx";
import { downloadExecutiveDashboardPdf } from "../lib/executiveReportPdf.jsx";
import { isSupportedUploadFile, mergeUploadFiles, removeUploadFile, uploadFileKey } from "../lib/uploadFiles.jsx";
import { AiReportBuilder } from "./AiReportBuilder.jsx";
import { SourceCoveragePanel } from "./SourceCoveragePanel.jsx";
import { UnifiedAnalysisDashboard } from "./UnifiedAnalysisDashboard.jsx";
import { CustomerValueDashboards } from "./CustomerValueDashboards.jsx";
import { CrowdStrikeInsights } from "./CrowdStrikeInsights.jsx";
import { CustomFieldMapper } from "./CustomFieldMapper.jsx";
import { QualysInsights } from "./QualysInsights.jsx";
import { OpenShiftInsights } from "./OpenShiftInsights.jsx";

const PRIORITY_COLORS = { P1: "#dc2626", P2: "#ea580c", P3: "#ca8a04", P4: "#16a34a" };
const SEVERITY_COLORS = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e", Info: "#0ea5e9", Unknown: "#64748b" };

export function MonthlyComparison({ analysis, onAnalyze, selectedSource, selectedMonth, onMonthChange, files, onFilesChange, onEditUploads, onResetUploads, onBackToDashboard, cadence = "monthly" }) {
  const [exportStatus, setExportStatus] = useState({ state: "idle", message: "" });
  const labels = comparisonLabels(cadence);
  if (!analysis) {
    return <MonthlyUploadGate key={`${selectedSource.id}-${cadence}`} selectedSource={selectedSource} onAnalyze={onAnalyze} files={files} onFilesChange={onFilesChange} onResetUploads={onResetUploads} onBackToDashboard={onBackToDashboard} cadence={cadence} />;
  }

  const dashboard = analysis.dashboard;
  const monthOptions = dashboard.uploadedPeriods ?? dashboard.uploadedMonths;
  const targetPeriod = monthOptions.includes(selectedMonth) ? selectedMonth : monthOptions.at(-1);
  const open = dashboard.totalOpenVulnerabilities;
  const patched = dashboard.totalVulnerabilitiesPatchedLastPeriod ?? dashboard.totalVulnerabilitiesPatchedLastMonth;
  const discoveredTrend = dashboard.trendDiscoveredLast3Periods ?? dashboard.trendDiscoveredLast3Months;
  const remediatedTrend = dashboard.trendRemediatedLast3Periods ?? dashboard.trendRemediatedLast3Months;
  const total = open.totalOpen || 1;
  const ageChartData = AGE_BUCKETS.map((bucket) => ({
    bucket: bucket.replace(" (6+ months)", ""),
    P1: dashboard.totalOpenByAgeAndPatchPriority.P1[bucket],
    P2: dashboard.totalOpenByAgeAndPatchPriority.P2[bucket],
    P3: dashboard.totalOpenByAgeAndPatchPriority.P3[bucket],
    P4: dashboard.totalOpenByAgeAndPatchPriority.P4[bucket],
  }));
  const priorityData = Object.entries(dashboard.totalOpenByPatchPriority).map(([priority, count]) => ({ priority, count, fill: PRIORITY_COLORS[priority] }));
  const severitySegments = Object.entries(dashboard.currentSeverityCounts)
    .filter(([, count]) => count > 0)
    .map(([label, value]) => ({ label, value, color: SEVERITY_COLORS[label], width: `${(value / total) * 100}%` }));

  const downloadExcel = async () => {
    setExportStatus({ state: "loading", message: "Building the Excel report..." });
    try {
      await downloadAnalysisWorkbook(analysis);
      setExportStatus({ state: "success", message: "Excel report generated and downloaded." });
    } catch (error) {
      setExportStatus({ state: "error", message: error.message || "Excel export failed." });
    }
  };

  const downloadCsv = () => {
    try {
      downloadNormalizedCsv(analysis);
      setExportStatus({ state: "success", message: "Normalized CSV generated and downloaded." });
    } catch (error) {
      setExportStatus({ state: "error", message: error.message || "CSV export failed." });
    }
  };

  const downloadPdf = async () => {
    setExportStatus({ state: "loading", message: `Building the ${targetPeriod} Remediation Guide PDF...` });
    try {
      const markdown = buildTemplateMarkdown({ analysis, targetMonth: targetPeriod });
      await downloadRemediationPdf({ markdown, sourceLabel: analysis.sourceLabel, targetMonth: targetPeriod, workflow: cadence });
      setExportStatus({ state: "success", message: `Remediation Guide PDF generated for ${targetPeriod}.` });
    } catch (error) {
      setExportStatus({ state: "error", message: error.message || "PDF export failed." });
    }
  };

  const downloadExecutivePdf = async () => {
    setExportStatus({ state: "loading", message: `Building the ${targetPeriod} Executive Dashboard PDF...` });
    try {
      await downloadExecutiveDashboardPdf({ analysis, targetPeriod });
      setExportStatus({ state: "success", message: `Executive Dashboard PDF generated for ${targetPeriod}.` });
    } catch (error) {
      setExportStatus({ state: "error", message: error.message || "Executive PDF export failed." });
    }
  };

  return (
    <section className="rounded-[1.75rem] border border-red-400/15 bg-slate-950/85 p-5 shadow-cyber backdrop-blur-xl">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label text-red-300">{labels.title} Comparison Report</p>
          <h2 className="mt-1 text-2xl font-black text-white">{dashboard.reportRange}</h2>
          <p className="mt-1 text-sm font-semibold text-slate-400">{analysis.sourceLabel} | {analysis.inputSummary?.fileCount ?? analysis.snapshots.length} validated files consolidated into {analysis.snapshots.length} {labels.lower} period{analysis.snapshots.length === 1 ? "" : "s"}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="min-w-[190px] rounded-xl border border-red-300/20 bg-black/30 px-3 py-2">
            <span className="mb-1 flex items-center gap-2 text-[0.62rem] font-black uppercase tracking-[0.15em] text-slate-500">
              <CalendarRange className="h-3.5 w-3.5 text-red-300" />PDF Target {labels.singular}
            </span>
            <span className="relative block">
              <select
                aria-label={`PDF target ${labels.unitLower}`}
                value={targetPeriod}
                onChange={(event) => onMonthChange?.(event.target.value)}
                className="w-full appearance-none bg-transparent pr-7 text-sm font-black text-white outline-none"
              >
                {monthOptions.map((period) => <option key={period} value={period}>{period}</option>)}
              </select>
              <ChevronDown className="pointer-events-none absolute right-0 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            </span>
          </label>
          <button type="button" onClick={onBackToDashboard} className="ghost-button flex items-center gap-2 py-3">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </button>
          <button type="button" onClick={onEditUploads} className="ghost-button flex items-center gap-2 py-3">
            <RefreshCcw className="h-4 w-4" />
            Back to {labels.title} Uploads
          </button>
          <button type="button" onClick={downloadExcel} disabled={exportStatus.state === "loading"} className="ghost-button flex items-center gap-2 py-3 disabled:cursor-wait disabled:opacity-50">
            <Download className="h-4 w-4" />
            {exportStatus.state === "loading" ? "Building Excel..." : "Download Excel Report"}
          </button>
          <button type="button" onClick={downloadCsv} disabled={exportStatus.state === "loading"} className="ghost-button flex items-center gap-2 py-3 disabled:opacity-50">
            <Table2 className="h-4 w-4" />
            Normalized CSV
          </button>
          <button type="button" onClick={downloadPdf} disabled={exportStatus.state === "loading"} className="ghost-button flex items-center gap-2 py-3 disabled:cursor-wait disabled:opacity-50">
            <FileText className="h-4 w-4" />
            Remediation PDF
          </button>
          <button type="button" onClick={downloadExecutivePdf} disabled={exportStatus.state === "loading"} className="ghost-button flex items-center gap-2 py-3 disabled:cursor-wait disabled:opacity-50">
            <FileText className="h-4 w-4 text-red-300" />
            Executive PDF
          </button>
          <a href="#ai-report-builder" className="neon-button flex items-center gap-2 py-3">
            <BrainCircuit className="h-4 w-4" />
            AI PDF Options
          </a>
        </div>
      </div>

      {exportStatus.message && (
        <div aria-live="polite" className={`mb-5 rounded-2xl border px-4 py-3 text-xs font-bold ${exportStatus.state === "error" ? "border-red-300/25 bg-red-400/10 text-red-200" : exportStatus.state === "success" ? "border-emerald-300/25 bg-emerald-400/10 text-emerald-200" : "border-cyan-300/25 bg-cyan-400/10 text-cyan-200"}`}>
          Export status: {exportStatus.message}
        </div>
      )}

      <div className="mb-5 rounded-2xl border border-red-300/15 bg-slate-900/70 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <p className="font-mono text-xs font-bold uppercase tracking-[0.16em] text-emerald-300">
            {open.totalOpen.toLocaleString()} open | {open.newVulnerabilities.toLocaleString()} new | {patched.patchedCount.toLocaleString()} patched
          </p>
          <p className="text-xs font-bold text-slate-500">Current report severity distribution</p>
        </div>
        <div className="flex h-3 overflow-hidden rounded-full bg-slate-800">
          {severitySegments.map((segment) => <div key={segment.label} style={{ width: segment.width, backgroundColor: segment.color }} />)}
        </div>
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs font-bold text-slate-400">
          {severitySegments.map((segment) => (
            <span key={segment.label}><span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ backgroundColor: segment.color }} />{segment.label} {segment.value}</span>
          ))}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Total Open Vulnerabilities" value={open.totalOpen} helper={`${open.newVulnerabilities} new + ${open.notClosedFromPreviousMonths} not closed`} color="#f87171" />
        <Kpi label="Immediate Patch Needed" value={(dashboard.totalOpenByPatchPriority.P1 ?? 0) + (dashboard.totalOpenByPatchPriority.P2 ?? 0)} helper="P1 + P2" color="#ef4444" />
        <Kpi label={`Patched Last ${labels.singular}`} value={patched.patchedCount} helper={`${patched.previousPeriod} to ${patched.currentPeriod}`} color="#22c55e" />
        <Kpi label="Periods Compared" value={analysis.snapshots.length} helper={`${analysis.inputSummary?.fileCount ?? analysis.snapshots.length} source file(s)`} color="#38bdf8" />
      </div>

      <div className="mt-5">
        <UnifiedAnalysisDashboard dashboard={dashboard} />
      </div>

      <div className="mt-5">
        <SourceCoveragePanel dashboard={dashboard} inputSummary={analysis.snapshots.at(-1)?.inputSummary ?? analysis.inputSummary} />
      </div>

      <div className="mt-5">
        <CustomerValueDashboards analysis={analysis} />
      </div>

      {dashboard.qualysInsights && (
        <div className="mt-5">
          <QualysInsights insights={dashboard.qualysInsights} />
        </div>
      )}

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <ChartPanel number="1" title={`Vulnerabilities Discovered - Last 3 ${labels.plural}`} subtitle={`New findings first observed in each uploaded ${labels.lower}`}>
          <TrendLineChart data={discoveredTrend} valueKey="discoveredCount" color="#f87171" seriesName="Discovered" />
        </ChartPanel>

        <ChartPanel number="2" title="Total Open Vulnerabilities" subtitle="New findings plus findings not closed from the previous report">
          <div className="grid h-[260px] content-center gap-4 sm:grid-cols-3">
            <OpenMeasure label="Total Open" value={open.totalOpen} color="text-emerald-300" />
            <OpenMeasure label="New" value={open.newVulnerabilities} color="text-sky-300" />
            <OpenMeasure label="Not Closed" value={open.notClosedFromPreviousMonths} color="text-orange-300" />
          </div>
        </ChartPanel>

        <ChartPanel number="3" title="Total Open by Patch Priority" subtitle="Approved severity and exploit-availability matrix">
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={priorityData} margin={{ top: 12, right: 18, bottom: 4, left: -8 }}>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="priority" stroke="#64748b" />
              <YAxis allowDecimals={false} stroke="#64748b" />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" name="Open findings" radius={[8, 8, 0, 0]} isAnimationActive={false}>
                {priorityData.map((entry) => <Cell key={entry.priority} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel number="4" title="Open Findings by Age and Patch Priority" subtitle="Cumulative >7, >30, >60, and >180 day thresholds">
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={ageChartData} margin={{ top: 12, right: 18, bottom: 4, left: -8 }}>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="bucket" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} stroke="#64748b" />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12, fontWeight: 700 }} />
              {Object.entries(PRIORITY_COLORS).map(([priority, color]) => <Bar key={priority} dataKey={priority} fill={color} radius={[4, 4, 0, 0]} isAnimationActive={false} />)}
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>
      </div>

      <div className="mt-5">
        <ChartPanel number="5" title={`Vulnerabilities Patched - Last 3 ${labels.plural}`} subtitle="Findings present in one report and absent from the next">
          <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
            <TrendLineChart data={remediatedTrend} valueKey="remediatedCount" color="#22c55e" seriesName="Patched" />
            <div className="grid content-center gap-3 rounded-2xl border border-emerald-300/20 bg-emerald-400/8 p-5">
              <p className="mini-label">Latest {labels.singular} Calculation</p>
              <p className="text-5xl font-black text-emerald-300">{patched.patchedCount}</p>
              <p className="text-sm font-semibold leading-6 text-slate-400">{patched.previousPeriodOpen} previous open + {patched.newVulnerabilitiesIdentifiedThisPeriod} new - {patched.currentPeriodOpen} current open</p>
            </div>
          </div>
        </ChartPanel>
      </div>

      {dashboard.crowdstrikeInsights && <CrowdStrikeInsights insights={dashboard.crowdstrikeInsights} />}
      {dashboard.openshiftInsights && <OpenShiftInsights insights={dashboard.openshiftInsights} />}

      <div className="mt-5 rounded-2xl border border-white/10 bg-slate-900/70 p-4">
        <div className="mb-3 flex items-center gap-3"><FileSpreadsheet className="h-5 w-5 text-emerald-300" /><h3 className="font-black text-white">Uploaded {labels.singular} Report</h3></div>
        <div className="overflow-auto">
          <table className="w-full min-w-[900px] border-collapse text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500"><tr>{[labels.singular, "Critical", "High", "Medium", "Low", "Total Open", "New", "Patched"].map((heading) => <th key={heading} className="border-b border-white/10 px-3 py-3 font-black">{heading}</th>)}</tr></thead>
            <tbody>{dashboard.severityTrend.map((row, index) => <tr key={row.month} className="border-b border-white/5 text-slate-300"><td className="px-3 py-3 font-bold text-white">{row.month}</td><td className="px-3 py-3 text-red-300">{row.Critical}</td><td className="px-3 py-3 text-orange-300">{row.High}</td><td className="px-3 py-3 text-yellow-200">{row.Medium}</td><td className="px-3 py-3 text-emerald-300">{row.Low}</td><td className="px-3 py-3 font-black text-white">{row.totalOpen}</td><td className="px-3 py-3 text-sky-300">{dashboard.openTrend[index].newThisMonth}</td><td className="px-3 py-3 text-emerald-300">{dashboard.openTrend[index].patchedSinceLastMonth}</td></tr>)}</tbody>
          </table>
        </div>
      </div>

      <div id="ai-report-builder" className="mt-5 grid gap-5 xl:grid-cols-[1fr_430px]">
        <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-5">
          <p className="mini-label">Report Outputs</p>
          <h3 className="mt-1 text-xl font-black text-white">Excel, normalized CSV, and Remediation Guide PDF</h3>
          <p className="mt-3 max-w-3xl text-sm font-semibold leading-6 text-slate-400">Excel, normalized CSV, and the standard PDF are generated locally. Only the selected {labels.unitLower} summary and bounded prioritized findings are sent from the Python API to the configured private AI service when you request an AI-generated guide.</p>
        </article>
        <AiReportBuilder analysis={analysis} selectedMonth={targetPeriod} onMonthChange={onMonthChange} monthOptions={monthOptions} workflow={cadence} />
      </div>
    </section>
  );
}

function MonthlyUploadGate({ selectedSource, onAnalyze, files = [], onFilesChange, onResetUploads, onBackToDashboard, cadence }) {
  const labels = comparisonLabels(cadence);
  const [statusOverride, setStatusOverride] = useState(null);
  const [customConfig, setCustomConfig] = useState({ mapping: {}, severityScale: "auto", exploitMode: "boolean", fileName: "", fields: [] });
  const periodExtractor = cadence === "quarterly" ? extractQuarterFromFilename : extractMonthFromFilename;
  const detectedMonths = [...new Set(files.map((file) => periodExtractor(file.name)?.label).filter(Boolean))];
  const unified = selectedSource.id === "unified";
  const customMappingEnabled = selectedSource.id === "custom-csv" || selectedSource.sourceIds?.includes("custom-csv");
  const status = statusOverride ?? selectionStatus(files.length, cadence, unified ? detectedMonths.length : null);
  const canAnalyze = unified ? detectedMonths.length >= 2 : files.length >= 2;

  const selectFiles = (fileList) => {
    const incomingFiles = Array.from(fileList ?? []);
    const invalid = incomingFiles.find((file) => !isSupportedUploadFile(file));
    if (invalid) {
      setStatusOverride({ state: "error", message: `${invalid.name} is not supported. Upload CSV or XLSX.` });
      return;
    }
    // Functional state prevents rapid consecutive drops from reading stale props.
    onFilesChange?.((currentFiles) => mergeUploadFiles(currentFiles, incomingFiles));
    setStatusOverride(null);
  };

  const removeFile = (file) => {
    onFilesChange?.((currentFiles) => removeUploadFile(currentFiles, file));
    setStatusOverride(null);
  };

  const clearFiles = () => {
    onResetUploads?.();
    setStatusOverride(null);
  };

  const analyze = async () => {
    if (!canAnalyze) return;
    setStatusOverride({ state: "loading", message: `Comparing ${files.length} ${labels.unitLower} reports locally...` });
    try {
      const result = await onAnalyze(files, {
        customMapping: customConfig.mapping,
        customSeverityScale: customConfig.severityScale,
        customExploitMode: customConfig.exploitMode,
      });
      setStatusOverride({ state: "success", message: unified ? `${result.inputSummary.fileCount} files consolidated into ${result.snapshots.length} ${labels.lower} periods.` : `${result.snapshots.length} reports analyzed.` });
    } catch (error) {
      setStatusOverride({ state: "error", message: error.message || `${labels.title} analysis failed.` });
    }
  };

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div><p className="mini-label">{labels.title} Data Comparison</p><h2 className="mt-1 text-2xl font-black text-white">Upload {labels.lower} exports</h2><p className="mt-1 max-w-3xl text-sm font-semibold leading-6 text-slate-400">{unified ? `Add each selected scanner's CSV/XLSX export for every ${labels.unitLower}. Files sharing a ${labels.unitLower} are consolidated into one historical snapshot.` : `Choose two or more ${selectedSource.name} CSV or XLSX files. Use one export per ${labels.unitLower}; CrowdStrike comparison uses Vulnerabilities or Vulnerability per asset exports.`}</p></div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={onBackToDashboard} className="ghost-button flex items-center gap-2 py-2.5">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </button>
          <span className={`rounded-full border px-4 py-2 text-sm font-bold ${canAnalyze ? "border-emerald-300/25 bg-emerald-300/10 text-emerald-200" : "border-white/10 bg-white/5 text-slate-400"}`}>{files.length ? `${files.length} reports selected` : "No reports selected"}</span>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
        <div>
          <label className="group grid min-h-64 cursor-pointer place-items-center rounded-3xl border border-dashed border-white/20 bg-slate-950/50 p-8 text-center transition hover:border-emerald-300/45 hover:bg-emerald-400/5" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); selectFiles(event.dataTransfer.files); }}>
            <input className="sr-only" type="file" accept=".csv,text/csv,.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" multiple onChange={(event) => { selectFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
            <UploadCloud className="mb-4 h-16 w-16 text-slate-300 transition group-hover:text-emerald-300" />
            <p className="text-lg font-black text-white">Drop one or more {labels.lower} CSV/XLSX files here</p>
            <p className="mt-2 text-sm font-semibold text-slate-500">Add files across separate drops or browse actions. Existing selections stay in place.</p>
          </label>
          {files.length > 0 && (
            <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/55 p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-black text-white">Selected {labels.lower} reports</p>
                  <p className="mt-1 text-xs font-semibold text-slate-500">Matching filenames are replaced; every other report is added.</p>
                </div>
                <button type="button" onClick={clearFiles} className="flex items-center gap-2 rounded-xl border border-red-300/20 bg-red-400/10 px-3 py-2 text-xs font-black text-red-200 transition hover:bg-red-400/20">
                  <Trash2 className="h-4 w-4" />
                  Clear all
                </button>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {files.map((file) => (
                  <article key={uploadFileKey(file)} className="flex min-w-0 items-center gap-3 rounded-2xl border border-cyan-300/15 bg-cyan-400/[0.06] p-3">
                    <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-200"><FileText className="h-5 w-5" /></span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-black uppercase tracking-wide text-cyan-200">{periodExtractor(file.name)?.label ?? `${labels.singular} detected during analysis`}</p>
                      <p className="mt-1 truncate text-xs font-semibold text-slate-400" title={file.name}>{file.name}</p>
                    </div>
                    <button type="button" onClick={() => removeFile(file)} aria-label={`Remove ${file.name}`} title={`Remove ${file.name}`} className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-white/10 text-slate-400 transition hover:border-red-300/30 hover:bg-red-400/10 hover:text-red-200"><X className="h-4 w-4" /></button>
                  </article>
                ))}
              </div>
            </div>
          )}
          {selectedSource.id === "crowdstrike" && (
            <div className="mt-4 block rounded-2xl border border-red-300/15 bg-red-400/5 p-4">
              <span className="mb-2 block text-xs font-black uppercase tracking-wide text-red-200">CrowdStrike {labels.lower} export type</span>
              <p className="text-sm font-semibold leading-6 text-slate-400">Use Vulnerabilities or Vulnerability per asset exports. The type is detected from headers; include the reporting period in every filename.</p>
              <p className="mt-3 font-mono text-xs font-semibold text-slate-400">Examples: {crowdStrikeFilenameExamples(cadence)}</p>
            </div>
          )}
          {customMappingEnabled && <CustomFieldMapper files={files} value={customConfig} onChange={setCustomConfig} />}
          <div className="mt-4">
            <button type="button" onClick={analyze} disabled={!canAnalyze || status.state === "loading"} className="neon-button disabled:cursor-not-allowed disabled:opacity-45">{status.state === "loading" ? `Analyzing ${labels.title} Reports...` : `Analyze & Generate ${labels.title} Report`}</button>
          </div>
          <p className={`mt-3 rounded-xl border px-4 py-3 text-xs font-bold ${status.state === "error" ? "border-red-300/25 bg-red-400/10 text-red-100" : status.state === "ready" ? "border-emerald-300/25 bg-emerald-400/10 text-emerald-100" : "border-white/10 bg-white/5 text-slate-400"}`}>{status.message}</p>
        </div>
        <div className="grid gap-4">
          <Requirement title={`2+ ${labels.title} Periods`} body={unified ? `Upload one file per selected tool for at least two distinct ${labels.lower} periods.` : "Calculates total open, new, not closed, and patched findings."} />
          <Requirement title={`3+ ${labels.title} Periods`} body={`Builds the required three-${labels.unitLower} discovered and patched line charts.`} />
          <Requirement title="Auto Field Mapping" body={unified ? "Every file is independently detected and mapped before multi-tool consolidation." : `${selectedSource.name} headers are detected and normalized before comparison.`} />
          {detectedMonths.length > 0 && <Requirement title={`Detected ${labels.plural}`} body={detectedMonths.join(" | ")} />}
        </div>
      </div>
    </section>
  );
}

function selectionStatus(fileCount, cadence = "monthly", detectedPeriodCount = null) {
  const lower = cadence === "quarterly" ? "quarterly" : "monthly";
  if (detectedPeriodCount != null) {
    if (fileCount === 0) return { state: "idle", message: `Select exports for at least two distinct ${lower} periods.` };
    if (detectedPeriodCount < 2) return { state: "idle", message: `${fileCount} file(s) selected for ${detectedPeriodCount || 0} detected period. Add another ${lower} period.` };
    return { state: "ready", message: `${fileCount} files across ${detectedPeriodCount} ${lower} periods are ready for consolidated analysis.` };
  }
  if (fileCount === 0) return { state: "idle", message: `Select at least two ${lower} CSV or XLSX exports.` };
  if (fileCount === 1) return { state: "idle", message: `1 ${lower} report selected. Add one more report to compare.` };
  return { state: "ready", message: `${fileCount} ${lower} reports ready. You can add or remove files before analysis.` };
}

function crowdStrikeFilenameExamples(cadence) {
  const period = cadence === "quarterly" ? "q3_2026" : "july_2026";
  return `crowdstrike_vulnerabilities_${period}.csv or crowdstrike_vulnerability_per_asset_${period}.xlsx`;
}

function comparisonLabels(cadence) {
  return cadence === "quarterly"
    ? { title: "Quarterly", lower: "quarterly", unitLower: "quarter", singular: "Quarter", plural: "Quarters" }
    : { title: "Monthly", lower: "monthly", unitLower: "month", singular: "Month", plural: "Months" };
}

function TrendLineChart({ data = [], valueKey, color, seriesName }) {
  const width = 760;
  const height = 260;
  const plot = { left: 58, top: 24, right: 24, bottom: 54 };
  const plotWidth = width - plot.left - plot.right;
  const plotHeight = height - plot.top - plot.bottom;
  const values = data.map((row) => Math.max(0, Number(row[valueKey]) || 0));
  const maxValue = Math.max(1, ...values);
  const axisMax = Math.max(5, Math.ceil(maxValue / 5) * 5);
  const xFor = (index) => plot.left + (data.length <= 1 ? plotWidth / 2 : (index / (data.length - 1)) * plotWidth);
  const yFor = (value) => plot.top + plotHeight - (value / axisMax) * plotHeight;
  const points = data.map((row, index) => `${xFor(index)},${yFor(values[index])}`).join(" ");
  const areaPoints = data.length ? `${plot.left},${plot.top + plotHeight} ${points} ${xFor(data.length - 1)},${plot.top + plotHeight}` : "";
  const gradientId = `trend-${valueKey}`;
  const ticks = Array.from({ length: 5 }, (_, index) => Math.round((axisMax * index) / 4));

  return (
    <div className="min-w-0" role="img" aria-label={`${seriesName} line chart: ${data.map((row, index) => `${row.period ?? row.month}, ${values[index]}`).join("; ")}`}>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[260px] w-full overflow-visible" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.3" />
            <stop offset="100%" stopColor={color} stopOpacity="0.015" />
          </linearGradient>
        </defs>
        {ticks.map((tick) => {
          const y = yFor(tick);
          return (
            <g key={tick}>
              <line x1={plot.left} y1={y} x2={width - plot.right} y2={y} stroke="#24324a" strokeDasharray="5 6" />
              <text x={plot.left - 13} y={y + 4} textAnchor="end" fill="#8290a8" fontSize="12" fontWeight="700">{tick}</text>
            </g>
          );
        })}
        {areaPoints && <polygon points={areaPoints} fill={`url(#${gradientId})`} />}
        {points && <polyline points={points} fill="none" stroke={color} strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />}
        {data.map((row, index) => {
          const x = xFor(index);
          const y = yFor(values[index]);
          return (
            <g key={`${row.period ?? row.month}-${index}`}>
              <circle cx={x} cy={y} r="7" fill="#09090b" stroke={color} strokeWidth="4" vectorEffect="non-scaling-stroke" />
              <text x={x} y={Math.max(16, y - 14)} textAnchor="middle" fill="#f8fafc" fontSize="13" fontWeight="900">{values[index]}</text>
              <text x={x} y={height - 20} textAnchor="middle" fill="#a7b3c7" fontSize="12" fontWeight="800">{row.period ?? row.month}</text>
            </g>
          );
        })}
      </svg>
      <div className="grid gap-2 sm:grid-cols-3">
        {data.map((row, index) => (
          <div key={`${seriesName}-${row.period ?? row.month}`} className="rounded-xl border border-white/10 bg-slate-950/55 px-3 py-2 text-center">
            <p className="text-[0.65rem] font-black uppercase tracking-wide text-slate-500">{row.period ?? row.month}</p>
            <p className="mt-1 text-lg font-black" style={{ color }}>{values[index].toLocaleString()}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function Kpi({ label, value, helper, color }) {
  return <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-4"><p className="font-mono text-[0.65rem] font-bold uppercase tracking-[0.15em] text-slate-500">{label}</p><p className="mt-2 text-3xl font-black tracking-[-0.05em]" style={{ color }}>{typeof value === "number" ? value.toLocaleString() : value}</p><p className="mt-1 truncate text-xs font-semibold text-slate-500" title={helper}>{helper}</p></article>;
}

function ChartPanel({ number, title, subtitle, children }) {
  return <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-5"><div className="mb-3 flex items-start gap-3"><span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-red-300/25 bg-red-400/10 font-mono text-xs font-black text-red-200">{number}</span><div><h3 className="font-black text-white">{title}</h3><p className="mt-1 text-xs font-semibold text-slate-500">{subtitle}</p></div></div>{children}</article>;
}

function OpenMeasure({ label, value, color }) {
  return <div className="rounded-2xl border border-white/10 bg-slate-950/55 p-5 text-center"><p className={`text-4xl font-black ${color}`}>{Number(value).toLocaleString()}</p><p className="mt-2 text-xs font-black uppercase tracking-wide text-slate-500">{label}</p></div>;
}

function Requirement({ title, body }) {
  return <div className="rounded-2xl border border-white/10 bg-slate-950/55 p-5"><div className="mb-3 flex items-center gap-3"><CalendarRange className="h-5 w-5 text-cyan-300" /><p className="font-black text-white">{title}</p></div><p className="text-sm font-semibold leading-6 text-slate-500">{body}</p></div>;
}

const tooltipStyle = { background: "#09090b", border: "1px solid #3f3f46", borderRadius: 12, color: "#f4f4f5" };
