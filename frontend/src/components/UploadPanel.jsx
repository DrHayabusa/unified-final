import { useState } from "react";
import { ArrowLeft, CheckCircle2, CloudUpload, FileSearch, FileSpreadsheet, FileText, LockKeyhole, Table2, Trash2, Upload, X } from "lucide-react";
import { downloadAnalysisWorkbook, downloadNormalizedCsv } from "../lib/reportExport.jsx";
import { buildTemplateMarkdown, downloadRemediationPdf } from "../lib/pdfReport.jsx";
import { downloadExecutiveDashboardPdf } from "../lib/executiveReportPdf.jsx";
import { isSupportedUploadFile, mergeUploadFiles, removeUploadFile, uploadFileKey } from "../lib/uploadFiles.jsx";
import { CustomFieldMapper } from "./CustomFieldMapper.jsx";

export function UploadPanel({ selectedSource, analysis, files = [], onFilesChange, onAnalyze, onBackToDashboard, workflow = "adhoc" }) {
  const [customConfig, setCustomConfig] = useState({ mapping: {}, severityScale: "auto", exploitMode: "boolean", fileName: "", fields: [] });
  const [status, setStatus] = useState({ state: "idle", message: "" });
  const quarterly = workflow === "quarterly-scan";
  const workflowLabel = quarterly ? "Quarterly" : "Ad hoc";
  const unified = selectedSource.id === "unified";
  const customMappingEnabled = selectedSource.id === "custom-csv" || selectedSource.sourceIds?.includes("custom-csv");
  const file = files[0] ?? null;

  const selectFiles = (fileList) => {
    const incomingFiles = Array.from(fileList ?? []);
    if (!incomingFiles.length) return;
    const invalid = incomingFiles.find((nextFile) => !isSupportedUploadFile(nextFile));
    if (invalid) {
      setStatus({ state: "error", message: `${invalid.name} is not supported. Upload CSV or XLSX; legacy XLS must first be saved as XLSX.` });
      return;
    }
    onFilesChange?.((currentFiles) => unified ? mergeUploadFiles(currentFiles, incomingFiles) : [incomingFiles.at(-1)]);
    setStatus({ state: "ready", message: unified ? `${incomingFiles.length} file(s) added. Existing selections remain available.` : `${incomingFiles.at(-1).name} is ready for local analysis.` });
  };

  const runAnalysis = async () => {
    if (!files.length || status.state === "loading") return;
    setStatus({ state: "loading", message: `Reading, detecting, and normalizing ${files.length} export${files.length === 1 ? "" : "s"}...` });
    try {
      const result = await onAnalyze?.(files, {
        customMapping: customConfig.mapping,
        customSeverityScale: customConfig.severityScale,
        customExploitMode: customConfig.exploitMode,
      });
      setStatus({
        state: "success",
        message: `${result?.sourceLabel ?? selectedSource.name}: ${result?.dashboard?.totalVulnerabilities?.toLocaleString() ?? 0} consolidated open findings from ${result?.inputSummary?.fileCount ?? files.length} file(s).`,
      });
    } catch (error) {
      setStatus({ state: "error", message: error.message || "Analysis failed." });
    }
  };

  const removeFile = (fileToRemove) => {
    onFilesChange?.((currentFiles) => removeUploadFile(currentFiles, fileToRemove));
    setStatus({ state: "ready", message: `${fileToRemove.name} removed.` });
  };

  const clearFiles = () => {
    onFilesChange?.([]);
    setStatus({ state: "idle", message: "All selected files were cleared." });
  };

  const downloadExcel = async () => {
    if (!analysis || status.state === "loading") return;
    setStatus({ state: "loading", message: `Building the ${workflowLabel} Excel report...` });
    try {
      await downloadAnalysisWorkbook(analysis);
      setStatus({ state: "success", message: `${workflowLabel} Excel report generated and downloaded.` });
    } catch (error) {
      setStatus({ state: "error", message: error.message || "Excel export failed." });
    }
  };

  const downloadCsv = () => {
    if (!analysis || status.state === "loading") return;
    try {
      downloadNormalizedCsv(analysis);
      setStatus({ state: "success", message: "Normalized findings CSV generated and downloaded." });
    } catch (error) {
      setStatus({ state: "error", message: error.message || "CSV export failed." });
    }
  };

  const downloadPdf = async () => {
    if (!analysis || status.state === "loading") return;
    const targetMonth = analysis.reportPeriod || analysis.reportMonth || `${workflowLabel} Report`;
    setStatus({ state: "loading", message: `Building the ${workflowLabel} Remediation Guide PDF...` });
    try {
      const markdown = buildTemplateMarkdown({ analysis, targetMonth });
      await downloadRemediationPdf({ markdown, sourceLabel: analysis.sourceLabel, targetMonth, workflow: analysis.workflow || workflow });
      setStatus({ state: "success", message: `${workflowLabel} Remediation Guide PDF generated and downloaded.` });
    } catch (error) {
      setStatus({ state: "error", message: error.message || "PDF export failed." });
    }
  };

  const downloadExecutivePdf = async () => {
    if (!analysis || status.state === "loading") return;
    const targetPeriod = analysis.reportPeriod || analysis.reportMonth || `${workflowLabel} Report`;
    setStatus({ state: "loading", message: `Building the ${workflowLabel} Executive Dashboard PDF...` });
    try {
      await downloadExecutiveDashboardPdf({ analysis, targetPeriod });
      setStatus({ state: "success", message: `${workflowLabel} Executive Dashboard PDF generated and downloaded.` });
    } catch (error) {
      setStatus({ state: "error", message: error.message || "Executive PDF export failed." });
    }
  };

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">{quarterly ? "Quarterly Scan Intake" : "Upload Export File"}</p>
          <h2 className="mt-1 text-2xl font-black text-white">{quarterly ? unified ? "Multi-source 3-month analysis" : "Single-export 3-month analysis" : "Ad hoc file intake"}</h2>
          <p className="mt-1 text-sm font-semibold text-slate-400">
            {quarterly
              ? unified ? "Combine one current scan export per selected tool and chart findings discovered during the latest three months." : `Analyze one ${selectedSource.name} CSV or XLSX and chart findings discovered during its latest three months.`
              : unified ? "Add one or more exports from every selected scanner for one consolidated current-state dashboard." : `Analyze one ${selectedSource.name} CSV or XLSX with automatic export-type detection.`}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={onBackToDashboard} className="ghost-button flex items-center gap-2 py-2.5">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </button>
          <div className="rounded-full border border-red-300/25 bg-red-400/[0.07] px-4 py-2 text-sm font-bold text-red-200">CSV/XLSX up to 500MB</div>
        </div>
      </div>

      <label
        className="group grid min-h-56 cursor-pointer place-items-center rounded-3xl border border-dashed border-white/20 bg-slate-950/50 p-8 text-center transition hover:border-emerald-300/45 hover:bg-emerald-400/5"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault();
          selectFiles(event.dataTransfer.files);
        }}
      >
        <input className="sr-only" type="file" accept=".csv,text/csv,.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" multiple={unified} onChange={(event) => { selectFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        {analysis ? (
          <CheckCircle2 className="mb-4 h-16 w-16 text-emerald-300" />
        ) : (
          <CloudUpload className="mb-4 h-16 w-16 text-slate-300 transition group-hover:text-emerald-300" />
        )}
        <p className="text-lg font-black text-white">
          {analysis ? "Analysis complete" : files.length ? unified ? `${files.length} exports ready` : file.name : unified ? "Drop scanner exports here or click to multi-select" : "Drop one CSV or XLSX here or click once to browse"}
        </p>
        <p className="mt-2 text-sm font-semibold text-slate-500">
          {analysis ? `${analysis.exportType} detected automatically` : files.length ? unified ? "Separate drops append; matching filenames replace the older copy." : formatBytes(file.size) : "Raw files remain in this browser and are never stored by MVA."}
        </p>
      </label>

      {files.length > 0 && (
        <div className="mt-4 rounded-2xl border border-white/10 bg-black/25 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div><p className="text-sm font-black text-white">Selected exports</p><p className="mt-1 text-xs font-semibold text-slate-500">{files.length} file{files.length === 1 ? "" : "s"} ready for source detection</p></div>
            <button type="button" onClick={clearFiles} className="flex items-center gap-2 rounded-xl border border-red-300/20 bg-red-400/10 px-3 py-2 text-xs font-black text-red-200"><Trash2 className="h-4 w-4" />Clear all</button>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {files.map((selectedFile) => (
              <article key={uploadFileKey(selectedFile)} className="flex min-w-0 items-center gap-3 rounded-xl border border-white/10 bg-white/[0.025] p-3">
                <FileText className="h-5 w-5 shrink-0 text-cyan-300" />
                <div className="min-w-0 flex-1"><p className="truncate text-xs font-black text-white" title={selectedFile.name}>{selectedFile.name}</p><p className="mt-1 text-[0.65rem] font-semibold text-slate-500">{formatBytes(selectedFile.size)}</p></div>
                <button type="button" onClick={() => removeFile(selectedFile)} aria-label={`Remove ${selectedFile.name}`} className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-white/10 text-slate-400 hover:border-red-300/30 hover:text-red-200"><X className="h-4 w-4" /></button>
              </article>
            ))}
          </div>
        </div>
      )}

      {selectedSource.id === "crowdstrike" && (
        <div className="mt-4 rounded-2xl border border-red-300/15 bg-red-400/5 p-4">
          <p className="text-xs font-black uppercase tracking-wide text-red-200">CrowdStrike export detection</p>
          <p className="mt-2 text-sm font-semibold leading-6 text-slate-400">Vulnerabilities, Vulnerability per asset, and Remediation per assets exports are detected automatically from their headers.</p>
        </div>
      )}

      {customMappingEnabled && <CustomFieldMapper files={files} value={customConfig} onChange={setCustomConfig} />}

      <div className="mt-4 grid gap-3 sm:grid-cols-[auto_1fr]">
        <button
          type="button"
          onClick={runAnalysis}
          disabled={!files.length || status.state === "loading"}
          className="neon-button flex items-center justify-center gap-2 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {status.state === "loading" ? <FileSearch className="h-4 w-4 animate-pulse" /> : <Upload className="h-4 w-4" />}
          {status.state === "loading" ? "Working..." : analysis ? "Re-analyze Selected Exports" : quarterly ? "Analyze 3-Month Scan" : "Analyze & Generate Dashboard"}
        </button>
        <div
          className={`rounded-xl border px-4 py-3 text-xs font-bold ${
            status.state === "error"
              ? "border-red-300/25 bg-red-400/10 text-red-100"
              : status.state === "success"
                ? "border-emerald-300/25 bg-emerald-400/10 text-emerald-100"
                : "border-white/10 bg-white/5 text-slate-400"
          }`}
        >
          {status.message || (unified ? "Select exports from at least two enabled scanner tools." : "Select a CSV or XLSX export to begin.")}
        </div>
      </div>

      {analysis && (
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <button type="button" onClick={downloadExcel} disabled={status.state === "loading"} className="ghost-button flex items-center justify-center gap-2 disabled:cursor-wait disabled:opacity-45">
            <FileSpreadsheet className="h-4 w-4 text-emerald-300" />
            Download Excel Report
          </button>
          <button type="button" onClick={downloadCsv} disabled={status.state === "loading"} className="ghost-button flex items-center justify-center gap-2 disabled:cursor-wait disabled:opacity-45">
            <Table2 className="h-4 w-4 text-cyan-300" />
            Download Normalized CSV
          </button>
          <button type="button" onClick={downloadPdf} disabled={status.state === "loading"} className="neon-button flex items-center justify-center gap-2 disabled:cursor-wait disabled:opacity-45">
            <FileText className="h-4 w-4" />
            Remediation Guide PDF
          </button>
          <button type="button" onClick={downloadExecutivePdf} disabled={status.state === "loading"} className="ghost-button flex items-center justify-center gap-2 disabled:cursor-wait disabled:opacity-45">
            <FileText className="h-4 w-4 text-red-300" />
            Executive Dashboard PDF
          </button>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-3">
        <span className="rounded-xl border border-emerald-300/25 bg-emerald-400/10 px-3 py-2 text-xs font-bold text-emerald-200">Local CSV/XLSX processing</span>
        <span className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs font-bold text-slate-400">
          <LockKeyhole className="h-4 w-4 text-emerald-300" />
          Raw files stay local; normalized results are saved to the selected tenant
        </span>
      </div>
    </section>
  );
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}
