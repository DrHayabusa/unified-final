import { useState } from "react";
import { ArrowLeft, Bot, Database, ExternalLink, FileText, Radar, Search, Server, ShieldAlert, Sparkles, Trash2, UploadCloud, X } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { buildLocalThreatIntel, normalizeThreatIntel, parseThreatIntelResponse } from "../lib/threatIntel.jsx";
import { parseExportFile, normalizeRows } from "../lib/vulnerabilityEngine.jsx";
import {
  enrichThreatIntelWithLocalLlm,
  importThreatIntelRecords,
  searchThreatIntelRecords,
} from "../lib/platformApi.jsx";
import { isSupportedUploadFile, mergeUploadFiles, removeUploadFile, uploadFileKey } from "../lib/uploadFiles.jsx";
import { CustomFieldMapper } from "./CustomFieldMapper.jsx";

const SOURCES = [
  { id: "stored", label: "Tenant CVE Library", helper: "Search normalized evidence retained in this tenant's PostgreSQL library.", icon: Database },
  { id: "current", label: "Current Analysis", helper: "Search the scanner findings analyzed in this browser session.", icon: Search },
  { id: "ollama", label: "Local Ollama Intelligence", helper: "Enrich stored tenant evidence through the backend-managed Gemma model.", icon: Bot },
];

export function ThreatIntelPanel({ analysis, onBackToDashboard }) {
  const platform = usePlatform();
  const [query, setQuery] = useState("");
  const [sourceId, setSourceId] = useState("stored");
  const [files, setFiles] = useState([]);
  const [importProfile, setImportProfile] = useState("auto");
  const [customConfig, setCustomConfig] = useState({ mapping: {}, severityScale: "auto", exploitMode: "boolean", fileName: "", fields: [] });
  const [importStatus, setImportStatus] = useState({ state: "idle", message: "Upload scanner exports to build the tenant CVE library.", completed: 0, total: 0 });
  const [status, setStatus] = useState({ state: "idle", message: "Enter a vulnerability name, CVE, QID, or plugin identifier." });
  const [result, setResult] = useState(null);
  const selectedSource = SOURCES.find((source) => source.id === sourceId) ?? SOURCES[0];
  const busy = status.state === "loading";
  const canWrite = platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(platform.selectedCustomer?.membershipRole);

  const addFiles = (fileList) => {
    const incoming = Array.from(fileList ?? []);
    const invalid = incoming.find((file) => !isSupportedUploadFile(file));
    if (invalid) {
      setImportStatus({ state: "error", message: `${invalid.name} is not supported. Upload CSV or XLSX.`, completed: 0, total: 0 });
      return;
    }
    setFiles((current) => mergeUploadFiles(current, incoming));
    setImportStatus({ state: "ready", message: `${mergeUploadFiles(files, incoming).length} file(s) selected for local parsing.`, completed: 0, total: 0 });
  };

  const importFiles = async () => {
    if (!files.length || !platform.selectedCustomerId || !platform.csrfToken || !canWrite) {
      setImportStatus({ state: "error", message: "Select files and use an owner or analyst tenant session.", completed: 0, total: 0 });
      return;
    }
    setImportStatus({ state: "loading", message: "Parsing and normalizing scanner evidence locally...", completed: 0, total: 0 });
    try {
      const parsedFiles = await Promise.all(files.map((file) => parseExportFile(file, { allowUnknown: true })));
      const findings = parsedFiles.flatMap((parsed) => {
        let sourceTool = parsed.sourceTool;
        if (importProfile === "custom-csv") {
          sourceTool = "custom-csv";
        } else if (importProfile === "custom-qualys" && sourceTool.startsWith("qualys-")) {
          sourceTool = sourceTool === "qualys-monthly" ? "qualys-custom-monthly" : "qualys-custom-adhoc";
        }
        return normalizeRows(parsed.rows, sourceTool, {
          customMapping: customConfig.mapping,
          customSeverityScale: customConfig.severityScale,
          customExploitMode: customConfig.exploitMode,
        });
      });
      const records = findings.map(threatIntelRecord);
      if (!records.length) throw new Error("The selected files contain no open vulnerability records after normalization.");
      const ingestionKey = await threatIntelIngestionKey(files, records);
      const imported = await importThreatIntelRecords(platform.selectedCustomerId, {
        ingestionKey,
        sourceLabel: sourceLabelForImport(parsedFiles, importProfile),
        fileNames: files.map((file) => file.name),
        records,
        csrfToken: platform.csrfToken,
        onProgress: ({ completed, total }) => setImportStatus({
          state: "loading",
          message: `Stored ${completed.toLocaleString()} of ${total.toLocaleString()} normalized intelligence records...`,
          completed,
          total,
        }),
      });
      setImportStatus({
        state: "success",
        message: `${imported.receivedRecords.toLocaleString()} records are ready in ${platform.selectedCustomer?.name}'s CVE library.`,
        completed: imported.receivedRecords,
        total: imported.expectedRecords,
      });
    } catch (error) {
      setImportStatus({ state: "error", message: error.message || "Threat-intelligence import failed.", completed: 0, total: 0 });
    }
  };

  const investigate = async (event) => {
    event.preventDefault();
    const searchText = query.trim();
    if (searchText.length < 2) {
      setStatus({ state: "error", message: "Enter a vulnerability name, CVE, QID, or plugin identifier." });
      return;
    }
    if (!platform.selectedCustomerId) {
      setStatus({ state: "error", message: "Select a tenant before searching threat intelligence." });
      return;
    }

    setStatus({ state: "loading", message: `Investigating ${searchText}...` });
    setResult(null);
    try {
      if (sourceId === "current") {
        setResult(normalizeThreatIntel(buildLocalThreatIntel(analysis, searchText), analysis?.sourceLabel));
      } else if (sourceId === "stored") {
        const response = await searchThreatIntelRecords(platform.selectedCustomerId, searchText, { limit: 100 });
        if (!response.records?.length) throw new Error(`No stored tenant evidence matched "${searchText}". Import scanner data first.`);
        const local = buildLocalThreatIntel(recordsAsAnalysis(response.records), searchText);
        setResult(normalizeThreatIntel(local, "Tenant CVE Library"));
      } else {
        if (!canWrite) throw new Error("An owner or analyst role is required for local AI enrichment.");
        const response = await enrichThreatIntelWithLocalLlm(platform.selectedCustomerId, searchText, platform.csrfToken);
        const intel = parseThreatIntelResponse(response.content, `Local Ollama - ${response.model}`);
        setResult({ ...intel, matchedFindings: response.evidenceCount || intel.matchedFindings });
      }
      setStatus({ state: "success", message: "Threat-intelligence analysis completed." });
    } catch (error) {
      setStatus({ state: "error", message: threatIntelError(error) });
    }
  };

  return (
    <div className="space-y-4">
      <section className="enterprise-panel p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-red-400/20 bg-red-500/[0.08] text-red-200"><Radar className="h-6 w-6" /></span>
            <div><p className="mini-label">Intelligence as a Service</p><h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">Threat Intelligence Feed</h2><p className="mt-2 max-w-3xl text-sm font-medium leading-6 text-slate-400">Build a tenant CVE library from scanner exports, search retained evidence, and request defensive enrichment through the local Gemma/Ollama service.</p></div>
          </div>
          <button type="button" onClick={onBackToDashboard} className="secondary-button flex items-center gap-2"><ArrowLeft className="h-4 w-4" />Back to Dashboards</button>
        </div>
      </section>

      <section className="enterprise-panel p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div><p className="mini-label">Tenant evidence onboarding</p><h3 className="mt-1 text-xl font-extrabold text-white">Import scanner CVE data</h3><p className="mt-2 text-xs font-medium leading-5 text-slate-500">Files are parsed in this browser. Normalized vulnerability evidence is stored; raw scanner files are not uploaded.</p></div>
          <label className="min-w-52"><span className="admin-label">Parsing profile</span><select value={importProfile} onChange={(event) => setImportProfile(event.target.value)} className="admin-input text-xs"><option value="auto">Auto-detect scanner</option><option value="custom-qualys">Custom Qualys rating</option><option value="custom-csv">Universal custom mapping</option></select></label>
        </div>

        <label className="group grid min-h-44 cursor-pointer place-items-center rounded-2xl border border-dashed border-white/[0.14] bg-black/20 p-6 text-center transition hover:border-red-400/35 hover:bg-red-500/[0.03]" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); addFiles(event.dataTransfer.files); }}>
          <input className="sr-only" type="file" accept=".csv,text/csv,.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" multiple onChange={(event) => { addFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
          <span><UploadCloud className="mx-auto h-10 w-10 text-red-300" /><p className="mt-3 font-extrabold text-white">Drop CSV/XLSX exports or browse</p><p className="mt-1 text-xs font-medium text-slate-600">Add files across multiple drops; existing selections remain.</p></span>
        </label>

        {files.length > 0 && (
          <div className="mt-4 rounded-2xl border border-white/[0.07] bg-black/20 p-4">
            <div className="mb-3 flex items-center justify-between gap-3"><p className="text-sm font-extrabold text-white">{files.length} selected file(s)</p><button type="button" onClick={() => setFiles([])} className="flex items-center gap-2 text-xs font-bold text-red-300"><Trash2 className="h-4 w-4" />Clear all</button></div>
            <div className="grid gap-2 md:grid-cols-2">
              {files.map((file) => <article key={uploadFileKey(file)} className="flex min-w-0 items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"><FileText className="h-4 w-4 shrink-0 text-slate-500" /><span className="min-w-0 flex-1 truncate text-xs font-bold text-slate-300">{file.name}</span><button type="button" onClick={() => setFiles((current) => removeUploadFile(current, file))} aria-label={`Remove ${file.name}`}><X className="h-4 w-4 text-slate-600 hover:text-red-300" /></button></article>)}
            </div>
          </div>
        )}

        {importProfile === "custom-csv" && <CustomFieldMapper files={files} value={customConfig} onChange={setCustomConfig} />}

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button type="button" onClick={importFiles} disabled={!files.length || importStatus.state === "loading" || !canWrite} className="primary-button flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-40"><Database className="h-4 w-4" />{importStatus.state === "loading" ? "Importing evidence..." : "Import to Tenant CVE Library"}</button>
          <ImportStatus status={importStatus} />
        </div>
      </section>

      <section className="enterprise-panel p-5 sm:p-6">
        <form onSubmit={investigate} className="grid gap-5 xl:grid-cols-[1fr_340px]">
          <div className="space-y-5">
            <label className="block">
              <span className="admin-label">Vulnerability, CVE, QID, or plugin</span>
              <div className="flex overflow-hidden rounded-2xl border border-white/[0.1] bg-black/30 transition focus-within:border-red-400/40 focus-within:ring-4 focus-within:ring-red-500/[0.06]">
                <Search className="ml-4 mt-4 h-5 w-5 shrink-0 text-red-300" />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Example: CVE-2021-44228 or Apache Log4j RCE" className="min-w-0 flex-1 bg-transparent px-4 py-4 font-semibold text-white outline-none placeholder:text-slate-700" />
                <button type="submit" disabled={busy} className="m-2 rounded-xl bg-red-600 px-5 py-3 text-sm font-extrabold text-white transition hover:bg-red-500 disabled:cursor-wait disabled:opacity-50">{busy ? "Investigating..." : "Investigate"}</button>
              </div>
            </label>

            <div className="grid gap-3 md:grid-cols-3">
              {SOURCES.map((source) => {
                const Icon = source.icon;
                const active = source.id === sourceId;
                return <button key={source.id} type="button" onClick={() => { setSourceId(source.id); setResult(null); }} className={`rounded-2xl border p-4 text-left transition ${active ? "border-red-400/30 bg-red-500/[0.08]" : "border-white/[0.07] bg-white/[0.02] hover:border-white/15 hover:bg-white/[0.035]"}`}><div className="flex items-center gap-3"><Icon className={`h-5 w-5 ${active ? "text-red-300" : "text-slate-600"}`} /><p className="font-extrabold text-white">{source.label}</p></div><p className="mt-2 text-xs font-medium leading-5 text-slate-600">{source.helper}</p></button>;
              })}
            </div>
            <Status status={status} />
          </div>

          <aside className="rounded-2xl border border-white/[0.07] bg-black/20 p-5">
            <p className="mini-label">Investigation route</p>
            <h3 className="mt-2 text-lg font-extrabold text-white">{selectedSource.label}</h3>
            <p className="mt-2 text-xs font-medium leading-5 text-slate-600">{selectedSource.helper}</p>
            <div className="mt-5 space-y-3 text-xs font-semibold text-slate-400">
              <ContextRow label="Tenant" value={platform.selectedCustomer?.name || "Not selected"} />
              <ContextRow label="Current dataset" value={analysis?.sourceLabel || "No active analysis"} />
              <ContextRow label="Raw file transfer" value="Never" />
            </div>
          </aside>
        </form>

        {result && <ThreatIntelResult result={result} />}
      </section>
    </div>
  );
}

function threatIntelRecord(finding) {
  return {
    cve: finding.cve,
    vulnerabilityName: finding.vulnerabilityName,
    sourceTool: finding.sourceTool,
    sourceVulnerabilityId: finding.sourceVulnerabilityId,
    ipAddress: finding.ipAddress,
    dnsName: finding.dnsName,
    severity: finding.severity,
    patchPriority: finding.patchPriority,
    exploitAvailable: finding.exploitAvailable,
    vulnerabilityConfidence: finding.vulnerabilityConfidence,
    exploitEvidence: finding.exploitSignal,
    description: finding.description || finding.summary,
    remediation: finding.remediation,
    kbLinks: finding.kbLinks,
    product: finding.product,
    platformDetails: finding.platformDetails,
    namespace: finding.namespace,
    deployment: finding.deployment,
    image: finding.image,
    component: finding.component,
    fixable: finding.fixable,
    fixedIn: finding.fixedIn,
    cvssScore: finding.cvssScore,
    firstObserved: finding.firstDiscovered,
    lastObserved: finding.lastObserved,
  };
}

function sourceLabelForImport(parsedFiles, profile) {
  if (profile === "custom-qualys") return "Custom Qualys";
  if (profile === "custom-csv") return "Custom Scanner";
  const labels = [...new Set(parsedFiles.map((parsed) => parsed.sourceTool))];
  return labels.length === 1 ? labels[0] : "Multi-Tool Scanner Evidence";
}

function recordsAsAnalysis(records) {
  return {
    sourceLabel: "Tenant CVE Library",
    findings: records.map((record, index) => ({
      ...record,
      findingKey: `${record.importId || "stored"}:${index}`,
      exploitSignal: record.exploitEvidence,
      firstDiscovered: record.firstObserved,
      lastObserved: record.lastObserved,
      recordCount: 1,
      dnsName: record.dnsName || "",
      ipAddress: record.ipAddress || "",
      summary: record.description,
    })),
  };
}

async function threatIntelIngestionKey(files, records) {
  const identity = [
    ...files.map((file) => `${file.name}:${file.size}:${file.lastModified}`).sort(),
    ...records.map((record) => `${record.sourceTool}|${record.sourceVulnerabilityId}|${record.cve}|${record.vulnerabilityName}|${record.lastObserved}`),
  ].join("\n");
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(identity));
    const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    return `mva:threat-intel:${hash}`;
  }
  let hash = 2166136261;
  for (let index = 0; index < identity.length; index += 1) hash = Math.imul(hash ^ identity.charCodeAt(index), 16777619);
  return `mva:threat-intel:${(hash >>> 0).toString(16)}`;
}

function ThreatIntelResult({ result }) {
  return (
    <section className="mt-6 border-t border-white/[0.07] pt-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3"><div><p className="mini-label">Intelligence Result</p><h3 className="mt-1 text-2xl font-extrabold text-white">Defensive vulnerability intelligence</h3></div><span className="rounded-full border border-red-400/20 bg-red-500/[0.07] px-4 py-2 text-xs font-extrabold text-red-200">{result.source}</span></div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <IntelMetric label="Severity" value={result.highestSeverity} tone="text-red-300" />
        <IntelMetric label="Exploit" value={result.exploitAvailable ? "Available / observed" : "Unconfirmed"} tone={result.exploitAvailable ? "text-orange-300" : "text-emerald-300"} />
        <IntelMetric label="Matching evidence" value={result.matchedFindings || "N/A"} tone="text-sky-300" />
        <IntelMetric label="Affected assets" value={result.affectedAssetCount || "N/A"} tone="text-amber-200" />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <IntelSection title="Executive Summary" items={[result.summary]} icon={Sparkles} />
        <IntelSection title="Exploitability and Attack Path" items={[result.exploitEvidence, result.attackPath].filter((item) => item && item !== "Unknown")} icon={ShieldAlert} />
        <IntelSection title="Affected Products and Versions" items={[...result.affectedProducts, ...result.affectedVersions]} icon={Server} />
        <IntelSection title="Patches and Remediation" items={[...result.patches, ...result.remediationSteps]} icon={ShieldAlert} />
        <IntelSection title="Detection and Validation" items={result.detectionSteps} icon={Search} />
        <IntelSection title="References" items={result.references} links icon={ExternalLink} />
      </div>
    </section>
  );
}

function IntelMetric({ label, value, tone }) {
  return <article className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-4"><p className="font-mono text-[0.6rem] font-bold uppercase tracking-[0.12em] text-slate-600">{label}</p><p className={`mt-2 text-xl font-extrabold ${tone}`}>{value}</p></article>;
}

function IntelSection({ title, items = [], links = false, icon: Icon }) {
  const visible = [...new Set(items.filter(Boolean))];
  return <article className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5"><div className="mb-4 flex items-center gap-3"><Icon className="h-5 w-5 text-red-300" /><h4 className="font-extrabold text-white">{title}</h4></div>{visible.length ? <ul className="space-y-3 text-sm font-medium leading-6 text-slate-400">{visible.map((item) => <li key={item} className="border-l-2 border-red-400/25 pl-3">{links ? <a href={item} target="_blank" rel="noreferrer" className="break-all text-sky-300 hover:text-sky-200">{item}</a> : item}</li>)}</ul> : <p className="text-sm font-medium text-slate-600">No verified information returned.</p>}</article>;
}

function ContextRow({ label, value }) {
  return <div className="flex items-center justify-between gap-4 border-b border-white/[0.05] pb-3"><span className="text-slate-600">{label}</span><span className="text-right font-extrabold text-slate-300">{value}</span></div>;
}

function Status({ status }) {
  const classes = status.state === "error" ? "border-red-300/25 bg-red-500/[0.08] text-red-200" : status.state === "success" ? "border-emerald-300/20 bg-emerald-400/[0.06] text-emerald-200" : status.state === "loading" ? "border-amber-300/20 bg-amber-400/[0.06] text-amber-100" : "border-white/[0.07] bg-white/[0.02] text-slate-400";
  return <div aria-live="polite" className={`rounded-xl border px-4 py-3 text-xs font-bold ${classes}`}>{status.message}</div>;
}

function ImportStatus({ status }) {
  const classes = status.state === "error" ? "text-red-200" : status.state === "success" ? "text-emerald-200" : status.state === "loading" ? "text-amber-100" : "text-slate-500";
  const percentage = status.total ? Math.round((status.completed / status.total) * 100) : 0;
  return <div className={`min-w-0 flex-1 text-xs font-bold ${classes}`}><p>{status.message}</p>{status.state === "loading" && status.total > 0 && <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className="h-full bg-red-500" style={{ width: `${percentage}%` }} /></div>}</div>;
}

function threatIntelError(error) {
  const message = error?.message || "Threat-intelligence analysis failed.";
  if (/cannot reach the MVA API/i.test(message)) return message;
  if (/cannot reach Ollama|not installed|not configured/i.test(message)) return `${message} Verify the local model from LLM Configuration.`;
  if (/timed out/i.test(message)) return "The local model request timed out. Verify model capacity or increase OLLAMA_TIMEOUT_MS.";
  return message;
}
