import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Database, HardDriveUpload, RefreshCcw, ServerOff } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { checkDatabaseHealth, databaseApiUrl, fetchScanHistory, persistAnalysis } from "../lib/databaseClient.jsx";

export function PersistencePanel({ analysis }) {
  const platform = usePlatform();
  const [health, setHealth] = useState({ state: "checking", message: "Checking local PostgreSQL..." });
  const [saveState, setSaveState] = useState({ state: "idle", message: "" });
  const [history, setHistory] = useState([]);
  const autoSaveAttempt = useRef({ analysis: null, customerId: "" });
  const canWrite = platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(platform.selectedCustomer?.membershipRole);
  const targetCustomerId = analysis?.customerWorkspaceId || platform.selectedCustomerId;
  const targetCustomerName = analysis?.customerWorkspaceName || platform.selectedCustomer?.name;
  const customerMatches = Boolean(targetCustomerId && targetCustomerId === platform.selectedCustomerId);

  const refresh = async () => {
    setHealth({ state: "checking", message: "Checking local PostgreSQL..." });
    try {
      const result = await checkDatabaseHealth();
      setHealth({ state: "ready", message: `Connected to ${result.database}` });
      setHistory(platform.selectedCustomerId ? await fetchScanHistory({ customerId: platform.selectedCustomerId, limit: 5 }) : []);
    } catch (error) {
      setHealth({ state: "offline", message: error.message || "Local PostgreSQL is offline." });
      setHistory([]);
    }
  };

  useEffect(() => {
    refresh();
  }, [platform.selectedCustomerId]);

  useEffect(() => {
    setSaveState({ state: "idle", message: "" });
  }, [analysis]);

  const save = async ({ automatic = false, customerId = targetCustomerId, customerName = targetCustomerName } = {}) => {
    setSaveState({ state: "saving", message: automatic ? "Automatically saving normalized findings..." : "Preparing normalized findings...", completed: 0, total: 0 });
    try {
      const run = await persistAnalysis(analysis, {
        customerId,
        customerName,
        csrfToken: platform.csrfToken,
        onProgress: ({ completed, total, message }) => setSaveState({ state: "saving", message, completed, total }),
      });
      setSaveState({
        state: "saved",
        message: `${run.weightedFindings.toLocaleString()} weighted findings ${automatic ? "automatically " : ""}saved for ${run.reportPeriod}.`,
        completed: run.receivedFindings,
        total: run.expectedFindings,
      });
      setHealth({ state: "ready", message: "Connected to mva" });
      if (customerId === platform.selectedCustomerId) setHistory(await fetchScanHistory({ customerId, limit: 5 }));
    } catch (error) {
      setSaveState({ state: "error", message: error.message || "The analysis could not be saved." });
    }
  };

  useEffect(() => {
    if (!analysis || !customerMatches || !canWrite || !platform.csrfToken) return;
    if (autoSaveAttempt.current.analysis === analysis && autoSaveAttempt.current.customerId === targetCustomerId) return;
    autoSaveAttempt.current = { analysis, customerId: targetCustomerId };
    void save({ automatic: true, customerId: targetCustomerId, customerName: targetCustomerName });
  }, [analysis, canWrite, customerMatches, platform.csrfToken, targetCustomerId, targetCustomerName]);

  const progress = saveState.total ? Math.round((saveState.completed / saveState.total) * 100) : 0;

  return (
    <section className="rounded-[1.75rem] border border-emerald-300/15 bg-slate-950/85 p-5 shadow-cyber backdrop-blur-xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label text-emerald-300">Local Data Store</p>
          <h2 className="mt-1 text-2xl font-black text-white">Automatic tenant history</h2>
          <p className="mt-2 max-w-3xl text-sm font-semibold leading-6 text-slate-400">
            Every completed analysis is saved automatically to the active tenant. Normalized findings and report metadata are retained; original scanner files remain in this browser.
          </p>
        </div>
        <div className={`flex items-center gap-2 rounded-full border px-3 py-2 text-xs font-black ${health.state === "ready" ? "border-emerald-300/25 bg-emerald-400/10 text-emerald-200" : health.state === "offline" ? "border-red-300/25 bg-red-400/10 text-red-200" : "border-white/10 bg-white/5 text-slate-300"}`}>
          {health.state === "ready" ? <CheckCircle2 className="h-4 w-4" /> : health.state === "offline" ? <ServerOff className="h-4 w-4" /> : <RefreshCcw className="h-4 w-4 animate-spin" />}
          {health.message}
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_auto]">
        <div className="rounded-2xl border border-white/10 bg-black/25 px-4 py-3">
          <span className="mini-label">Destination tenant</span>
          <p className="mt-2 text-sm font-black text-white">{platform.selectedCustomer?.name || "No tenant selected"}</p>
          <p className="mt-1 text-xs font-semibold text-slate-500">The API enforces this tenant boundary for every chunk and report.</p>
        </div>
        <div className="flex flex-wrap items-stretch gap-3">
          <button type="button" onClick={refresh} className="ghost-button flex items-center justify-center gap-2">
            <Database className="h-4 w-4 text-emerald-300" />Test Database
          </button>
          <button type="button" onClick={() => save()} disabled={!analysis || !platform.selectedCustomer || !customerMatches || !canWrite || health.state !== "ready" || saveState.state === "saving"} className="neon-button flex items-center justify-center gap-2 disabled:cursor-not-allowed disabled:opacity-40">
            <HardDriveUpload className="h-4 w-4" />{saveState.state === "saving" ? `Saving ${progress}%` : saveState.state === "saved" ? "Saved automatically" : saveState.state === "error" ? "Retry save" : "Save now"}
          </button>
        </div>
      </div>

      {saveState.message && (
        <div aria-live="polite" className={`mt-4 rounded-2xl border px-4 py-3 text-xs font-bold ${saveState.state === "error" ? "border-red-300/25 bg-red-400/10 text-red-200" : saveState.state === "saved" ? "border-emerald-300/25 bg-emerald-400/10 text-emerald-200" : "border-cyan-300/25 bg-cyan-400/10 text-cyan-200"}`}>
          {saveState.message}
          {saveState.state === "saving" && <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-black/30"><div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${progress}%` }} /></div>}
        </div>
      )}

      <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {history.length ? history.map((run) => (
          <article key={run.id} className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
            <p className="truncate text-sm font-black text-white">{run.customerName}</p>
            <p className="mt-1 truncate text-xs font-bold text-emerald-300">{run.reportPeriod}</p>
            <p className="mt-3 text-xs font-semibold text-slate-500">{run.sourceLabel}</p>
            <p className="mt-1 text-xs font-bold text-slate-300">{run.weightedFindings.toLocaleString()} findings</p>
          </article>
        )) : (
          <div className="md:col-span-2 xl:col-span-5 rounded-2xl border border-dashed border-white/10 px-4 py-5 text-sm font-semibold text-slate-500">
            No saved analyses yet. The first completed tenant analysis will be retained automatically. API: {databaseApiUrl()}
          </div>
        )}
      </div>
    </section>
  );
}
