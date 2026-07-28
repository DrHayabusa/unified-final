import { useDeferredValue, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Check,
  CircleAlert,
  CloudUpload,
  Download,
  FileSearch,
  Gauge,
  HardDrive,
  Radar,
  RefreshCcw,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import {
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { fetchCustomerAssets, fetchCustomerScanAssetCoverage } from "../lib/platformApi.jsx";
import {
  analyzeHostDiscoveryCoverage,
  buildThreeLayerCoverage,
  downloadDiscoveryCsv,
  extractDiscoveryPeriod,
  formatDiscoveryPeriod,
  hostDiscoveryAssetListCsv,
  hostDiscoveryCoverageCsv,
  hostDiscoveryExceptionsCsv,
  hostDiscoveryTemplateCsv,
  isHostDiscoveryFile,
  threeLayerCoverageCsv,
} from "../lib/hostDiscovery.jsx";

const MAX_FILES = 5;

export function HostDiscoveryCoverage({ platform, onBackToDashboard, onManageInventory }) {
  const [inventoryState, setInventoryState] = useState({ loading: false, assets: [], error: "" });
  const [scanCoverageState, setScanCoverageState] = useState({ loading: false, coverage: null, error: "" });
  const [uploads, setUploads] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [selectedPeriod, setSelectedPeriod] = useState("");
  const [status, setStatus] = useState({ state: "idle", message: "Add one to five monthly host-discovery exports." });
  const [dragging, setDragging] = useState(false);
  const [search, setSearch] = useState("");
  const [coverageFilter, setCoverageFilter] = useState("all");
  const [assetTypeFilter, setAssetTypeFilter] = useState("");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());

  useEffect(() => {
    setUploads([]);
    setAnalysis(null);
    setSelectedPeriod("");
    setStatus({ state: "idle", message: "Add one to five monthly host-discovery exports." });
    if (!platform.selectedCustomerId) {
      setInventoryState({ loading: false, assets: [], error: "" });
      setScanCoverageState({ loading: false, coverage: null, error: "" });
      return;
    }
    let active = true;
    setInventoryState({ loading: true, assets: [], error: "" });
    fetchCustomerAssets(platform.selectedCustomerId, { limit: 100_000, timeoutMs: 60_000 })
      .then((payload) => active && setInventoryState({ loading: false, assets: payload.assets ?? [], error: "" }))
      .catch((error) => active && setInventoryState({ loading: false, assets: [], error: error.message }));
    setScanCoverageState({ loading: true, coverage: null, error: "" });
    fetchCustomerScanAssetCoverage(platform.selectedCustomerId, { timeoutMs: 60_000 })
      .then((payload) => active && setScanCoverageState({ loading: false, coverage: payload.coverage ?? null, error: "" }))
      .catch((error) => active && setScanCoverageState({ loading: false, coverage: null, error: error.message }));
    return () => { active = false; };
  }, [platform.selectedCustomerId]);

  const inScopeAssets = useMemo(() => inventoryState.assets.filter((asset) => asset.inScope !== false), [inventoryState.assets]);
  const selectedSummary = analysis?.periods.find((period) => period.period === selectedPeriod) ?? analysis?.latest ?? null;
  const assetTypes = useMemo(() => [...new Set((analysis?.assetCoverage ?? []).map((asset) => asset.assetType || "Other"))].sort(), [analysis]);
  const visibleAssets = useMemo(() => (analysis?.assetCoverage ?? []).filter((asset) => {
    if (coverageFilter === "scanned" && !asset.statuses[selectedSummary?.period]) return false;
    if (coverageFilter === "not-scanned" && asset.statuses[selectedSummary?.period]) return false;
    if (coverageFilter === "never" && asset.monthsScanned !== 0) return false;
    if (assetTypeFilter && (asset.assetType || "Other") !== assetTypeFilter) return false;
    if (!deferredSearch) return true;
    return [asset.displayName, asset.ipAddress, asset.dnsName, asset.hostName, asset.externalId, asset.assetType, asset.teamName]
      .some((value) => String(value ?? "").toLowerCase().includes(deferredSearch));
  }), [analysis, assetTypeFilter, coverageFilter, deferredSearch, selectedSummary?.period]);

  const appendFiles = (fileList) => {
    const incoming = Array.from(fileList ?? []);
    const invalid = incoming.find((file) => !isHostDiscoveryFile(file));
    if (invalid) {
      setStatus({ state: "error", message: `${invalid.name} is not supported. Upload CSV or XLSX.` });
      return;
    }
    if (!incoming.length) return;
    setUploads((current) => {
      const next = [...current];
      for (const file of incoming) {
        const key = fileKey(file);
        const existing = next.findIndex((upload) => fileKey(upload.file) === key);
        const fallback = fallbackPeriod(next.length);
        const entry = { file, period: extractDiscoveryPeriod(file.name) || (existing >= 0 ? next[existing].period : fallback) };
        if (existing >= 0) next[existing] = entry;
        else if (next.length < MAX_FILES) next.push(entry);
      }
      if (current.length + incoming.length > MAX_FILES && next.length === MAX_FILES) setStatus({ state: "error", message: "A maximum of five monthly discovery files can be compared at once." });
      else setStatus({ state: "idle", message: `${next.length} discovery file${next.length === 1 ? "" : "s"} ready. Confirm each reporting month.` });
      return next;
    });
    setAnalysis(null);
  };

  const setUploadPeriod = (index, period) => {
    setUploads((current) => current.map((upload, uploadIndex) => uploadIndex === index ? { ...upload, period } : upload));
    setAnalysis(null);
  };

  const removeUpload = (index) => {
    setUploads((current) => current.filter((_, uploadIndex) => uploadIndex !== index));
    setAnalysis(null);
    setStatus({ state: "idle", message: "File removed. Analyze again after confirming the remaining months." });
  };

  const runAnalysis = async () => {
    setStatus({ state: "loading", message: `Reconciling ${uploads.length} discovery file${uploads.length === 1 ? "" : "s"} against ${inScopeAssets.length.toLocaleString()} in-scope assets...` });
    try {
      const result = await analyzeHostDiscoveryCoverage({ inventory: inventoryState.assets, uploads });
      setAnalysis(result);
      setSelectedPeriod(result.latestPeriod);
      setStatus({ state: "success", message: `${result.periods.length}-month coverage analysis completed with exact IP and DNS inventory matching.` });
    } catch (error) {
      setAnalysis(null);
      setStatus({ state: "error", message: error.message || "Host discovery analysis failed." });
    }
  };

  const clear = () => {
    setUploads([]);
    setAnalysis(null);
    setSelectedPeriod("");
    setStatus({ state: "idle", message: "Add one to five monthly host-discovery exports." });
  };

  const tenantSlug = String(platform.selectedCustomer?.slug || platform.selectedCustomer?.name || "tenant").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  return (
    <div className="space-y-4">
      <section className="enterprise-panel relative overflow-hidden p-5 sm:p-6">
        <div className="pointer-events-none absolute -right-28 -top-36 h-80 w-80 rounded-full border border-red-400/10 shadow-[0_0_0_48px_rgba(239,68,68,.018),0_0_0_96px_rgba(239,68,68,.012)]" />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4"><span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-red-400/20 bg-red-500/[0.08]"><Radar className="h-6 w-6 text-red-300" /></span><div><p className="mini-label">{platform.selectedCustomer?.name || "Tenant"}</p><h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">Host discovery coverage</h2><p className="mt-2 max-w-3xl text-sm font-medium leading-6 text-slate-400">Compare one to five monthly host-discovery exports with the saved asset inventory to prove what was scanned, identify coverage gaps, and track recovery over time.</p></div></div>
          <div className="flex flex-wrap gap-2"><button type="button" onClick={onBackToDashboard} className="secondary-button flex items-center gap-2"><ArrowLeft className="h-4 w-4" />Back to Dashboards</button><button type="button" onClick={onManageInventory} className="secondary-button flex items-center gap-2"><HardDrive className="h-4 w-4" />Manage inventory</button></div>
        </div>
      </section>

      {inventoryState.error && <Notice error>{inventoryState.error}</Notice>}
      {inventoryState.loading && <section className="enterprise-panel grid min-h-48 place-items-center p-8 text-center"><div><RefreshCcw className="mx-auto h-6 w-6 animate-spin text-red-300" /><p className="mt-3 text-sm font-extrabold text-white">Loading tenant inventory</p><p className="mt-1 text-xs font-medium text-slate-600">Reading approved and scanner-discovered assets from PostgreSQL.</p></div></section>}

      {!inventoryState.loading && !inventoryState.error && (
        <>
          <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
            <div className="enterprise-panel p-5 sm:p-6">
              <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="mini-label">Discovery evidence</p><h3 className="mt-1 text-xl font-extrabold text-white">Add monthly host results</h3><p className="mt-2 text-xs font-medium leading-5 text-slate-500">Use a CSV/XLSX with exactly two columns: IP Address and DNS Name. Either value may be blank only when the other uniquely identifies the asset. Add files across separate drops; existing files remain until removed.</p></div><span className="status-chip">{uploads.length} / {MAX_FILES} files</span></div>

              <label onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setDragging(false); }} onDrop={(event) => { event.preventDefault(); setDragging(false); appendFiles(event.dataTransfer.files); }} className={`mt-5 grid min-h-36 cursor-pointer place-items-center rounded-2xl border border-dashed p-6 text-center transition ${dragging ? "border-red-400/50 bg-red-500/[0.08]" : "border-white/[0.12] bg-black/20 hover:border-red-400/30 hover:bg-red-500/[0.035]"}`}>
                <input type="file" multiple accept=".csv,.xlsx" className="sr-only" onChange={(event) => { appendFiles(event.target.files); event.target.value = ""; }} />
                <div><CloudUpload className="mx-auto h-7 w-7 text-red-300" /><p className="mt-3 text-sm font-extrabold text-white">Drop files here or browse</p><p className="mt-1 text-xs font-medium text-slate-600">One consolidated discovery export per reporting month</p></div>
              </label>

              {uploads.length > 0 && <div className="mt-4 space-y-2">{uploads.map((upload, index) => <div key={fileKey(upload.file)} className="grid gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 sm:grid-cols-[minmax(0,1fr)_170px_auto] sm:items-center"><div className="min-w-0"><p className="truncate text-xs font-extrabold text-white">{upload.file.name}</p><p className="mt-1 font-mono text-[0.58rem] font-bold uppercase tracking-wider text-slate-600">{formatBytes(upload.file.size)}</p></div><label><span className="sr-only">Reporting month for {upload.file.name}</span><input type="month" value={upload.period} onChange={(event) => setUploadPeriod(index, event.target.value)} className="admin-input py-2 text-xs" /></label><button type="button" onClick={() => removeUpload(index)} aria-label={`Remove ${upload.file.name}`} className="grid h-9 w-9 place-items-center rounded-lg border border-white/[0.07] text-slate-600 transition hover:border-red-400/25 hover:bg-red-500/[0.07] hover:text-red-300"><X className="h-4 w-4" /></button></div>)}</div>}

              <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={runAnalysis} disabled={!uploads.length || !inScopeAssets.length || status.state === "loading"} className="primary-button flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-40"><FileSearch className="h-4 w-4" />{status.state === "loading" ? "Analyzing coverage..." : "Analyze discovery coverage"}</button><button type="button" onClick={() => downloadDiscoveryCsv(hostDiscoveryTemplateCsv(), "mva-host-discovery-template.csv")} className="secondary-button flex items-center gap-2"><Download className="h-4 w-4" />Download template</button>{uploads.length > 0 && <button type="button" onClick={clear} className="secondary-button flex items-center gap-2"><Trash2 className="h-4 w-4" />Clear</button>}</div>
              <StatusNotice status={status} />
            </div>

            <aside className="enterprise-panel p-5">
              <p className="mini-label">Comparison baseline</p><h3 className="mt-1 text-lg font-extrabold text-white">Saved asset inventory</h3>
              <div className="mt-5 space-y-2"><InventoryMetric label="In-scope assets" value={inScopeAssets.length} icon={Server} /><InventoryMetric label="Assets with IP" value={inScopeAssets.filter((asset) => asset.ipAddress).length} icon={HardDrive} /><InventoryMetric label="Assets with DNS" value={inScopeAssets.filter((asset) => asset.dnsName).length} icon={Radar} /><InventoryMetric label="Latest scan assets" value={scanCoverageState.coverage?.matchedInventoryAssets ?? 0} icon={FileSearch} /></div>
              <p className="mt-4 rounded-xl border border-white/[0.07] bg-black/20 p-3 text-[0.68rem] font-medium leading-5 text-slate-600">Inventory is the customer-approved scope. Host discovery proves visibility, while the latest saved vulnerability result proves scanner coverage. Only unique IP or DNS matches count.</p>
              {scanCoverageState.error && <p className="mt-3 text-[0.68rem] font-bold leading-5 text-red-300">{scanCoverageState.error}</p>}
              {!inScopeAssets.length && <button type="button" onClick={onManageInventory} className="primary-button mt-4 w-full">Add inventory assets</button>}
            </aside>
          </section>

          {analysis && selectedSummary && <DiscoveryResults analysis={analysis} inventory={inScopeAssets} scanCoverageState={scanCoverageState} selectedSummary={selectedSummary} selectedPeriod={selectedPeriod} onPeriodChange={setSelectedPeriod} visibleAssets={visibleAssets} search={search} onSearchChange={setSearch} coverageFilter={coverageFilter} onCoverageFilterChange={setCoverageFilter} assetTypeFilter={assetTypeFilter} onAssetTypeFilterChange={setAssetTypeFilter} assetTypes={assetTypes} tenantSlug={tenantSlug} onDownloadCoverage={() => downloadDiscoveryCsv(hostDiscoveryCoverageCsv(analysis), `mva-${tenantSlug}-host-discovery-coverage-${analysis.latestPeriod}.csv`)} onDownloadExceptions={() => downloadDiscoveryCsv(hostDiscoveryExceptionsCsv(analysis), `mva-${tenantSlug}-host-discovery-exceptions-${analysis.latestPeriod}.csv`)} />}
        </>
      )}
    </div>
  );
}

function DiscoveryResults({ analysis, inventory, scanCoverageState, selectedSummary, selectedPeriod, onPeriodChange, visibleAssets, search, onSearchChange, coverageFilter, onCoverageFilterChange, assetTypeFilter, onAssetTypeFilterChange, assetTypes, tenantSlug, onDownloadCoverage, onDownloadExceptions }) {
  const threeLayer = buildThreeLayerCoverage({ inventory, discoveryPeriod: selectedSummary, scanCoverage: scanCoverageState.coverage });
  const vulnerabilityScanAssetIds = new Set(scanCoverageState.coverage?.assetIds ?? []);
  const trend = analysis.periods.map((period) => ({
    month: period.periodLabel.replace(/\s(20\d{2})$/, " '$1").replace("'20", "'"),
    coverage: period.coveragePercentage,
    scanned: period.scannedAssets,
    notScanned: period.notScannedAssets,
  }));
  const downloadAssetCategory = (category) => downloadDiscoveryCsv(
    hostDiscoveryAssetListCsv(analysis, { period: selectedSummary.period, category }),
    `mva-${tenantSlug}-${category}-${selectedSummary.period}.csv`,
  );
  const downloadThreeLayerCategory = (category) => downloadDiscoveryCsv(
    threeLayerCoverageCsv({ inventory, data: threeLayer, category }),
    `mva-${tenantSlug}-${category}-${selectedSummary.period}.csv`,
  );
  return <>
    <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-6">
      <CoverageMetric label="Inventory assets" value={selectedSummary.inventoryAssets} detail="Customer in-scope list" icon={Server} tone="slate" />
      <CoverageMetric label="Rows received" value={selectedSummary.sourceRows} detail="IP and DNS input rows" icon={FileSearch} tone="amber" />
      <CoverageMetric label="Unique hosts" value={selectedSummary.discoveredHosts} detail="Duplicates removed" icon={Radar} tone="cyan" />
      <CoverageMetric label="Host discovered" value={selectedSummary.scannedAssets} detail={selectedSummary.periodLabel} icon={Check} tone="green" />
      <CoverageMetric label="Not discovered" value={selectedSummary.notScannedAssets} detail="Possible reachability gap" icon={ShieldAlert} tone="red" />
      <CoverageMetric label="Discovery coverage" value={`${selectedSummary.coveragePercentage}%`} detail="Unique inventory matches" icon={Gauge} tone="cyan" />
    </section>

    <ThreeLayerCoverage data={threeLayer} scanCoverageState={scanCoverageState} selectedSummary={selectedSummary} onDownload={downloadThreeLayerCategory} />

    <section className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(320px,.75fr)]">
      <article className="enterprise-panel p-5"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="mini-label">Coverage movement</p><h3 className="mt-1 text-lg font-extrabold text-white">Host discovered vs not discovered</h3><p className="mt-1 text-xs font-medium text-slate-600">One to five submitted reporting months</p></div><select aria-label="Selected discovery month" value={selectedPeriod} onChange={(event) => onPeriodChange(event.target.value)} className="table-select">{analysis.periods.map((period) => <option key={period.period} value={period.period}>{period.periodLabel}</option>)}</select></div><div className="mt-4 h-64"><ResponsiveContainer width="100%" height="100%"><ComposedChart data={trend} margin={{ top: 12, right: 12, bottom: 0, left: -18 }}><CartesianGrid stroke="rgba(255,255,255,.055)" vertical={false} /><XAxis dataKey="month" tick={{ fill: "#71717a", fontSize: 11, fontWeight: 700 }} axisLine={false} tickLine={false} /><YAxis yAxisId="assets" allowDecimals={false} tick={{ fill: "#71717a", fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis yAxisId="coverage" orientation="right" domain={[0, 100]} tickFormatter={(value) => `${value}%`} tick={{ fill: "#71717a", fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip content={<DiscoveryTooltip />} /><Legend wrapperStyle={{ fontSize: 11, color: "#a1a1aa", fontWeight: 700 }} /><Line yAxisId="assets" type="monotone" dataKey="scanned" name="Host discovered" stroke="#22c55e" strokeWidth={2.5} dot={{ fill: "#09090a", stroke: "#4ade80", strokeWidth: 2, r: 3 }} /><Line yAxisId="assets" type="monotone" dataKey="notScanned" name="Not discovered" stroke="#ef4444" strokeWidth={2.5} dot={{ fill: "#09090a", stroke: "#f87171", strokeWidth: 2, r: 3 }} /><Line yAxisId="coverage" type="monotone" dataKey="coverage" name="Coverage %" stroke="#38bdf8" strokeDasharray="5 4" strokeWidth={2} dot={false} /></ComposedChart></ResponsiveContainer></div></article>
      <article className="enterprise-panel p-5"><p className="mini-label">Selected month</p><h3 className="mt-1 text-lg font-extrabold text-white">{selectedSummary.periodLabel}</h3><div className="mt-5 space-y-3"><MovementRow label="Newly discovered assets" value={selectedSummary.newCoverage} tone="text-emerald-300" /><MovementRow label="No longer discovered" value={selectedSummary.lostCoverage} tone="text-red-300" /><MovementRow label="Matched by IP + DNS" value={selectedSummary.matchedByIpAndDns} tone="text-emerald-300" /><MovementRow label="Matched by IP only" value={selectedSummary.matchedByIpOnly} tone="text-sky-300" /><MovementRow label="Matched by DNS only" value={selectedSummary.matchedByDnsOnly} tone="text-sky-300" /><MovementRow label="Not in inventory" value={selectedSummary.unmatchedHosts.length} tone="text-orange-300" /><MovementRow label="Ambiguous IP / DNS" value={selectedSummary.ambiguousHosts.length} tone="text-amber-200" /><MovementRow label="Duplicate rows ignored" value={selectedSummary.duplicateRowsRemoved} tone="text-slate-300" /></div></article>
    </section>

    <section className="grid gap-4 xl:grid-cols-2"><CoverageBreakdown title="Coverage by asset type" rows={selectedSummary.byAssetType} /><CoverageBreakdown title="Coverage by responsible team" rows={selectedSummary.byTeam} /></section>

    <section className="enterprise-panel overflow-hidden">
      <div className="border-b border-white/[0.07] p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="mini-label">Asset-level evidence</p><h3 className="mt-1 text-lg font-extrabold text-white">Coverage history</h3><p className="mt-1 text-xs font-medium text-slate-600">{visibleAssets.length.toLocaleString()} matching assets · {analysis.neverScanned.toLocaleString()} never discovered · {analysis.consistentlyScanned.toLocaleString()} discovered every submitted month</p></div><div className="flex flex-wrap gap-2"><button type="button" onClick={onDownloadCoverage} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Full history</button><button type="button" onClick={() => downloadAssetCategory("discovered")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Discovered</button><button type="button" onClick={() => downloadAssetCategory("not-discovered")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Not discovered</button><button type="button" onClick={() => downloadAssetCategory("never-discovered")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Never discovered</button><button type="button" onClick={onDownloadExceptions} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Exceptions</button></div></div><div className="mt-4 grid gap-2 lg:grid-cols-[minmax(220px,1fr)_170px_190px]"><label className="relative"><span className="sr-only">Search assets</span><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={search} onChange={(event) => onSearchChange(event.target.value)} placeholder="Search asset, IP, DNS, type, or owner" className="admin-input py-2.5 pl-10 text-xs" /></label><select aria-label="Coverage status filter" value={coverageFilter} onChange={(event) => onCoverageFilterChange(event.target.value)} className="admin-input py-2.5 text-xs"><option value="all">All coverage states</option><option value="scanned">Discovered this month</option><option value="not-scanned">Not discovered this month</option><option value="never">Never discovered</option></select><select aria-label="Asset type filter" value={assetTypeFilter} onChange={(event) => onAssetTypeFilterChange(event.target.value)} className="admin-input py-2.5 text-xs"><option value="">All asset types</option>{assetTypes.map((assetType) => <option key={assetType}>{assetType}</option>)}</select></div></div>
      <div className="max-h-[560px] overflow-auto"><table className="enterprise-table min-w-[1180px]"><thead className="sticky top-0 z-10 bg-[#111113]"><tr><th>Asset identity</th><th>IP address</th><th>Type</th><th>Owner</th>{analysis.periods.map((period) => <th key={period.period}>{period.periodLabel}</th>)}<th>Latest vulnerability scan</th><th>Coverage</th><th>Last discovered</th></tr></thead><tbody>{visibleAssets.map((asset) => <tr key={asset.id}><td><p className="font-extrabold text-white">{asset.displayName}</p>{asset.externalId && <p className="mt-1 font-mono text-[0.58rem] text-slate-600">{asset.externalId}</p>}</td><td className="font-mono text-[0.68rem] text-slate-400">{asset.ipAddress || "—"}</td><td>{asset.assetType || "Other"}</td><td>{asset.teamName || "Unassigned"}</td>{analysis.periods.map((period) => <td key={period.period}>{asset.statuses[period.period] ? <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-300/15 bg-emerald-400/[0.06] px-2 py-1 text-[0.62rem] font-extrabold text-emerald-300"><Check className="h-3 w-3" />Discovered</span> : <span className="inline-flex items-center gap-1.5 rounded-lg border border-red-300/15 bg-red-500/[0.06] px-2 py-1 text-[0.62rem] font-extrabold text-red-300"><X className="h-3 w-3" />Not discovered</span>}</td>)}<td>{!scanCoverageState.coverage?.available ? <span className="text-slate-600">No saved scan</span> : vulnerabilityScanAssetIds.has(asset.id) ? <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-300/15 bg-emerald-400/[0.06] px-2 py-1 text-[0.62rem] font-extrabold text-emerald-300"><Check className="h-3 w-3" />Included</span> : <span className="inline-flex items-center gap-1.5 rounded-lg border border-amber-300/15 bg-amber-400/[0.06] px-2 py-1 text-[0.62rem] font-extrabold text-amber-200"><CircleAlert className="h-3 w-3" />Missing</span>}</td><td className="font-extrabold text-white">{asset.coveragePercentage}%</td><td>{asset.lastScannedPeriod ? formatDiscoveryPeriod(asset.lastScannedPeriod) : <span className="font-bold text-red-300">Never</span>}</td></tr>)}</tbody></table>{!visibleAssets.length && <div className="grid min-h-36 place-items-center p-8 text-sm font-medium text-slate-600">No assets match the selected filters.</div>}</div>
    </section>

    <section className="rounded-2xl border border-white/[0.07] bg-black/20 p-4"><p className="text-xs font-extrabold text-slate-300">Accuracy rule</p><p className="mt-1 text-[0.68rem] font-medium leading-5 text-slate-600">Host discovery uses only IP Address and DNS Name. Counts require one unique match to the customer inventory; ambiguous, unmanaged, and duplicate rows never inflate coverage. Vulnerability scan coverage is calculated from the latest finalized scan period and the same inventory identities.</p></section>
  </>;
}

function ThreeLayerCoverage({ data, scanCoverageState, selectedSummary, onDownload }) {
  const scanCoverage = scanCoverageState.coverage;
  return <section className="enterprise-panel overflow-hidden p-5 sm:p-6">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div><p className="mini-label">Three-layer asset visibility</p><h3 className="mt-1 text-xl font-extrabold text-white">In-scope inventory vs host discovery vs vulnerability result</h3><p className="mt-2 max-w-3xl text-xs font-medium leading-5 text-slate-500">Separates the customer-approved asset baseline from hosts visible in discovery and assets represented in the latest finalized vulnerability scan result.</p></div>
      <span className="status-chip">Host discovery: {selectedSummary.periodLabel}</span>
    </div>

    <div className="mt-5 grid gap-3 lg:grid-cols-3">
      <CoverageLayer index="01" label="In-scope inventory" value={data.inventoryAssets} percentage={100} detail="Customer asset inventory baseline" tone="slate" />
      <CoverageLayer index="02" label="Host discovered" value={data.hostDiscoveredAssets} percentage={data.discoveryCoveragePercentage} detail="Unique IP / DNS matches in discovery" tone="green" />
      <CoverageLayer index="03" label="In vulnerability result" value={data.vulnerabilityScanAssets} percentage={data.vulnerabilityScanCoveragePercentage} detail={scanCoverage?.available ? `${scanCoverage.sourceLabel || "Saved scan"} · ${formatScanPeriod(scanCoverage.reportPeriod)}` : "No finalized vulnerability result saved"} tone="red" loading={scanCoverageState.loading} />
    </div>

    {scanCoverage?.available ? <>
      <div className="mt-4 grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        <GapMetric label="Not discovered" value={data.inventoryNotDiscovered} detail="Possible reachability or discovery gap" tone="text-red-300" />
        <GapMetric label="Absent from vuln result" value={data.discoveredNotInVulnerabilityScan} detail="Reachable, clean, excluded, or scan gap" tone="text-amber-200" />
        <GapMetric label="Vuln-result only" value={data.vulnerabilityScanNotInDiscovery} detail="Check period or discovery coverage" tone="text-sky-300" />
        <GapMetric label="Confirmed in both" value={data.confirmedByBoth} detail={`${data.discoveredAssetScanPercentage}% of discovered assets`} tone="text-emerald-300" />
      </div>
      <div className="mt-4 flex flex-wrap gap-2 text-[0.66rem] font-bold text-slate-500"><span className="rounded-lg border border-white/[0.07] bg-black/20 px-3 py-2">{data.scanResultIdentities.toLocaleString()} unique identities in scan result</span><span className="rounded-lg border border-white/[0.07] bg-black/20 px-3 py-2">{data.unmatchedScanIdentities.toLocaleString()} not mapped to inventory</span><span className="rounded-lg border border-white/[0.07] bg-black/20 px-3 py-2">{data.ambiguousScanIdentities.toLocaleString()} ambiguous</span></div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" onClick={() => onDownload("confirmedByBoth")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Confirmed in both</button>
        <button type="button" onClick={() => onDownload("inventoryNotDiscovered")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Not discovered</button>
        <button type="button" onClick={() => onDownload("discoveredNotInVulnerabilityScan")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Missing from vuln result</button>
        <button type="button" onClick={() => onDownload("vulnerabilityScanNotInDiscovery")} className="secondary-button flex items-center gap-2 text-xs"><Download className="h-4 w-4" />Vuln-result only</button>
      </div>
      {data.periodsAligned === false && <div className="mt-4 rounded-xl border border-amber-300/15 bg-amber-400/[0.05] px-4 py-3 text-xs font-bold text-amber-100">Period warning: the selected host-discovery month does not match the latest vulnerability-result month. Interpret the gap as a timing difference until matching-period data is uploaded.</div>}
    </> : !scanCoverageState.loading && <div className="mt-4 rounded-xl border border-amber-300/15 bg-amber-400/[0.05] px-4 py-3 text-xs font-bold leading-5 text-amber-100">No saved vulnerability scan is available for this tenant. Save an analyzed scanner report to PostgreSQL to activate the third comparison layer.</div>}
  </section>;
}

function CoverageLayer({ index, label, value, percentage, detail, tone, loading = false }) {
  const tones = { slate: "border-white/[0.08] bg-white/[0.025] text-slate-300", green: "border-emerald-300/15 bg-emerald-400/[0.045] text-emerald-300", red: "border-red-300/15 bg-red-500/[0.045] text-red-300" };
  const bars = { slate: "bg-slate-400", green: "bg-emerald-400", red: "bg-red-500" };
  return <article className={`rounded-2xl border p-4 ${tones[tone]}`}><div className="flex items-center justify-between gap-3"><span className="font-mono text-[0.58rem] font-black tracking-wider text-slate-600">LAYER {index}</span><span className="text-xs font-extrabold">{loading ? "Loading" : `${Number(percentage).toLocaleString()}%`}</span></div><p className="mt-3 text-xs font-extrabold uppercase tracking-[0.08em] text-slate-500">{label}</p><p className="mt-2 text-3xl font-extrabold text-white">{loading ? "—" : Number(value).toLocaleString()}</p><div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={`h-full rounded-full ${bars[tone]}`} style={{ width: `${Math.min(100, Math.max(0, Number(percentage) || 0))}%` }} /></div><p className="mt-3 text-[0.65rem] font-medium leading-5 text-slate-600">{detail}</p></article>;
}

function GapMetric({ label, value, detail, tone }) {
  return <article className="rounded-xl border border-white/[0.07] bg-black/20 p-4"><div className="flex items-start justify-between gap-3"><p className="text-xs font-bold text-slate-400">{label}</p><span className={`text-xl font-extrabold ${tone}`}>{Number(value).toLocaleString()}</span></div><p className="mt-2 text-[0.62rem] font-medium leading-5 text-slate-600">{detail}</p></article>;
}

function CoverageMetric({ label, value, detail, icon: Icon, tone }) {
  const colors = { slate: "text-slate-300 bg-white/[0.03] border-white/[0.07]", green: "text-emerald-300 bg-emerald-400/[0.05] border-emerald-300/15", red: "text-red-300 bg-red-500/[0.05] border-red-300/15", cyan: "text-sky-300 bg-sky-400/[0.05] border-sky-300/15", amber: "text-amber-200 bg-amber-400/[0.05] border-amber-300/15", orange: "text-orange-300 bg-orange-400/[0.05] border-orange-300/15" };
  return <article className={`rounded-2xl border p-4 ${colors[tone]}`}><div className="flex items-center justify-between gap-2"><p className="font-mono text-[0.56rem] font-bold uppercase tracking-[0.11em] text-slate-600">{label}</p><Icon className="h-4 w-4" /></div><p className="mt-3 text-2xl font-extrabold text-white">{typeof value === "number" ? value.toLocaleString() : value}</p><p className="mt-1 text-[0.62rem] font-medium text-slate-600">{detail}</p></article>;
}

function CoverageBreakdown({ title, rows }) {
  return <article className="enterprise-panel p-5"><p className="mini-label">Scope quality</p><h3 className="mt-1 text-lg font-extrabold text-white">{title}</h3><div className="mt-4 space-y-3">{rows.slice(0, 10).map((row) => <div key={row.label}><div className="flex items-center justify-between gap-3 text-xs"><span className="truncate font-bold text-slate-400">{row.label}</span><span className="shrink-0 font-extrabold text-white">{row.scannedAssets}/{row.inventoryAssets} · {row.coveragePercentage}%</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.05]"><div className={`h-full rounded-full ${row.coveragePercentage >= 90 ? "bg-emerald-400" : row.coveragePercentage >= 70 ? "bg-amber-400" : "bg-red-500"}`} style={{ width: `${row.coveragePercentage}%` }} /></div></div>)}</div></article>;
}

function InventoryMetric({ label, value, icon: Icon }) {
  return <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] px-3 py-3"><span className="flex items-center gap-2 text-xs font-bold text-slate-500"><Icon className="h-4 w-4 text-slate-600" />{label}</span><span className="text-sm font-extrabold text-white">{Number(value).toLocaleString()}</span></div>;
}

function MovementRow({ label, value, tone }) {
  return <div className="flex items-center justify-between gap-3 border-b border-white/[0.05] pb-3"><span className="text-xs font-medium text-slate-500">{label}</span><span className={`text-sm font-extrabold ${tone}`}>{Number(value).toLocaleString()}</span></div>;
}

function DiscoveryTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="rounded-xl border border-white/[0.1] bg-black/95 px-3 py-2 shadow-2xl"><p className="text-xs font-extrabold text-white">{label}</p>{payload.map((item) => <p key={item.dataKey} className="mt-1 text-xs font-bold" style={{ color: item.color }}>{item.name}: {item.dataKey === "coverage" ? `${item.value}%` : Number(item.value).toLocaleString()}</p>)}</div>;
}

function StatusNotice({ status }) {
  const classes = status.state === "error" ? "border-red-300/20 bg-red-500/[0.07] text-red-200" : status.state === "success" ? "border-emerald-300/15 bg-emerald-400/[0.05] text-emerald-200" : status.state === "loading" ? "border-amber-300/15 bg-amber-400/[0.05] text-amber-100" : "border-white/[0.07] bg-white/[0.02] text-slate-500";
  return <div aria-live="polite" className={`mt-4 rounded-xl border px-4 py-3 text-xs font-bold ${classes}`}>{status.message}</div>;
}

function Notice({ children, error = false }) {
  return <div role={error ? "alert" : "status"} className={`rounded-xl border px-4 py-3 text-sm font-bold ${error ? "border-red-300/25 bg-red-500/[0.08] text-red-100" : "border-emerald-300/20 bg-emerald-400/[0.06] text-emerald-100"}`}>{children}</div>;
}

function fallbackPeriod(existingCount) {
  const now = new Date();
  const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - existingCount, 1));
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function fileKey(file) {
  return `${String(file?.name ?? "").toLowerCase()}::${Number(file?.size ?? 0)}::${Number(file?.lastModified ?? 0)}`;
}

function formatBytes(bytes = 0) {
  if (!bytes) return "0 KB";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024)).toLocaleString()} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatScanPeriod(value) {
  const text = String(value ?? "").trim();
  const iso = text.match(/^(20\d{2})-(0[1-9]|1[0-2])/);
  return iso ? formatDiscoveryPeriod(`${iso[1]}-${iso[2]}`) : text || "Unknown period";
}
