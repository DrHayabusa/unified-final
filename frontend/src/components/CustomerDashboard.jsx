import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Boxes,
  CheckCircle2,
  CircleAlert,
  Crosshair,
  Database,
  Download,
  RefreshCcw,
  ScanSearch,
  Server,
  ShieldAlert,
  UsersRound,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { usePlatform } from "../context/PlatformContext.jsx";
import {
  downloadCustomerFindingsCsv,
  fetchCustomerAssets,
  fetchCustomerDashboard,
  fetchCustomerTeams,
} from "../lib/platformApi.jsx";

const priorityColors = { P1: "#ef4444", P2: "#f97316", P3: "#facc15", P4: "#22c55e" };
const severityColors = { Critical: "#ef4444", High: "#f97316", Medium: "#facc15", Low: "#22c55e", Info: "#38bdf8" };
const ageBuckets = ["0-7 days", "8-30 days", "31-60 days", "61-180 days", "Over 180 days"];

export function CustomerDashboard({ onNavigate }) {
  const platform = usePlatform();
  const [state, setState] = useState({ loading: false, dashboard: null, error: "" });
  const [teams, setTeams] = useState([]);
  const [assets, setAssets] = useState([]);
  const [teamId, setTeamId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [exportState, setExportState] = useState({ busy: false, error: "" });
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    setTeamId("");
    setAssetId("");
    setExportState({ busy: false, error: "" });
    if (!platform.selectedCustomerId) {
      setTeams([]);
      setAssets([]);
      return;
    }
    let active = true;
    Promise.all([
      fetchCustomerTeams(platform.selectedCustomerId),
      fetchCustomerAssets(platform.selectedCustomerId, { limit: 100_000, timeoutMs: 60_000 }),
    ])
      .then(([teamPayload, assetPayload]) => {
        if (!active) return;
        setTeams(teamPayload.teams ?? []);
        setAssets(assetPayload.assets ?? []);
      })
      .catch(() => {
        if (!active) return;
        setTeams([]);
        setAssets([]);
      });
    return () => { active = false; };
  }, [platform.selectedCustomerId]);

  const selectableAssets = useMemo(
    () => assets
      .filter((asset) => asset.inScope !== false && (!teamId || asset.teamId === teamId))
      .sort((left, right) => assetDisplayName(left).localeCompare(assetDisplayName(right))),
    [assets, teamId],
  );

  useEffect(() => {
    if (assetId && !selectableAssets.some((asset) => asset.id === assetId)) setAssetId("");
  }, [assetId, selectableAssets]);

  useEffect(() => {
    if (!platform.selectedCustomerId) {
      setState({ loading: false, dashboard: null, error: "" });
      return;
    }
    let active = true;
    setState((current) => ({ ...current, loading: true, error: "" }));
    fetchCustomerDashboard(platform.selectedCustomerId, { teamId, assetId })
      .then((payload) => active && setState({ loading: false, dashboard: payload.dashboard, error: "" }))
      .catch((error) => active && setState({ loading: false, dashboard: null, error: error.message }));
    return () => { active = false; };
  }, [platform.selectedCustomerId, teamId, assetId, refreshKey]);

  if (!platform.customers.length) return <NoCustomers onNavigate={onNavigate} />;

  const dashboard = state.dashboard;
  const metrics = dashboard?.metrics ?? {};
  const comparisonLabel = dashboard?.comparisonAvailable ? `vs ${dashboard.previousPeriod}` : "Awaiting a comparable period";
  const selectedTeam = teams.find((team) => team.id === teamId);
  const selectedAsset = assets.find((asset) => asset.id === assetId);
  const scopeLabel = selectedAsset ? assetDisplayName(selectedAsset) : selectedTeam?.name || "All assets";

  const downloadFindings = async () => {
    setExportState({ busy: true, error: "" });
    try {
      const { blob, filename } = await downloadCustomerFindingsCsv(platform.selectedCustomerId, { teamId, assetId });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setExportState({ busy: false, error: "" });
    } catch (error) {
      setExportState({ busy: false, error: error.message });
    }
  };

  return (
    <div className="space-y-4">
      <section className="enterprise-panel relative overflow-hidden px-5 py-5 sm:px-6">
        <div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-red-500 via-red-700 to-transparent" />
        <div className="relative flex flex-wrap items-start justify-between gap-5">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <p className="mini-label">Dashboards / {platform.selectedCustomer?.name}</p>
              <span className="rounded-lg border border-emerald-300/15 bg-emerald-400/[0.05] px-2 py-1 font-mono text-[0.55rem] font-bold uppercase tracking-wider text-emerald-300">Tenant active</span>
            </div>
            <h2
              aria-label={`${platform.selectedCustomer?.name || "Tenant"} Dashboard`}
              className="mt-2 text-2xl font-extrabold tracking-[-0.035em] text-white sm:text-[1.75rem]"
            >
              {platform.selectedCustomer?.name || "Tenant"}<span className="ml-2">Dashboard</span>
            </h2>
            <p className="mt-1.5 text-sm font-medium text-slate-500">
              {dashboard?.latestRun ? `${dashboard.currentPeriod} security posture · ${scopeLabel}` : "Asset inventory is ready. Analyze scanner data to activate the saved vulnerability dashboard."}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" disabled={!dashboard?.latestRun || exportState.busy} onClick={downloadFindings} className="secondary-button flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-40">
              <Download className="h-4 w-4" />{exportState.busy ? "Preparing CSV..." : "Download findings CSV"}
            </button>
            <button type="button" onClick={() => onNavigate?.("scanner")} className="primary-button flex items-center gap-2">
              <Activity className="h-4 w-4" /> Create analysis
            </button>
            <button type="button" onClick={() => onNavigate?.("discovery")} className="secondary-button flex items-center gap-2">
              <ScanSearch className="h-4 w-4" /> Discovery coverage
            </button>
          </div>
        </div>
      </section>

      <section className="enterprise-panel grid gap-2 p-2.5 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1fr_auto]">
          <DashboardSelect label="Tenant" value={platform.selectedCustomerId} onChange={(event) => platform.setSelectedCustomerId(event.target.value)}>
            {platform.customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}
          </DashboardSelect>
          <DashboardSelect label="Responsible owner" value={teamId} onChange={(event) => setTeamId(event.target.value)}>
            <option value="">All responsible owners</option>
            {teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
          </DashboardSelect>
          <DashboardSelect label="Asset" value={assetId} onChange={(event) => setAssetId(event.target.value)}>
            <option value="">All assets in selected scope</option>
            {selectableAssets.map((asset) => <option key={asset.id} value={asset.id}>{assetOptionLabel(asset)}</option>)}
          </DashboardSelect>
          <button type="button" onClick={() => setRefreshKey((value) => value + 1)} className="secondary-button flex items-center gap-2 self-end px-3">
            <RefreshCcw className={`h-4 w-4 ${state.loading ? "animate-spin" : ""}`} /> Refresh
          </button>
      </section>

      {state.error && <div role="alert" className="rounded-2xl border border-red-400/25 bg-red-500/10 px-5 py-4 text-sm font-bold text-red-100">{state.error}</div>}
      {exportState.error && <div role="alert" className="rounded-2xl border border-red-400/25 bg-red-500/10 px-5 py-4 text-sm font-bold text-red-100">CSV export failed: {exportState.error}</div>}
      {state.loading && !dashboard && <section aria-live="polite" className="cyber-panel grid min-h-64 place-items-center rounded-[1.75rem] p-8 text-center"><div><RefreshCcw className="mx-auto h-7 w-7 animate-spin text-red-300" /><p className="mt-4 text-base font-black text-white">Loading tenant dashboard</p><p className="mt-2 text-sm font-semibold text-slate-500">Reconciling saved scanner findings, asset scope, and operational ownership from PostgreSQL.</p></div></section>}
      {dashboard?.latestRun && platform.selectedCustomer?.assetScopeMode === "inventory" && dashboard.inventory?.inScopeAssets === 0 && <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-amber-300/20 bg-amber-400/[0.06] px-5 py-4"><div><p className="text-sm font-extrabold text-amber-100">Scanner findings are saved, but no approved inventory assets are in scope.</p><p className="mt-1 text-xs font-medium text-amber-100/60">Import the approved asset list or ask an administrator to change the tenant scope policy.</p></div><button type="button" onClick={() => onNavigate?.("assets")} className="secondary-button px-4 py-2 text-xs">Manage asset inventory</button></div>}

      {(!state.loading || dashboard) && <>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
          <MetricCard icon={ShieldAlert} label="Total open" value={metrics.totalOpen} tone="red" detail={dashboard?.currentPeriod || "No report"} />
          <MetricCard icon={ArrowUpRight} label="New" value={metrics.newFindings} tone="orange" detail={comparisonLabel} />
          <MetricCard icon={CheckCircle2} label="Fixed" value={metrics.fixedFindings} tone="green" detail={comparisonLabel} />
          <MetricCard icon={Server} label="Affected assets" value={metrics.affectedAssets} tone="cyan" detail={`${dashboard?.inventory?.inScopeAssets ?? 0} in scope`} />
          <MetricCard icon={CircleAlert} label="Immediate patch" value={metrics.immediatePatch} tone="amber" detail="P1 + P2 findings" />
          <MetricCard icon={Crosshair} label="Exploitable" value={metrics.exploitable} tone="violet" detail="Exploit available" />
        </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px] 2xl:grid-cols-[minmax(0,1fr)_350px]">
        <div className="min-w-0 space-y-4">
          <Panel eyebrow="Vulnerability movement" title="Open vulnerability trend" detail="Latest retained reporting periods">
              {dashboard?.trend?.length ? (
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={dashboard.trend} margin={{ top: 18, right: 18, left: -12, bottom: 0 }}>
                      <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false} />
                      <XAxis dataKey="period" tick={{ fill: "#71717a", fontSize: 11, fontWeight: 700 }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: "#71717a", fontSize: 11, fontWeight: 700 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Line type="monotone" dataKey="totalOpen" name="Total open" stroke="#ef4444" strokeWidth={3} dot={{ fill: "#080809", stroke: "#f87171", strokeWidth: 3, r: 4 }} activeDot={{ r: 6 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : <ChartEmpty />}
          </Panel>

          <div className="grid gap-4 2xl:grid-cols-[.8fr_1.2fr]">
            <Panel eyebrow="Current Exposure" title="Severity profile" detail="Normalized across scanner sources">
              <SeverityBars severity={dashboard?.severity} />
            </Panel>
            <Panel eyebrow="Remediation Aging" title="Age by patch priority" detail="Open findings grouped into operational age bands">
              <AgeMatrix rows={dashboard?.ageByPriority ?? []} />
            </Panel>
          </div>

          <Panel eyebrow="Asset Risk" title="Most affected assets" detail="Ranked by current open finding count">
            <TopAssets assets={dashboard?.topAssets ?? []} />
          </Panel>

          {teams.length > 0 && <Panel eyebrow="Operational Ownership" title="Responsible team posture" detail="Assets and current findings mapped to each resolver team"><TeamOwnership teams={dashboard?.teamBreakdown ?? []} /></Panel>}
        </div>

        <aside className="space-y-4">
          <PriorityReference />
          <Panel eyebrow="Risk Concentration" title="Patch priority" detail="Current open findings">
            <PriorityBars priority={dashboard?.priority} />
          </Panel>
          <InventoryCard dashboard={dashboard} customer={platform.selectedCustomer} onNavigate={onNavigate} />
          <SourceCard sources={dashboard?.sources ?? {}} />
          <RecentRuns runs={dashboard?.recentRuns ?? []} />
        </aside>
      </div></>}
    </div>
  );
}

function DashboardSelect({ label, value, onChange, children }) {
  return (
    <label className="block rounded-xl border border-white/[0.08] bg-black/20 px-3 py-2.5">
      <span className="block font-mono text-[0.5rem] font-bold uppercase tracking-[0.13em] text-slate-700">{label}</span>
      <select aria-label={label} value={value} onChange={onChange} className="mt-1 w-full min-w-0 bg-transparent text-xs font-bold text-slate-200 outline-none">
        {children}
      </select>
    </label>
  );
}

function MetricCard({ icon: Icon, label, value = 0, tone, detail }) {
  const tones = {
    red: "border-red-400/15 text-red-300 after:bg-red-500",
    orange: "border-orange-400/15 text-orange-300 after:bg-orange-500",
    green: "border-emerald-400/15 text-emerald-300 after:bg-emerald-500",
    cyan: "border-cyan-400/15 text-cyan-300 after:bg-cyan-500",
    amber: "border-amber-400/15 text-amber-300 after:bg-amber-400",
    violet: "border-blue-400/15 text-blue-300 after:bg-blue-500",
  };
  return (
    <article className={`relative min-w-0 overflow-hidden rounded-[0.9rem] border bg-[#111113] p-4 after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 after:opacity-70 ${tones[tone]}`}>
      <div className="flex items-center justify-between gap-2">
        <p className="truncate font-mono text-[0.58rem] font-bold uppercase tracking-[0.12em] text-slate-500">{label}</p>
        <Icon className="h-4 w-4 shrink-0" />
      </div>
      <p className="mt-3 text-2xl font-extrabold tracking-[-0.04em] text-white">{Number(value || 0).toLocaleString()}</p>
      <p className="mt-1.5 truncate text-[0.64rem] font-semibold text-slate-600">{detail}</p>
    </article>
  );
}

function assetDisplayName(asset = {}) {
  return asset.dnsName || asset.hostName || asset.ipAddress || asset.assetKey || "Unnamed asset";
}

function assetOptionLabel(asset = {}) {
  const name = assetDisplayName(asset);
  const details = [asset.ipAddress && asset.ipAddress !== name ? asset.ipAddress : "", asset.teamName].filter(Boolean);
  return details.length ? `${name} · ${details.join(" · ")}` : name;
}

function Panel({ eyebrow, title, detail, children }) {
  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <p className="mini-label">{eyebrow}</p>
      <div className="mt-1 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-lg font-extrabold text-white">{title}</h3>
        <p className="text-xs font-medium text-slate-600">{detail}</p>
      </div>
      <div className="mt-5">{children}</div>
    </section>
  );
}

function PriorityBars({ priority = {} }) {
  const data = ["P1", "P2", "P3", "P4"].map((name) => ({ name, count: Number(priority?.[name] ?? 0) }));
  if (!data.some((item) => item.count)) return <ChartEmpty />;
  return (
    <div className="grid grid-cols-4 gap-2">
      {data.map((item) => (
        <div key={item.name} className="rounded-xl border p-3" style={{ borderColor: `${priorityColors[item.name]}2b`, backgroundColor: `${priorityColors[item.name]}0d` }}>
          <p className="font-mono text-[0.62rem] font-bold" style={{ color: priorityColors[item.name] }}>{item.name}</p>
          <p className="mt-2 text-lg font-extrabold tracking-tight text-white">{item.count.toLocaleString()}</p>
        </div>
      ))}
    </div>
  );
}

function SeverityBars({ severity = {} }) {
  const data = ["Critical", "High", "Medium", "Low", "Info"].map((name) => ({ name, count: Number(severity?.[name] ?? severity?.[name.toLowerCase()] ?? 0) }));
  const total = data.reduce((sum, item) => sum + item.count, 0);
  if (!total) return <ChartEmpty />;
  return (
    <div className="space-y-4">
      {data.map((item) => (
        <div key={item.name}>
          <div className="mb-2 flex items-center justify-between text-xs font-bold"><span className="text-slate-400">{item.name}</span><span className="text-white">{item.count.toLocaleString()}</span></div>
          <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]"><div className="h-full rounded-full" style={{ width: `${total ? Math.max(item.count ? 2 : 0, item.count / total * 100) : 0}%`, backgroundColor: severityColors[item.name] }} /></div>
        </div>
      ))}
    </div>
  );
}

function AgeMatrix({ rows }) {
  const lookup = useMemo(() => new Map(rows.map((row) => [`${row.priority}|${row.bucket}`, row.count])), [rows]);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-separate border-spacing-1.5 text-left">
        <thead><tr><th className="px-2 py-2 font-mono text-[0.62rem] uppercase tracking-wider text-slate-600">Priority</th>{ageBuckets.map((bucket) => <th key={bucket} className="px-2 py-2 text-center font-mono text-[0.6rem] uppercase tracking-wider text-slate-500">{bucket}</th>)}</tr></thead>
        <tbody>{["P1", "P2", "P3", "P4"].map((priority) => (
          <tr key={priority}>
            <th className="rounded-lg px-3 py-3 text-sm font-black text-white" style={{ backgroundColor: `${priorityColors[priority]}22`, color: priorityColors[priority] }}>{priority}</th>
            {ageBuckets.map((bucket) => <td key={bucket} className="rounded-lg border border-white/[0.06] bg-white/[0.025] px-3 py-3 text-center text-sm font-black text-slate-200">{Number(lookup.get(`${priority}|${bucket}`) ?? 0).toLocaleString()}</td>)}
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

function TopAssets({ assets }) {
  if (!assets.length) return <ChartEmpty label="No affected assets are available yet." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-left">
        <thead className="font-mono text-[0.62rem] uppercase tracking-[0.12em] text-slate-600"><tr><th className="pb-3">Asset</th><th className="pb-3">IP address</th><th className="pb-3 text-right">P1</th><th className="pb-3 text-right">P2</th><th className="pb-3 text-right">Total open</th></tr></thead>
        <tbody className="divide-y divide-white/[0.06]">{assets.map((asset, index) => (
          <tr key={`${asset.asset}-${index}`}><td className="py-3 pr-4 text-sm font-black text-white">{asset.asset}</td><td className="py-3 pr-4 font-mono text-xs font-semibold text-slate-500">{asset.ipAddress || "—"}</td><td className="py-3 text-right text-sm font-black text-red-300">{asset.p1}</td><td className="py-3 text-right text-sm font-black text-orange-300">{asset.p2}</td><td className="py-3 text-right text-sm font-black text-white">{asset.total}</td></tr>
        ))}</tbody>
      </table>
    </div>
  );
}

function TeamOwnership({ teams }) {
  if (!teams.length) return <ChartEmpty label="Assign assets to operational teams to populate ownership metrics." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left">
        <thead className="font-mono text-[0.62rem] uppercase tracking-[0.12em] text-slate-600"><tr><th className="pb-3">Responsible team</th><th className="pb-3 text-right">In-scope assets</th><th className="pb-3 text-right">P1</th><th className="pb-3 text-right">P2</th><th className="pb-3 text-right">Total open</th></tr></thead>
        <tbody className="divide-y divide-white/[0.06]">{teams.map((team) => <tr key={team.id}><td className="py-3 pr-4"><div className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded-xl border border-red-400/20 bg-red-500/[0.07] text-red-300"><UsersRound className="h-4 w-4" /></span><div><p className="text-sm font-black text-white">{team.name}</p><p className="mt-0.5 font-mono text-[0.62rem] font-bold uppercase text-slate-600">{team.code}</p></div></div></td><td className="py-3 text-right text-sm font-black text-slate-300">{team.inScopeAssetCount.toLocaleString()}</td><td className="py-3 text-right text-sm font-black text-red-300">{team.p1.toLocaleString()}</td><td className="py-3 text-right text-sm font-black text-orange-300">{team.p2.toLocaleString()}</td><td className="py-3 text-right text-sm font-black text-white">{team.totalOpen.toLocaleString()}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

function PriorityReference() {
  const rows = [
    ["Critical", "P1", "P2"],
    ["High", "P1", "P2"],
    ["Medium", "P2", "P3"],
    ["Low", "P2", "P4"],
  ];
  return (
    <section className="enterprise-panel p-5">
      <p className="mini-label">Calculation Reference</p>
      <h3 className="mt-1 text-lg font-extrabold text-white">Patch priority matrix</h3>
      <p className="mt-2 text-xs font-medium leading-5 text-slate-500">Priority is calculated from normalized severity and whether an exploit is available.</p>
      <div className="mt-5 grid grid-cols-[1fr_.72fr_.72fr] gap-1.5 text-center text-xs font-extrabold">
        <span className="p-2 text-left font-mono text-[0.56rem] uppercase text-slate-600">Severity</span><span className="p-2 font-mono text-[0.54rem] uppercase leading-4 text-slate-500">Exploit available<br />Yes</span><span className="p-2 font-mono text-[0.54rem] uppercase leading-4 text-slate-500">Exploit available<br />No</span>
        {rows.flatMap(([severity, yes, no]) => [
          <span key={`${severity}-label`} className="rounded-lg border border-white/[0.06] bg-white/[0.03] p-2 text-left text-slate-300">{severity}</span>,
          <span key={`${severity}-yes`} className="rounded-lg p-2" style={{ color: priorityColors[yes], backgroundColor: `${priorityColors[yes]}18` }}>{yes}</span>,
          <span key={`${severity}-no`} className="rounded-lg p-2" style={{ color: priorityColors[no], backgroundColor: `${priorityColors[no]}18` }}>{no}</span>,
        ])}
      </div>
    </section>
  );
}

function InventoryCard({ dashboard, customer, onNavigate }) {
  const inventory = dashboard?.inventory ?? {};
  const categories = Object.entries(inventory.assetTypes ?? {}).sort((left, right) => right[1] - left[1]);
  return (
    <section className="enterprise-panel p-5">
      <div className="flex items-start justify-between"><div><p className="mini-label">Asset Scope</p><h3 className="mt-1 text-lg font-extrabold text-white">Known asset inventory</h3></div><Boxes className="h-6 w-6 text-cyan-300" /></div>
      <div className="mt-5 grid grid-cols-2 gap-2">
        <MiniMetric label="In scope" value={inventory.inScopeAssets} />
        <MiniMetric label="Total known" value={inventory.totalAssets} />
        <MiniMetric label="Imported" value={inventory.manualAssets} />
        <MiniMetric label="Discovered" value={inventory.discoveredAssets} />
      </div>
      {categories.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{categories.slice(0, 5).map(([assetType, count]) => <span key={assetType} className="rounded-lg border border-cyan-300/10 bg-cyan-400/[0.05] px-2 py-1 text-[0.62rem] font-bold text-cyan-200">{count} {assetType}</span>)}</div>}
      <p className="mt-4 rounded-xl border border-white/[0.07] bg-black/25 px-3 py-3 text-xs font-semibold leading-5 text-slate-500">Scope policy: <span className="font-black text-slate-300">{customer?.assetScopeMode === "inventory" ? "Approved inventory only" : "Combined imported + scanner-discovered assets"}</span></p>
      {dashboard?.metrics?.excludedByScope > 0 && <p className="mt-2 text-xs font-bold text-amber-300">{dashboard.metrics.excludedByScope.toLocaleString()} findings excluded by tenant scope.</p>}
      <button type="button" onClick={() => onNavigate?.("assets")} className="secondary-button mt-4 w-full py-2.5 text-sm">Manage asset inventory</button>
    </section>
  );
}

function SourceCard({ sources }) {
  const entries = Object.entries(sources);
  return (
    <section className="enterprise-panel p-5">
      <p className="mini-label">Scanner Coverage</p><h3 className="mt-1 text-lg font-extrabold text-white">Source contribution</h3>
      <div className="mt-4 space-y-2">{entries.length ? entries.map(([source, count]) => <div key={source} className="flex items-center justify-between rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-3"><span className="text-xs font-black uppercase text-slate-400">{source}</span><span className="text-sm font-black text-white">{Number(count).toLocaleString()}</span></div>) : <p className="text-sm font-semibold text-slate-600">No saved scanner coverage.</p>}</div>
    </section>
  );
}

function RecentRuns({ runs }) {
  return (
    <section className="enterprise-panel p-5">
      <p className="mini-label">Evidence History</p><h3 className="mt-1 text-lg font-extrabold text-white">Recent reports</h3>
      <div className="mt-4 space-y-2">{runs.length ? runs.slice(0, 5).map((run) => <div key={run.id} className="rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-3"><div className="flex items-center justify-between gap-3"><span className="truncate text-xs font-black text-white">{run.reportPeriod}</span><span className="shrink-0 text-xs font-black text-red-300">{run.weightedFindings.toLocaleString()}</span></div><p className="mt-1 truncate text-[0.68rem] font-semibold text-slate-600">{run.sourceLabel}</p></div>) : <p className="text-sm font-semibold text-slate-600">No saved reports.</p>}</div>
    </section>
  );
}

function MiniMetric({ label, value = 0 }) {
  return <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><p className="font-mono text-[0.58rem] font-bold uppercase tracking-wider text-slate-600">{label}</p><p className="mt-2 text-xl font-black text-white">{Number(value).toLocaleString()}</p></div>;
}

function NoCustomers({ onNavigate }) {
  return (
    <section className="cyber-panel rounded-[2rem] p-8 sm:p-12">
      <div className="mx-auto max-w-2xl text-center"><div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-red-400/25 bg-red-500/10"><Database className="h-7 w-7 text-red-300" /></div><p className="mini-label mt-6">Platform ready</p><h2 className="mt-2 text-3xl font-black text-white">Create your first tenant</h2><p className="mt-3 text-sm font-semibold leading-6 text-slate-400">A tenant is the isolation boundary for users, assets, scanner reports, lifecycle metrics, exports, and remediation evidence.</p><button type="button" onClick={() => onNavigate?.("admin")} className="neon-button mt-7 inline-flex items-center gap-2"><Boxes className="h-4 w-4" /> Open administration</button></div>
    </section>
  );
}

function ChartEmpty({ label = "Save an analyzed report to populate this view." }) {
  return <div className="grid h-64 place-items-center rounded-2xl border border-dashed border-white/10 bg-black/15 px-6 text-center text-sm font-semibold text-slate-600">{label}</div>;
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="rounded-xl border border-white/10 bg-black/95 px-3 py-2 shadow-2xl"><p className="text-xs font-black text-white">{label}</p>{payload.map((item) => <p key={item.dataKey} className="mt-1 text-xs font-bold" style={{ color: item.color }}>{item.name}: {Number(item.value).toLocaleString()}</p>)}</div>;
}
