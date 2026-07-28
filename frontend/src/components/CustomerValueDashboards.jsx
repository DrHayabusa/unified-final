import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  BadgeCheck,
  BookOpenCheck,
  CheckCircle2,
  ClipboardCheck,
  FileWarning,
  Layers3,
  Radar,
  RotateCcw,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

const TABS = [
  ["threat", "Threat Signals"],
  ["campaigns", "Campaigns"],
  ["verification", "Verification"],
  ["quality", "Data Quality"],
];
const PRIORITY_TONES = { P1: "bg-red-500/15 text-red-200", P2: "bg-orange-500/15 text-orange-200", P3: "bg-amber-500/15 text-amber-100", P4: "bg-emerald-500/15 text-emerald-200" };
const TOOLTIP_STYLE = { backgroundColor: "#09090b", border: "1px solid rgba(248,113,113,.24)", borderRadius: 14, color: "#f8fafc", fontSize: 12 };

export function CustomerValueDashboards({ analysis }) {
  const [activeTab, setActiveTab] = useState("threat");
  const insights = analysis?.dashboard?.customerValueInsights;
  if (!insights) return null;

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6" data-testid="customer-value-dashboards">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">Decision Intelligence</p>
          <h2 className="mt-1 text-2xl font-black text-white">Evidence-driven remediation operations</h2>
          <p className="mt-2 max-w-4xl text-sm font-semibold leading-6 text-slate-400">
            Threat signals, remediation grouping, scan-to-scan verification, and evidence completeness derived from the uploaded scanner exports. Your approved P1-P4 matrix remains unchanged.
          </p>
        </div>
        <span className="rounded-full border border-emerald-300/20 bg-emerald-400/[0.08] px-4 py-2 text-xs font-black text-emerald-200">Scanner evidence only</span>
      </div>

      <div className="mt-6 flex flex-wrap gap-2" role="tablist" aria-label="Decision intelligence dashboards">
        {TABS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={activeTab === id}
            onClick={() => setActiveTab(id)}
            className={`rounded-xl border px-4 py-2.5 text-xs font-black transition ${activeTab === id ? "border-red-300/35 bg-red-500/15 text-white shadow-glow" : "border-white/10 bg-black/20 text-slate-400 hover:border-white/20 hover:text-white"}`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="mt-5">
        {activeTab === "threat" && <ThreatDashboard threat={insights.threatPriority} />}
        {activeTab === "campaigns" && <CampaignDashboard data={insights.remediationCampaigns} />}
        {activeTab === "verification" && <VerificationDashboard verification={insights.verification} />}
        {activeTab === "quality" && <DataQualityDashboard quality={insights.dataQuality} />}
      </div>
    </section>
  );
}

function ThreatDashboard({ threat }) {
  const exposureValue = threat.internetExposureObserved ? threat.internetExposed : "Not supplied";
  const exposureHelper = threat.internetExposureObserved
    ? `${threat.internetExposureObserved} assessed | ${threat.internetExposureUnknown} unknown`
    : `${threat.internetExposureUnknown} findings have unknown exposure`;
  const metrics = [
    [ShieldAlert, "Threat Review Queue", threat.reviewQueue, "Additional evidence warrants review", "text-red-300"],
    [Radar, "Exploit Available", threat.exploitAvailable, "Scanner-reported exploit signal", "text-amber-200"],
    [Layers3, "Confirmed Internet Exposed", exposureValue, exposureHelper, "text-sky-300"],
    [Sparkles, "EPSS >= 50%", threat.epssAbove50, `${threat.epssObserved} findings include EPSS`, "text-cyan-300"],
  ];

  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(([Icon, label, value, helper, tone]) => <MetricCard key={label} icon={Icon} label={label} value={value} helper={helper} tone={tone} />)}
      </div>

      <div className="mt-5">
        <div className="mb-4 rounded-2xl border border-sky-300/15 bg-sky-400/[0.05] px-4 py-3 text-xs font-semibold leading-5 text-sky-100/80">
          Threat signals help analysts focus their review using exploit, exposure, EPSS, and severity evidence from the uploaded files. They do not change the approved P1-P4 patch priority.
        </div>
        <DataTable
          title="Threat-priority review queue"
          subtitle="Threat evidence is an overlay; Patch Priority is not recalculated"
          headers={["Priority", "Asset", "Service", "Vulnerability", "Evidence", "Exposure"]}
          empty="No findings meet the current threat-review criteria."
        >
          {threat.queue.slice(0, 10).map((row, index) => (
            <tr key={`${row.asset}-${row.vulnerability}-${index}`} className="border-t border-white/5 text-slate-300">
              <td className="px-3 py-3"><PriorityBadge value={row.priority} /></td>
              <td className="max-w-48 truncate px-3 py-3 font-bold text-white" title={row.asset}>{row.asset}</td>
              <td className="px-3 py-3 font-mono text-[0.68rem] text-slate-500">{row.service}</td>
              <td className="px-3 py-3"><p className="font-bold text-white">{row.vulnerability}</p>{row.cve && <p className="mt-1 font-mono text-[0.65rem] text-slate-500">{row.cve}</p>}</td>
              <td className="px-3 py-3 text-xs text-slate-400">{row.signals.join(" | ")}</td>
              <td className="px-3 py-3 font-black text-red-200">{row.exposure.toLocaleString()}</td>
            </tr>
          ))}
        </DataTable>
      </div>
    </div>
  );
}

function CampaignDashboard({ data }) {
  const chartData = data.campaigns.slice(0, 8).map((campaign) => ({
    name: shorten(campaign.title, 28),
    findings: campaign.findingCount,
  }));
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={ClipboardCheck} label="Remediation Campaigns" value={data.campaignCount} helper="Grouped by vulnerability and action" tone="text-red-300" />
        <MetricCard icon={Layers3} label="Multi-asset Campaigns" value={data.multiAssetCampaigns} helper="One action across multiple assets" tone="text-orange-300" />
        <MetricCard icon={CheckCircle2} label="Action Ready" value={data.actionReady} helper="Remediation steps available" tone="text-emerald-300" />
        <MetricCard icon={BookOpenCheck} label="Reference Ready" value={data.referenceReady} helper="KB or advisory evidence available" tone="text-sky-300" />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[0.75fr_1.25fr]">
        <article className="rounded-2xl border border-white/10 bg-black/25 p-5">
          <p className="mini-label">Campaign Concentration</p>
          <h3 className="mt-1 text-lg font-black text-white">Highest-volume remediation groups</h3>
          <p className="mt-2 text-xs font-semibold leading-5 text-slate-500">Campaign tables are included in Excel for downstream ticket or change workflows.</p>
          <div className="mt-4 h-[340px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 16, bottom: 5, left: 6 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" allowDecimals={false} stroke="#64748b" />
                <YAxis type="category" dataKey="name" width={150} stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="findings" name="Open Findings" fill="#f87171" radius={[0, 7, 7, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>

        <DataTable
          title="Remediation campaign queue"
          subtitle={`${data.immediatePatchFindings.toLocaleString()} P1/P2 findings grouped into actionable work packages`}
          headers={["Priority", "Campaign", "Findings", "Assets", "Sources", "Readiness"]}
          empty="No remediation campaigns could be derived."
        >
          {data.campaigns.slice(0, 12).map((campaign) => (
            <tr key={campaign.id} className="border-t border-white/5 text-slate-300">
              <td className="px-3 py-3"><PriorityBadge value={campaign.primaryPriority} /></td>
              <td className="px-3 py-3"><p className="font-bold text-white">{campaign.title}</p><p className="mt-1 max-w-xl text-xs leading-5 text-slate-500">{shorten(campaign.action || "Remediation text not provided by source", 145)}</p></td>
              <td className="px-3 py-3 font-black text-white">{campaign.findingCount.toLocaleString()}</td>
              <td className="px-3 py-3">{campaign.assets.length.toLocaleString()}</td>
              <td className="px-3 py-3">{campaign.sources.length.toLocaleString()}</td>
              <td className="px-3 py-3 text-xs"><span className={campaign.actionReady ? "text-emerald-300" : "text-amber-200"}>{campaign.actionReady ? "Steps" : "Needs steps"}</span><span className="mx-1 text-slate-700">|</span><span className={campaign.referenceReady ? "text-sky-300" : "text-slate-500"}>{campaign.referenceReady ? "Reference" : "No reference"}</span></td>
            </tr>
          ))}
        </DataTable>
      </div>
    </div>
  );
}

function VerificationDashboard({ verification }) {
  if (!verification.available) {
    return (
      <div className="grid min-h-72 place-items-center rounded-2xl border border-dashed border-white/15 bg-black/20 p-8 text-center">
        <div className="max-w-2xl">
          <RotateCcw className="mx-auto h-10 w-10 text-slate-500" />
          <h3 className="mt-4 text-xl font-black text-white">Comparison data required</h3>
          <p className="mt-2 text-sm font-semibold leading-6 text-slate-400">{verification.message}</p>
        </div>
      </div>
    );
  }

  const statusData = [
    { status: "Persisting", count: verification.persistent, color: "#f97316" },
    { status: "New", count: verification.newFindings, color: "#38bdf8" },
    { status: "Reappeared", count: verification.reappeared, color: "#ef4444" },
    { status: "Not observed", count: verification.noLongerObserved, color: "#22c55e" },
  ];
  return (
    <div>
      <div className="rounded-2xl border border-amber-300/20 bg-amber-400/[0.06] px-4 py-3 text-xs font-semibold leading-5 text-amber-100/80">{verification.message}</div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard icon={RotateCcw} label="Persisting" value={verification.persistent} helper={`${verification.persistenceRate}% of previous open`} tone="text-orange-300" />
        <MetricCard icon={Sparkles} label="New" value={verification.newFindings} helper={`Added in ${verification.currentPeriod}`} tone="text-sky-300" />
        <MetricCard icon={FileWarning} label="Reappeared" value={verification.reappeared} helper="Seen earlier, absent last period" tone="text-red-300" />
        <MetricCard icon={CheckCircle2} label="Not Observed" value={verification.noLongerObserved} helper="Requires closure evidence" tone="text-emerald-300" />
        <MetricCard icon={BadgeCheck} label="Reconciled" value={verification.reconciled ? "Yes" : "No"} helper={`${verification.previousTotal} previous -> ${verification.currentTotal} current`} tone={verification.reconciled ? "text-emerald-300" : "text-red-300"} />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[0.7fr_1.3fr]">
        <article className="rounded-2xl border border-white/10 bg-black/25 p-5">
          <p className="mini-label">Latest Period Movement</p>
          <h3 className="mt-1 text-lg font-black text-white">{verification.previousPeriod} to {verification.currentPeriod}</h3>
          <div className="mt-4 h-[290px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} margin={{ top: 10, right: 10, bottom: 4, left: -18 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="status" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Findings" radius={[7, 7, 0, 0]} isAnimationActive={false}>{statusData.map((row) => <Cell key={row.status} fill={row.color} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>

        <DataTable
          title="Closure evidence candidates"
          subtitle="Findings present previously and not observed in the latest scan"
          headers={["Priority", "Asset", "Service", "Vulnerability", "Count", "Exposure"]}
          empty="No findings disappeared between the latest two reports."
        >
          {verification.closureCandidates.slice(0, 12).map((row, index) => (
            <tr key={`${row.asset}-${row.vulnerability}-${index}`} className="border-t border-white/5 text-slate-300">
              <td className="px-3 py-3"><PriorityBadge value={row.priority} /></td>
              <td className="max-w-48 truncate px-3 py-3 font-bold text-white" title={row.asset}>{row.asset}</td>
              <td className="px-3 py-3 font-mono text-[0.68rem] text-slate-500">{row.service}</td>
              <td className="px-3 py-3"><p className="font-bold text-white">{row.vulnerability}</p>{row.cve && <p className="mt-1 font-mono text-[0.65rem] text-slate-500">{row.cve}</p>}</td>
              <td className="px-3 py-3 font-black">{row.count}</td>
              <td className="px-3 py-3 text-emerald-200">{row.exposure}</td>
            </tr>
          ))}
        </DataTable>
      </div>
    </div>
  );
}

function DataQualityDashboard({ quality }) {
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={BadgeCheck} label="Evidence Completeness" value={`${quality.evidenceCompleteness}%`} helper="Across eight normalized evidence fields" tone="text-emerald-300" />
        <MetricCard icon={CheckCircle2} label="Core Complete" value={quality.completeCore} helper={`Of ${quality.totalFindings} open findings`} tone="text-cyan-300" />
        <MetricCard icon={FileWarning} label="Open Data Gaps" value={quality.issues.length} helper="Field categories with missing values" tone="text-amber-200" />
        <MetricCard icon={Radar} label="Stale Observations" value={quality.staleObservations} helper=">30 days behind report date" tone="text-red-300" />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
        <article className="rounded-2xl border border-white/10 bg-black/25 p-5">
          <p className="mini-label">Normalized Field Coverage</p>
          <h3 className="mt-1 text-lg font-black text-white">Evidence completeness by field</h3>
          <div className="mt-5 grid gap-4">
            {quality.completeness.map((row) => (
              <div key={row.label}>
                <div className="mb-2 flex items-center justify-between gap-3 text-xs font-bold"><span className="text-slate-300">{row.label}</span><span className="font-mono text-white">{row.percent}%</span></div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-gradient-to-r from-red-500 via-orange-400 to-emerald-400" style={{ width: `${row.percent}%` }} /></div>
              </div>
            ))}
          </div>
        </article>

        <DataTable title="Data-quality attention" subtitle="Missing values are reported, never silently invented" headers={["Field", "Present", "Missing", "Coverage"]} empty="No normalized data gaps detected.">
          {quality.issues.map((row) => (
            <tr key={row.label} className="border-t border-white/5 text-slate-300">
              <td className="px-3 py-3 font-bold text-white">{row.label}</td>
              <td className="px-3 py-3 text-emerald-200">{row.present}</td>
              <td className="px-3 py-3 text-amber-200">{row.missing}</td>
              <td className="px-3 py-3 font-mono text-xs">{row.percent}%</td>
            </tr>
          ))}
        </DataTable>
      </div>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, helper, tone }) {
  return (
    <article className="rounded-2xl border border-white/10 bg-black/25 p-4">
      <Icon className={`h-5 w-5 ${tone}`} />
      <p className="mt-4 text-2xl font-black text-white">{typeof value === "number" ? value.toLocaleString() : value}</p>
      <p className="mt-1 text-[0.64rem] font-black uppercase tracking-[0.12em] text-slate-400">{label}</p>
      <p className="mt-2 text-[0.68rem] font-semibold leading-4 text-slate-600">{helper}</p>
    </article>
  );
}

function DataTable({ title, subtitle, headers, empty, children }) {
  const childCount = Array.isArray(children) ? children.length : children ? 1 : 0;
  return (
    <article className="overflow-hidden rounded-2xl border border-white/10 bg-black/25">
      <div className="border-b border-white/10 p-5"><h3 className="text-lg font-black text-white">{title}</h3><p className="mt-1 text-xs font-semibold text-slate-500">{subtitle}</p></div>
      {childCount ? (
        <div className="max-h-[420px] overflow-auto">
          <table className="w-full min-w-[720px] text-left text-xs">
            <thead className="sticky top-0 z-10 bg-zinc-950 uppercase tracking-wide text-slate-500"><tr>{headers.map((header) => <th key={header} className="px-3 py-3 font-black">{header}</th>)}</tr></thead>
            <tbody>{children}</tbody>
          </table>
        </div>
      ) : <p className="p-8 text-center text-sm font-semibold text-slate-500">{empty}</p>}
    </article>
  );
}

function PriorityBadge({ value }) {
  return <span className={`inline-flex min-w-9 justify-center rounded-lg px-2 py-1 font-black ${PRIORITY_TONES[value] ?? "bg-slate-500/15 text-slate-300"}`}>{value}</span>;
}

function shorten(value, maxLength) {
  const text = String(value ?? "").trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
}
