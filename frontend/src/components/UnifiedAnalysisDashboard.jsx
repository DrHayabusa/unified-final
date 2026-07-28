import {
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, Crosshair, Layers3, Radar, ShieldAlert, ShieldCheck } from "lucide-react";

const PRIORITY_COLORS = { P1: "#ef4444", P2: "#f97316", P3: "#eab308", P4: "#22c55e" };
const TOOLTIP_STYLE = {
  backgroundColor: "#09090b",
  border: "1px solid rgba(248,113,113,.24)",
  borderRadius: 14,
  color: "#f8fafc",
  fontSize: 12,
};

export function UnifiedAnalysisDashboard({ dashboard }) {
  const insights = dashboard?.unifiedInsights;
  if (!insights) return null;
  const trend = dashboard?.unifiedTrend ?? [];
  const historical = trend.length > 1;
  const priorityData = Object.entries(insights.patchPriorityCounts).map(([priority, findingCount]) => ({ priority, findingCount }));

  const metrics = [
    { label: "Confirmed by multiple tools", value: insights.crossToolConfirmed, helper: "Same finding reported by 2+ tools", icon: ShieldCheck, tone: "text-emerald-300" },
    { label: "Reported by one tool", value: insights.singleSourceOnly, helper: "Seen in exactly 1 selected tool", icon: Radar, tone: "text-sky-300" },
    { label: "Confirmation rate", value: `${insights.confirmationRate}%`, helper: "Multi-tool confirmed / total open", icon: Layers3, tone: "text-cyan-300" },
    { label: "Immediate patch", value: insights.immediatePatch, helper: "P1 + P2 findings", icon: ShieldAlert, tone: "text-red-300" },
    { label: "Exploit available", value: insights.exploitAvailable, helper: "Positive exploit evidence", icon: Crosshair, tone: "text-orange-300" },
    { label: "Affected assets", value: insights.distinctAssets, helper: "Unique consolidated assets", icon: Activity, tone: "text-violet-300" },
  ];

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">Consolidated analysis</p>
          <h2 className="mt-1 text-2xl font-black text-white">Consolidated analysis</h2>
          <p className="mt-2 max-w-4xl text-sm font-semibold leading-6 text-slate-400">
            One view across the selected tools. A finding is confirmed by multiple tools only when its asset, vulnerability, protocol, and port match. Different vulnerabilities on the same asset remain separate findings.
          </p>
        </div>
        <span className="rounded-full border border-red-300/20 bg-red-400/[0.08] px-4 py-2 text-xs font-black text-red-100">
          {insights.totalOpen.toLocaleString()} consolidated open
        </span>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {metrics.map(({ label, value, helper, icon: Icon, tone }) => (
          <article key={label} className="rounded-2xl border border-white/10 bg-black/25 p-4">
            <Icon className={`h-5 w-5 ${tone}`} />
            <p className="mt-4 text-2xl font-black text-white">{typeof value === "number" ? value.toLocaleString() : value}</p>
            <p className="mt-1 text-[0.65rem] font-black uppercase tracking-[0.12em] text-slate-400">{label}</p>
            <p className="mt-2 text-[0.68rem] font-semibold text-slate-600">{helper}</p>
          </article>
        ))}
      </div>

      {historical ? (
        <div className="mt-6 grid gap-5 xl:grid-cols-2">
          <ChartCard title="Consolidated vulnerability trend" subtitle="Open, new, and patched findings across all selected tools">
            <ResponsiveContainer width="100%" height={285}>
              <LineChart data={trend} margin={{ top: 14, right: 20, bottom: 6, left: -8 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="period" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={legendStyle} />
                <Line type="monotone" dataKey="totalOpen" name="Total Open" stroke="#f87171" strokeWidth={3} dot={{ r: 4 }} isAnimationActive={false} />
                <Line type="monotone" dataKey="newFindings" name="New" stroke="#38bdf8" strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
                <Line type="monotone" dataKey="patchedFindings" name="Patched" stroke="#34d399" strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Patch-priority movement" subtitle="P1-P4 exposure across all open findings">
            <ResponsiveContainer width="100%" height={285}>
              <LineChart data={trend} margin={{ top: 14, right: 20, bottom: 6, left: -8 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="period" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={legendStyle} />
                {Object.entries(PRIORITY_COLORS).map(([priority, color]) => (
                  <Line key={priority} type="monotone" dataKey={priority} name={priority} stroke={color} strokeWidth={priority === "P1" ? 3 : 2.25} dot={{ r: 3 }} isAnimationActive={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard className="xl:col-span-2" title="Finding confirmation trend" subtitle="Findings confirmed by multiple tools, reported by one tool, and repeated rows removed during consolidation">
            <ResponsiveContainer width="100%" height={275}>
              <BarChart data={trend} margin={{ top: 14, right: 20, bottom: 6, left: -8 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="period" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={legendStyle} />
                <Bar dataKey="crossToolConfirmed" name="Confirmed by Multiple Tools" fill="#34d399" radius={[6, 6, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="singleSourceOnly" name="Reported by One Tool" fill="#38bdf8" radius={[6, 6, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="repeatsRemoved" name="Repeated Rows Removed" fill="#f97316" radius={[6, 6, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
        </div>
      ) : (
        <div className="mt-6 grid gap-5 xl:grid-cols-2">
          <ChartCard title="Findings by number of reporting tools" subtitle="Same asset, vulnerability, protocol, and port reported by exactly 1, 2, 3, or 4 selected tools">
            <ResponsiveContainer width="100%" height={265}>
              <BarChart data={insights.sourceAgreementDistribution} margin={{ top: 14, right: 20, bottom: 6, left: -8 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="label" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="findingCount" name="Open Findings" fill="#34d399" radius={[8, 8, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Consolidated priority distribution" subtitle="Open findings after multi-tool consolidation">
            <ResponsiveContainer width="100%" height={265}>
              <BarChart data={priorityData} margin={{ top: 14, right: 20, bottom: 6, left: -8 }}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="priority" stroke="#64748b" />
                <YAxis allowDecimals={false} stroke="#64748b" />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="findingCount" name="Open Findings" radius={[8, 8, 0, 0]} isAnimationActive={false}>
                  {priorityData.map((row) => <Cell key={row.priority} fill={PRIORITY_COLORS[row.priority]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
        </div>
      )}

      <div className="mt-6 grid gap-5 xl:grid-cols-2">
        <RiskTable title="Highest-risk assets" columns={["Asset", "Open", "P1/P2", "Critical", "Exploit", "Sources", "Exposure"]}>
          {insights.topRiskAssets.map((row) => (
            <tr key={row.asset} className="border-t border-white/5 text-slate-300">
              <RiskName value={row.asset} />
              <RiskNumber value={row.totalOpen} />
              <RiskNumber value={row.immediatePatch} tone="text-red-200" />
              <RiskNumber value={row.critical} tone="text-red-300" />
              <RiskNumber value={row.exploitAvailable} tone="text-orange-200" />
              <RiskNumber value={row.sourceCount} tone="text-emerald-200" />
              <RiskNumber value={row.maxExposure} tone="text-cyan-200" />
            </tr>
          ))}
        </RiskTable>

        <RiskTable title="Highest-impact vulnerabilities" columns={["Vulnerability", "Open", "Assets", "P1/P2", "Exploit", "Sources"]}>
          {insights.topVulnerabilities.map((row) => (
            <tr key={`${row.cve}-${row.vulnerability}`} className="border-t border-white/5 text-slate-300">
              <td className="max-w-[260px] px-3 py-3">
                <p className="truncate font-black text-white" title={row.vulnerability}>{row.vulnerability}</p>
                {row.cve && <p className="mt-1 truncate font-mono text-[0.65rem] text-red-300">{row.cve}</p>}
              </td>
              <RiskNumber value={row.totalOpen} />
              <RiskNumber value={row.affectedAssets} tone="text-sky-200" />
              <RiskNumber value={row.immediatePatch} tone="text-red-200" />
              <RiskNumber value={row.exploitAvailable} tone="text-orange-200" />
              <RiskNumber value={row.sourceCount} tone="text-emerald-200" />
            </tr>
          ))}
        </RiskTable>
      </div>
    </section>
  );
}

function ChartCard({ title, subtitle, className = "", children }) {
  return (
    <article className={`rounded-2xl border border-white/10 bg-slate-950/55 p-4 sm:p-5 ${className}`}>
      <h3 className="font-black text-white">{title}</h3>
      <p className="mt-1 text-xs font-semibold leading-5 text-slate-500">{subtitle}</p>
      <div className="mt-4">{children}</div>
    </article>
  );
}

function RiskTable({ title, columns, children }) {
  return (
    <article className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/55">
      <div className="border-b border-white/10 px-5 py-4"><h3 className="font-black text-white">{title}</h3></div>
      <div className="overflow-auto">
        <table className="w-full min-w-[650px] text-left text-xs">
          <thead className="bg-black/25 uppercase tracking-wide text-slate-500"><tr>{columns.map((column) => <th key={column} className="px-3 py-3">{column}</th>)}</tr></thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </article>
  );
}

function RiskName({ value }) {
  return <td className="max-w-[240px] truncate px-3 py-3 font-black text-white" title={value}>{value}</td>;
}

function RiskNumber({ value, tone = "text-white" }) {
  return <td className={`px-3 py-3 font-black ${tone}`}>{Number(value ?? 0).toLocaleString()}</td>;
}

const legendStyle = { color: "#94a3b8", fontSize: 11, fontWeight: 700, paddingTop: 10 };
