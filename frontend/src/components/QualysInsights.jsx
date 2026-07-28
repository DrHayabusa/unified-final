import { Building2, History, Layers3, ShieldCheck } from "lucide-react";

export function QualysInsights({ insights }) {
  if (!insights) return null;
  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">Qualys operational context</p>
          <h2 className="mt-1 text-xl font-extrabold text-white">Datacentre, lifecycle, and detection history</h2>
          <p className="mt-2 text-xs font-medium leading-5 text-slate-500">Uses only supplied Datacentre, Vuln Status, Times Detected, and exploit-evidence fields.</p>
        </div>
        <span className="status-chip">Qualys evidence</span>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric icon={ShieldCheck} label="Open findings" value={insights.totalOpen} detail="Current Qualys rows" tone="text-red-300" />
        <Metric icon={History} label="Repeated findings" value={insights.repeatedFindings} detail="Times Detected greater than 1" tone="text-amber-200" />
        <Metric icon={Layers3} label="Detection events" value={insights.detectionEvents} detail="Sum of Times Detected" tone="text-sky-300" />
        <Metric icon={Building2} label="Datacentres" value={insights.datacentres.filter((row) => row.datacentre !== "Not supplied").length} detail="Distinct supplied categories" tone="text-emerald-300" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Distribution title="Datacentre distribution" labelKey="datacentre" rows={insights.datacentres} color="#38bdf8" />
        <Distribution title="Vulnerability status" labelKey="status" rows={insights.statuses} color="#f97316" />
        <Distribution title="Vendor rating" labelKey="rating" rows={insights.vendorRatings} color="#ef4444" />
      </div>
    </section>
  );
}

function Metric({ icon: Icon, label, value, detail, tone }) {
  return (
    <article className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
      <div className="flex items-center justify-between"><p className="font-mono text-[0.56rem] font-bold uppercase tracking-[0.12em] text-slate-600">{label}</p><Icon className={`h-4 w-4 ${tone}`} /></div>
      <p className="mt-3 text-2xl font-extrabold text-white">{Number(value || 0).toLocaleString()}</p>
      <p className="mt-1 text-[0.64rem] font-medium text-slate-600">{detail}</p>
    </article>
  );
}

function Distribution({ title, labelKey, rows = [], color }) {
  const maximum = Math.max(1, ...rows.map((row) => Number(row.vulnerabilityCount) || 0));
  return (
    <article className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
      <h3 className="text-sm font-extrabold text-white">{title}</h3>
      <div className="mt-4 space-y-3">
        {rows.slice(0, 8).map((row) => (
          <div key={row[labelKey]}>
            <div className="flex items-center justify-between gap-3 text-xs"><span className="truncate font-bold text-slate-400">{row[labelKey]}</span><span className="font-extrabold text-white">{Number(row.vulnerabilityCount).toLocaleString()}</span></div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full" style={{ width: `${Math.max(2, (Number(row.vulnerabilityCount) / maximum) * 100)}%`, backgroundColor: color }} /></div>
          </div>
        ))}
        {!rows.length && <p className="text-xs font-medium text-slate-600">No source values supplied.</p>}
      </div>
    </article>
  );
}
