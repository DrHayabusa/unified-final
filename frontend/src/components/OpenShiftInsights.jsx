import { Boxes, Container, Layers3, PackageCheck, PackageX, Waypoints } from "lucide-react";

export function OpenShiftInsights({ insights }) {
  if (!insights) return null;

  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">OpenShift workload context</p>
          <h2 className="mt-1 text-xl font-extrabold text-white">Container fix coverage and workload concentration</h2>
          <p className="mt-2 max-w-4xl text-xs font-medium leading-5 text-slate-500">
            Only supplied OpenShift fields are displayed. Because this export has no exploitability field, patch priority follows source severity: Critical P1, High P2, Medium P3, and Low P4.
          </p>
        </div>
        <span className="status-chip">11 supplied fields mapped</span>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <Metric icon={PackageCheck} label="Fix available" value={insights.fixable} detail="Fixable or fixed version supplied" tone="text-emerald-300" />
        <Metric icon={PackageX} label="No fixed version" value={insights.noFixedVersion} detail="Requires vendor review or mitigation" tone="text-amber-300" />
        <Metric icon={Waypoints} label="Namespaces" value={insights.namespaceCount} detail="Distinct affected namespaces" tone="text-sky-300" />
        <Metric icon={Layers3} label="Deployments" value={insights.deploymentCount} detail="Distinct affected deployments" tone="text-red-300" />
        <Metric icon={Container} label="Images" value={insights.imageCount} detail="Distinct affected images" tone="text-cyan-300" />
        <Metric icon={Boxes} label="Components" value={insights.componentCount} detail="Distinct affected packages" tone="text-violet-300" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Distribution title="Namespace concentration" labelKey="namespace" rows={insights.namespaces} color="#38bdf8" />
        <Distribution title="Affected components" labelKey="component" rows={insights.components} color="#f87171" />
        <Distribution title="Affected images" labelKey="image" rows={insights.images} color="#22d3ee" />
      </div>
    </section>
  );
}

function Metric({ icon: Icon, label, value, detail, tone }) {
  return (
    <article className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[0.56rem] font-bold uppercase tracking-[0.12em] text-slate-600">{label}</p>
        <Icon className={`h-4 w-4 ${tone}`} />
      </div>
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
            <div className="flex items-center justify-between gap-3 text-xs">
              <span className="truncate font-bold text-slate-400" title={row[labelKey]}>{row[labelKey]}</span>
              <span className="font-extrabold text-white">{Number(row.vulnerabilityCount).toLocaleString()}</span>
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
              <div className="h-full rounded-full" style={{ width: `${Math.max(2, (Number(row.vulnerabilityCount) / maximum) * 100)}%`, backgroundColor: color }} />
            </div>
          </div>
        ))}
        {!rows.length && <p className="text-xs font-medium text-slate-600">No source values supplied.</p>}
      </div>
    </article>
  );
}
