import { Crosshair, Eye, ShieldCheck, Signal } from "lucide-react";

export function CrowdStrikeInsights({ insights }) {
  if (!insights) return null;

  const exposureValue = insights.internetExposureObserved ? insights.internetExposed : "Not supplied";
  const exposureHelper = insights.internetExposureObserved
    ? `${insights.internetExposureObserved.toLocaleString()} assessed | ${insights.internetExposureUnknown.toLocaleString()} unknown`
    : "No authoritative exposure field in the export";

  return (
    <section className="mt-5 rounded-2xl border border-red-300/15 bg-red-400/[0.035] p-5">
      <div className="mb-4">
        <p className="mini-label text-red-300">CrowdStrike evidence</p>
        <h3 className="mt-1 text-xl font-black text-white">Exploit, confidence, and exposure context</h3>
        <p className="mt-2 max-w-3xl text-xs font-semibold leading-5 text-slate-500">
          Exploit status follows the explicit CrowdStrike label first, then the status value and ExPRT rating. Vulnerability Confidence is retained as a separate finding-quality signal.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric icon={Crosshair} label="Exploit available" value={insights.exploitAvailable} helper="Positive scanner exploit evidence" color="#fb923c" />
        <Metric icon={Eye} label="Confirmed internet exposed" value={exposureValue} helper={exposureHelper} color="#22d3ee" />
        <Metric icon={ShieldCheck} label="Confirmed findings" value={insights.confirmedFindings} helper="Vulnerability Confidence = Confirmed" color="#34d399" />
        <Metric icon={Signal} label="Potential findings" value={insights.potentialFindings} helper="Vulnerability Confidence = Potential" color="#fbbf24" />
      </div>

      {(insights.confidenceDistribution.length > 0 || insights.exploitEvidenceSources.length > 0) && (
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          <Distribution title="Vulnerability confidence" rows={insights.confidenceDistribution} labelKey="confidence" color="#34d399" />
          <Distribution title="Exploit evidence source" rows={insights.exploitEvidenceSources} labelKey="source" color="#fb923c" />
        </div>
      )}
    </section>
  );
}

function Metric({ icon: Icon, label, value, helper, color }) {
  return (
    <article className="rounded-2xl border border-white/10 bg-slate-900/70 p-4">
      <Icon className="h-5 w-5" style={{ color }} />
      <p className="mt-3 font-mono text-[0.62rem] font-bold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-black tracking-[-0.04em]" style={{ color }}>{typeof value === "number" ? value.toLocaleString() : value}</p>
      <p className="mt-1 text-xs font-semibold leading-5 text-slate-500">{helper}</p>
    </article>
  );
}

function Distribution({ title, rows, labelKey, color }) {
  const maximum = Math.max(1, ...rows.map((row) => row.vulnerabilityCount));
  return (
    <article className="rounded-2xl border border-white/10 bg-slate-950/55 p-4">
      <h4 className="font-black text-white">{title}</h4>
      <div className="mt-4 space-y-3">
        {rows.map((row) => (
          <div key={row[labelKey]}>
            <div className="flex items-center justify-between gap-3 text-xs">
              <span className="truncate font-bold text-slate-400">{row[labelKey]}</span>
              <span className="font-black text-white">{row.vulnerabilityCount.toLocaleString()}</span>
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full" style={{ width: `${(row.vulnerabilityCount / maximum) * 100}%`, backgroundColor: color }} />
            </div>
          </div>
        ))}
      </div>
    </article>
  );
}
