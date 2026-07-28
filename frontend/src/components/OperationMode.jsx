import { Activity, BarChart3, CalendarRange, Radar, Zap } from "lucide-react";

const modes = [
  {
    id: "adhoc",
    title: "Ad hoc scan",
    subtitle: "On-demand immediate file process or live scan.",
    icon: Zap,
    accent: "from-red-500 to-rose-700",
  },
  {
    id: "monthly",
    title: "Monthly comparison",
    subtitle: "Multi-month trends, Excel reporting, and selected-month remediation guides.",
    icon: BarChart3,
    accent: "from-red-500 to-rose-700",
  },
  {
    id: "quarterly",
    title: "Quarterly Analysis",
    subtitle: "One current reporting cycle summarized across its latest three months, with a discovery trend and report outputs.",
    icon: CalendarRange,
    accent: "from-red-500 to-rose-700",
  },
  {
    id: "threat-intel",
    title: "Threat Intelligence",
    subtitle: "Build a tenant CVE library and enrich retained scanner evidence through the local Ollama/Gemma service.",
    icon: Radar,
    accent: "from-red-500 to-rose-700",
  },
];

export function OperationMode({ mode, onModeChange, disabled = false, disabledMessage = "" }) {
  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <p className="mini-label">Analysis workflow</p>
          <h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white">Choose an analysis type</h2>
          <p className="mt-1.5 text-sm font-medium text-slate-500">Run an immediate assessment, compare reporting periods, or investigate retained vulnerability evidence.</p>
        </div>
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-white/[0.08] bg-black/20 text-red-300"><Activity className="h-5 w-5" /></div>
      </div>

      {disabled && (
        <div className="mb-5 rounded-2xl border border-amber-300/25 bg-amber-400/[0.06] px-4 py-3 text-sm font-bold text-amber-100">
          {disabledMessage}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
        {modes.map((item) => {
          const Icon = item.icon;
          const active = mode === item.id;

          return (
            <button
              key={item.id}
              type="button"
              disabled={disabled}
              onClick={() => onModeChange(item.id)}
              className={`group relative overflow-hidden rounded-xl border p-5 text-left transition duration-200 ${
                disabled
                  ? "cursor-not-allowed border-white/[0.05] bg-[#0b0b0c] opacity-40"
                  : active
                  ? "border-red-400/45 bg-red-500/[0.055]"
                  : "border-white/[0.075] bg-[#0d0d0f] hover:border-white/[0.14] hover:bg-[#121214]"
              }`}
            >
              <div className={`absolute inset-y-0 left-0 w-0.5 bg-gradient-to-b ${item.accent} ${active ? "opacity-100" : "opacity-0 group-hover:opacity-60"}`} />
              <div className="relative flex items-start gap-4">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-red-400/15 bg-red-500/[0.055] text-red-300">
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-base font-extrabold text-white">{item.title}</p>
                  <p className="mt-1.5 max-w-xl text-xs font-medium leading-5 text-slate-500">{item.subtitle}</p>
                  <p className="mt-4 font-mono text-[0.58rem] font-bold uppercase tracking-[0.14em] text-red-300">
                    {active ? "Active workflow" : "Select workflow"}
                  </p>
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}
