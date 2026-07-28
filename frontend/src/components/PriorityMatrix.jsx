const rows = [
  ["Critical", "P1", "P2", "text-red-400"],
  ["High", "P1", "P2", "text-orange-400"],
  ["Medium", "P2", "P3", "text-yellow-300"],
  ["Low", "P2", "P4", "text-emerald-400"],
];

const priorityTone = {
  P1: "border-red-400/30 bg-red-500/15 text-red-200",
  P2: "border-orange-400/30 bg-orange-500/15 text-orange-200",
  P3: "border-yellow-400/30 bg-yellow-500/15 text-yellow-100",
  P4: "border-emerald-400/30 bg-emerald-500/15 text-emerald-200",
};

export function PriorityMatrix({ compact = false }) {
  return (
    <section aria-label="Patch priority calculation matrix" className={`cyber-panel rounded-[1.75rem] ${compact ? "p-4" : "p-5"}`}>
      <p className="mini-label">Priority Matrix</p>
      <h2 className={`mt-1 font-black text-white ${compact ? "text-lg" : "text-xl"}`}>Exploit Available vs Severity</h2>
      {compact && <p className="mt-2 text-xs font-semibold leading-5 text-slate-500">SC <span className="text-slate-300">Exploit?</span>, IO <span className="text-slate-300">Exploit Ease</span>, or the selected scanner&apos;s equivalent signal.</p>}

      <div className={`${compact ? "mt-4" : "mt-5"} overflow-hidden rounded-2xl border border-white/10`}>
        <div className="grid grid-cols-[0.9fr_1fr_1fr] bg-black/40 text-center text-[0.62rem] font-black uppercase tracking-[0.1em] text-slate-400">
          <div className={compact ? "p-2.5" : "p-3"}>Severity</div>
          <div className={`border-l border-white/10 ${compact ? "p-2.5" : "p-3"}`}>Exploit Available: Yes</div>
          <div className={`border-l border-white/10 ${compact ? "p-2.5" : "p-3"}`}>Exploit Available: No</div>
        </div>
        {rows.map(([severity, yes, no, tone]) => (
          <div key={severity} className="grid grid-cols-[0.9fr_1fr_1fr] border-t border-white/10 text-center font-black">
            <div className={`grid place-items-center bg-white/[0.025] uppercase ${compact ? "p-2.5 text-xs" : "p-3"} ${tone}`}>{severity}</div>
            <div className={`grid place-items-center border-l border-white/10 ${compact ? "p-2" : "p-3"}`}><PriorityBadge priority={yes} compact={compact} /></div>
            <div className={`grid place-items-center border-l border-white/10 ${compact ? "p-2" : "p-3"}`}><PriorityBadge priority={no} compact={compact} /></div>
          </div>
        ))}
      </div>

      <div className={`mt-4 grid grid-cols-4 ${compact ? "gap-1.5" : "gap-2"}`}>
        {[
          ["P1", "Immediate"],
          ["P2", "Priority"],
          ["P3", "Planned"],
          ["P4", "Deferred"],
        ].map(([priority, label]) => (
          <div key={priority} className={`rounded-xl border border-white/10 bg-white/[0.025] text-center ${compact ? "p-2" : "p-3"}`}>
            <PriorityBadge priority={priority} compact />
            <p className={`font-bold text-slate-500 ${compact ? "mt-1.5 text-[0.58rem]" : "mt-2 text-xs"}`}>{label}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function PriorityBadge({ priority, compact = false }) {
  return <span className={`inline-flex items-center justify-center rounded-lg border font-mono font-black ${priorityTone[priority]} ${compact ? "min-w-10 px-2 py-1 text-xs" : "min-w-14 px-3 py-1.5 text-base"}`}>{priority}</span>;
}
