import { Line, LineChart, ResponsiveContainer } from "recharts";
import { ShieldAlert } from "lucide-react";

const colors = {
  "Total Open": "#14b8a6",
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#facc15",
  Low: "#22c55e",
  "Immediate Patch Needed": "#22d3ee",
};

export function MetricsRow({ dashboard }) {
  const total = dashboard?.totalVulnerabilities ?? 0;
  const counts = dashboard?.severityCounts ?? {};
  const immediate = (dashboard?.patchPriorityCounts?.P1 ?? 0) + (dashboard?.patchPriorityCounts?.P2 ?? 0);
  const metricCards = [
    ["Total Open", total, `${dashboard?.distinctAssets ?? 0} affected assets`],
    ["Critical", counts.Critical ?? 0, share(counts.Critical, total)],
    ["High", counts.High ?? 0, share(counts.High, total)],
    ["Medium", counts.Medium ?? 0, share(counts.Medium, total)],
    ["Low", counts.Low ?? 0, share(counts.Low, total)],
    ["Immediate Patch Needed", immediate, "P1 + P2"],
  ].map(([label, value, helper]) => ({ label, value, helper, color: colors[label], data: microSeries(value) }));

  return (
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      {metricCards.map((metric) => {
        const chartData = metric.data.map((value, index) => ({ index, value }));

        return (
          <article key={metric.label} className="cyber-card cyber-card-hover relative min-h-52 overflow-hidden p-5">
            <div className="absolute -right-10 -top-10 h-28 w-28 rounded-full opacity-15 blur-xl" style={{ backgroundColor: metric.color }} />
            <div className="relative flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-black uppercase tracking-wide text-slate-400">{metric.label}</p>
                <p className="mt-3 text-5xl font-black tracking-[-0.08em] text-white">{metric.value}</p>
                <p className="mt-1 text-sm font-bold" style={{ color: metric.color }}>
                  {metric.helper}
                </p>
              </div>
              <div className="grid h-12 w-12 place-items-center rounded-2xl border border-white/10 bg-white/5">
                <ShieldAlert className="h-6 w-6" style={{ color: metric.color }} />
              </div>
            </div>

            <div className="relative z-10 mt-5 h-14 rounded-xl bg-slate-950/35 px-1 py-1">
              <ResponsiveContainer width="100%" height={48}>
                <LineChart data={chartData} margin={{ top: 8, right: 4, bottom: 4, left: 4 }}>
                  <Line
                    dataKey="value"
                    type="monotone"
                    stroke={metric.color}
                    strokeWidth={3}
                    isAnimationActive={false}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </article>
        );
      })}
    </section>
  );
}

function share(value = 0, total = 0) {
  return total ? `${((value / total) * 100).toFixed(1)}% of total` : "0% of total";
}

function microSeries(value) {
  const factors = [0.72, 0.78, 0.75, 0.84, 0.82, 0.9, 0.86, 0.94, 0.91, 0.97, 0.95, 1];
  return factors.map((factor) => Math.max(0, Math.round(Number(value || 0) * factor)));
}
