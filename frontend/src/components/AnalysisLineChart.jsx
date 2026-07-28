import { CalendarRange } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function AnalysisLineChart({ dashboard }) {
  const quarterly = dashboard?.quarterlyDiscoveryTrend ?? [];
  const configured = dashboard?.adhocLineSeries;
  const points = quarterly.length
    ? quarterly.map((row) => ({ label: row.month, value: row.discoveredCount }))
    : configured?.points ?? [];
  const title = quarterly.length ? "Vulnerabilities discovered in the last 3 months" : configured?.title ?? "Vulnerability line chart";
  const dated = quarterly.length > 0 || configured?.basis === "first-discovered";
  const total = points.reduce((sum, point) => sum + (Number(point.value) || 0), 0);

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">{dated ? "Three-Month Discovery View" : "Current Finding Profile"}</p>
          <h2 className="mt-1 text-xl font-bold text-white">{title}</h2>
          <p className="mt-1 text-sm font-semibold text-slate-500">
            {dated
              ? "Calculated from First Discovered dates supplied in this scan export."
              : "The source has no dated history, so the line shows the current severity distribution without inventing a trend."}
          </p>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-red-400/20 bg-red-500/[0.06] px-4 py-3">
          <CalendarRange className="h-5 w-5 text-red-300" />
          <div><p className="text-2xl font-bold text-white">{total.toLocaleString()}</p><p className="text-xs font-semibold text-slate-500">{dated ? "discovered in period" : "open findings shown"}</p></div>
        </div>
      </div>

      <div className="h-[310px] rounded-2xl border border-white/10 bg-black/25 p-4" role="img" aria-label={`${title}: ${points.map((point) => `${point.label}, ${point.value}`).join("; ")}`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 20, right: 30, bottom: 10, left: 0 }}>
            <CartesianGrid stroke="#27272a" strokeDasharray="4 5" vertical={false} />
            <XAxis dataKey="label" stroke="#71717a" tick={{ fontSize: 12, fontWeight: 600 }} />
            <YAxis allowDecimals={false} stroke="#71717a" tick={{ fontSize: 12 }} />
            <Tooltip contentStyle={{ background: "#0a0a0b", border: "1px solid #3f3f46", borderRadius: 10 }} formatter={(value) => [value, dated ? "Discovered" : "Open findings"]} />
            <Line type="monotone" dataKey="value" name={dated ? "Discovered" : "Open findings"} stroke="#ef4444" strokeWidth={4} dot={{ r: 6, fill: "#0a0a0b", stroke: "#fb7185", strokeWidth: 3 }} activeDot={{ r: 7 }} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
