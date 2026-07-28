import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Globe2, Server } from "lucide-react";

export function TrendPanel({ dashboard }) {
  const assets = (dashboard?.top10AffectedAssets ?? []).map((row) => ({
    asset: shorten(row.asset),
    fullAsset: row.asset,
    count: row.vulnerabilityCount,
  }));
  const showCrowdStrikeSignals = (dashboard?.internetExposureObserved ?? 0) > 0;

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="mini-label">Asset Concentration</p>
          <h2 className="mt-1 text-xl font-black text-white">Top 10 affected assets</h2>
        </div>
        <span className="rounded-full border border-red-300/20 bg-red-400/10 px-3 py-2 text-xs font-black text-red-100">
          {dashboard?.distinctAssets ?? 0} assets in scope
        </span>
      </div>

      <div className="h-[340px] rounded-2xl border border-white/10 bg-slate-950/45 p-3">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={assets} layout="vertical" margin={{ top: 8, right: 22, bottom: 8, left: 32 }}>
            <CartesianGrid stroke="#27272a" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" allowDecimals={false} stroke="#64748b" tick={{ fontSize: 11 }} />
            <YAxis type="category" dataKey="asset" width={145} stroke="#64748b" tick={{ fontSize: 11 }} />
            <Tooltip
              cursor={{ fill: "rgba(63, 63, 70, 0.35)" }}
              contentStyle={{ background: "#09090b", border: "1px solid #3f3f46", borderRadius: 12 }}
              formatter={(value) => [value, "Open findings"]}
              labelFormatter={(_, payload) => payload?.[0]?.payload?.fullAsset ?? "Asset"}
            />
            <Bar dataKey="count" fill="#dc2626" radius={[0, 7, 7, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {showCrowdStrikeSignals && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Signal icon={Globe2} label="Confirmed Internet Exposed" value={dashboard.internetExposed} tone="text-cyan-300" />
          <Signal icon={Server} label="Exploit Available" value={dashboard.exploitAvailable} tone="text-orange-300" />
        </div>
      )}
    </section>
  );
}

function Signal({ icon: Icon, label, value, tone }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/55 p-4">
      <Icon className={`h-5 w-5 ${tone}`} />
      <p className="mt-3 text-2xl font-black text-white">{Number(value ?? 0).toLocaleString()}</p>
      <p className="mt-1 text-xs font-bold uppercase tracking-wide text-slate-500">{label}</p>
    </div>
  );
}

function shorten(value) {
  if (!value) return "Unknown";
  return value.length > 23 ? `${value.slice(0, 20)}...` : value;
}
