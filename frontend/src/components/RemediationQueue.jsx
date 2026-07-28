import { useDeferredValue, useState } from "react";
import { Search } from "lucide-react";

const severityClass = {
  Critical: "bg-red-500 text-white",
  High: "bg-orange-500 text-white",
  Medium: "bg-yellow-400 text-slate-950",
  Low: "bg-emerald-500 text-slate-950",
  Info: "bg-sky-500 text-white",
  Unknown: "bg-slate-600 text-white",
};

const priorityClass = {
  P1: "bg-red-500 text-white",
  P2: "bg-orange-500 text-white",
  P3: "bg-yellow-400 text-slate-950",
  P4: "bg-emerald-500 text-slate-950",
};

export function RemediationQueue({ findings = [] }) {
  const [search, setSearch] = useState("");
  const [priority, setPriority] = useState("All");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const showSources = new Set(findings.flatMap((finding) => finding.sourceTools ?? [finding.sourceTool]).filter(Boolean)).size > 1;
  const filtered = findings
    .filter((finding) => priority === "All" || finding.patchPriority === priority)
    .filter((finding) => {
      if (!deferredSearch) return true;
      return [finding.ipAddress, finding.dnsName, finding.vulnerabilityName, finding.cve, finding.product, finding.sourceDisplay]
        .join(" ")
        .toLowerCase()
        .includes(deferredSearch);
    })
    .sort((left, right) => priorityRank(left.patchPriority) - priorityRank(right.patchPriority) || right.assetExposure - left.assetExposure);
  const visible = filtered.slice(0, 100);
  const weightedTotal = findings.reduce((sum, finding) => sum + (finding.recordCount ?? 1), 0);

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mini-label">Remediation Queue</p>
          <h2 className="mt-1 text-2xl font-black text-white">
            Prioritized findings <span className="text-base text-emerald-300">{weightedTotal.toLocaleString()} open</span>
          </h2>
        </div>
        <div className="flex flex-wrap gap-3">
          <select
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
            className="rounded-xl border border-white/10 bg-slate-950/70 px-3 py-2 text-sm font-bold text-slate-300 outline-none"
          >
            {["All", "P1", "P2", "P3", "P4"].map((option) => <option key={option}>{option}</option>)}
          </select>
          <label className="flex items-center gap-2 rounded-xl border border-white/10 bg-slate-950/70 px-3 py-2">
            <Search className="h-4 w-4 text-slate-500" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search asset, CVE, product..."
              className="w-56 bg-transparent text-sm font-bold text-slate-200 outline-none placeholder:text-slate-600"
            />
          </label>
        </div>
      </div>

      <div className="overflow-auto rounded-2xl border border-white/10">
        <table className={`w-full border-collapse text-left text-sm ${showSources ? "min-w-[1280px]" : "min-w-[1080px]"}`}>
          <thead className="sticky top-0 z-10 bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              {["IP Address", "DNS Name", ...(showSources ? ["Source Tools"] : []), "Vulnerability Name", "CVE", "Severity", "Exploit", "Priority", "Exposure", "Count"].map((heading) => (
                <th key={heading} className="px-4 py-4 font-black">{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={row.findingKey} className="border-t border-white/10 bg-slate-950/35 text-slate-300 hover:bg-cyan-400/5">
                <td className="px-4 py-4 font-bold">{row.ipAddress || "-"}</td>
                <td className="px-4 py-4 font-bold">{row.dnsName || "-"}</td>
                {showSources && <td className="max-w-56 px-4 py-4 text-xs font-black text-cyan-200">{row.sourceDisplay || row.sourceTool}</td>}
                <td className="max-w-md px-4 py-4 font-bold text-slate-100">{row.vulnerabilityName}</td>
                <td className="px-4 py-4 font-mono text-xs font-bold">{row.cve || "N/A"}</td>
                <td className="px-4 py-4"><span className={`rounded-full px-3 py-1 text-xs font-black ${severityClass[row.severity] ?? severityClass.Unknown}`}>{row.severity}</span></td>
                <td className="px-4 py-4 font-black text-slate-200">{row.exploitAvailable ? "Available" : "No"}</td>
                <td className="px-4 py-4"><span className={`rounded-full px-3 py-1 text-xs font-black ${priorityClass[row.patchPriority]}`}>{row.patchPriority}</span></td>
                <td className="px-4 py-4 font-black text-white">{row.assetExposure}</td>
                <td className="px-4 py-4 font-black text-white">{row.recordCount ?? 1}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs font-semibold text-slate-500">
        Showing {visible.length.toLocaleString()} of {filtered.length.toLocaleString()} normalized rows. Excel and CSV exports contain the complete analyzed dataset.
      </p>
    </section>
  );
}

function priorityRank(priority) {
  return { P1: 1, P2: 2, P3: 3, P4: 4 }[priority] ?? 9;
}
