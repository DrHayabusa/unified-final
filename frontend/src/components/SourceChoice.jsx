import { CheckCircle2, Layers3, ScanLine } from "lucide-react";
import { SourceToolIcon } from "./ToolIcons.jsx";
import { sourceTools } from "../data/dashboardData.jsx";

export function SourceChoice({ selectionMode = "single", selectedSourceIds = [], onModeChange, onToggle, onSelectAll, onClear }) {
  const unified = selectionMode === "multi";
  const selectionReady = !unified || selectedSourceIds.length >= 2;
  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-5">
        <div>
          <p className="mini-label">Analysis setup</p>
          <h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white">Tool selection</h2>
          <p className="mt-1.5 text-sm font-medium text-slate-500">Choose one vulnerability platform or consolidate multiple scanner exports.</p>
        </div>
        <div className="inline-flex rounded-xl border border-white/[0.08] bg-black/25 p-1">
          <ModeButton active={!unified} icon={ScanLine} label="Single Tool" onClick={() => onModeChange?.("single")} />
          <ModeButton active={unified} icon={Layers3} label="Unified Multi-Tool" onClick={() => onModeChange?.("multi")} />
        </div>
      </div>

      <div className={`mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 ${unified ? "border-red-400/20 bg-red-500/[0.045]" : "border-white/[0.07] bg-black/20"}`}>
        <div>
          <p className="text-sm font-extrabold text-slate-200">{unified ? "Multi-tool consolidation" : "Single-tool analysis"}</p>
          <p className="mt-1 text-xs font-medium text-slate-500">
            {unified
              ? "Select two or more tools. Files are detected independently, normalized, and deduplicated with source provenance retained."
              : "Select one tool for its established ad hoc, monthly, or quarterly workflow."}
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <span className={`rounded-full border bg-black/25 px-3 py-2 text-xs font-black ${selectionReady ? "border-red-300/20 text-red-100" : "border-amber-300/30 text-amber-200"}`}>
            {unified ? `${selectedSourceIds.length} selected${selectionReady ? "" : " · choose at least 2"}` : "Auto field mapping"}
          </span>
          {unified && (
            <>
              <button type="button" onClick={onSelectAll} className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-black text-slate-200 transition hover:border-red-300/30 hover:text-white">
                Select all
              </button>
              <button type="button" onClick={onClear} disabled={selectedSourceIds.length === 0} className="rounded-xl border border-white/10 bg-black/25 px-3 py-2 text-xs font-black text-slate-400 transition hover:text-white disabled:cursor-not-allowed disabled:opacity-35">
                Clear
              </button>
            </>
          )}
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {sourceTools.map((tool) => {
          const isSelected = selectedSourceIds.includes(tool.id);

          return (
            <button
              key={tool.id}
              type="button"
              disabled={!tool.implemented}
              aria-pressed={isSelected}
              onClick={() => onToggle?.(tool.id)}
              className={`group relative min-h-40 overflow-hidden rounded-xl border p-4 text-left transition duration-200 ${
                isSelected
                  ? "border-red-400/45 bg-red-500/[0.055] shadow-[inset_0_1px_0_rgba(255,255,255,.035)]"
                  : tool.implemented
                    ? "border-white/[0.075] bg-[#0d0d0f] hover:border-white/[0.14] hover:bg-[#121214]"
                    : "cursor-not-allowed border-white/[0.05] bg-[#0b0b0c] opacity-40"
              }`}
            >
              <span className={`absolute inset-x-0 top-0 h-px ${isSelected ? "bg-red-400/80" : "bg-transparent"}`} />
              {isSelected && <CheckCircle2 className="absolute right-3.5 top-3.5 h-4 w-4 text-red-300" />}
              {!tool.implemented && <span className="absolute right-3 top-3 rounded-full border border-white/10 bg-slate-900 px-2 py-1 text-[0.6rem] font-black uppercase tracking-wide text-slate-400">Next</span>}
              <div className="mb-3 flex justify-center">
                <SourceToolIcon id={tool.id} accent={tool.accent} />
              </div>
              <p className="text-center text-base font-extrabold text-white">{tool.name}</p>
              <p className="mt-1 text-center text-[0.7rem] font-medium text-slate-600">{tool.description}</p>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function ModeButton({ active, icon: Icon, label, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-2 rounded-lg px-4 py-2.5 text-xs font-extrabold transition ${active ? "bg-red-600 text-white shadow-[0_6px_18px_rgba(220,38,38,.16)]" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200"}`}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}
