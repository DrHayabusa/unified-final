import { Building2, CalendarDays, ShieldCheck } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { HelpAgLogo } from "./Branding.jsx";
import { MvaLogo } from "./ToolIcons.jsx";

export function HeroHeader() {
  const platform = usePlatform();
  const currentDate = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(new Date());

  return (
    <header className="relative overflow-hidden rounded-2xl border border-white/[0.075] bg-[linear-gradient(105deg,#141416,#101012)] px-4 py-3.5 shadow-[0_10px_28px_rgba(0,0,0,0.2)] sm:px-5">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-red-500/70 via-red-400/20 to-transparent" />
      <div className="relative flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <MvaLogo className="h-10 w-10 shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <h1 className="truncate text-base font-extrabold tracking-[-0.025em] text-white sm:text-lg">MVA Vulnerability Agent</h1>
              <span className="hidden h-1.5 w-1.5 rounded-full bg-red-500 sm:block" />
            </div>
            <p className="mt-0.5 truncate font-mono text-[0.53rem] font-bold uppercase tracking-[0.13em] text-slate-600">Unified Vulnerability Management Platform</p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <span className="hidden h-9 items-center border-r border-white/[0.08] pr-3 2xl:flex">
            <HelpAgLogo className="w-28" />
          </span>
          <span className="hidden h-9 items-center gap-2 rounded-xl border border-white/[0.075] bg-black/20 px-3 text-[0.67rem] font-bold text-slate-400 md:flex">
            <Building2 className="h-3.5 w-3.5 text-red-300" />
            <span className="max-w-32 truncate">{platform.selectedCustomer?.name || "No workspace"}</span>
          </span>
          <span className="hidden h-9 items-center gap-2 rounded-xl border border-white/[0.075] bg-black/20 px-3 font-mono text-[0.58rem] font-bold uppercase tracking-wider text-slate-500 xl:flex">
            <CalendarDays className="h-3.5 w-3.5" />{currentDate}
          </span>
          <span className="flex h-9 items-center gap-2 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.05] px-3 text-[0.67rem] font-bold text-emerald-300">
            <ShieldCheck className="h-3.5 w-3.5" /> Operational
          </span>
        </div>
      </div>
    </header>
  );
}
