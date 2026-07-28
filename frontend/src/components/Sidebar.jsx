import { BarChart3, Bot, Boxes, CalendarRange, Database, LayoutDashboard, LogOut, Radar, ScanSearch, Settings2, UploadCloud, Zap } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { HelpAgLogo } from "./Branding.jsx";
import { MvaLogo } from "./ToolIcons.jsx";

const groups = [
  {
    label: "Platform",
    items: [
      { id: "portfolio", label: "Dashboards", icon: LayoutDashboard },
      { id: "scanner", label: "Tool selection", icon: UploadCloud },
    ],
  },
  {
    label: "Analysis",
    items: [
      { id: "adhoc", label: "Ad hoc analysis", icon: Zap },
      { id: "monthly", label: "Monthly comparison", icon: BarChart3 },
      { id: "quarterly", label: "Quarterly analysis", icon: CalendarRange },
      { id: "discovery", label: "Discovery coverage", icon: ScanSearch },
    ],
  },
  {
    label: "Delivery",
    items: [
      { id: "threat-intel", label: "Threat intelligence", icon: Radar },
      { id: "llm-config", label: "LLM configuration", icon: Bot },
    ],
  },
];

export function Sidebar({ activePage = "portfolio", onNavigate }) {
  const platform = usePlatform();
  const customerRole = platform.selectedCustomer?.membershipRole;
  const canManageAssets = platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(customerRole);
  const controlItems = [
    ...(canManageAssets ? [{ id: "assets", label: "Asset inventory", icon: Database }] : []),
    ...(platform.user?.globalRole === "system_admin" ? [{ id: "admin", label: "Administration", icon: Settings2 }] : []),
  ];
  const navigation = [...groups, ...(controlItems.length ? [{ label: "Control", items: controlItems }] : [])];
  const mobileItems = navigation.flatMap((group) => group.items);

  return (
    <>
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-white/[0.07] bg-[#080809]/98 px-4 py-5 shadow-[12px_0_40px_rgba(0,0,0,.18)] backdrop-blur-2xl lg:flex">
        <div className="flex items-center gap-3 px-2 pb-5">
          <MvaLogo className="h-11 w-11" />
          <div><p className="text-lg font-extrabold tracking-tight text-white">MVA</p><p className="max-w-32 font-mono text-[0.5rem] font-semibold uppercase leading-3 tracking-[0.12em] text-slate-600">Unified Vulnerability<br />Management Platform</p></div>
        </div>

        <label className="block rounded-xl border border-white/[0.08] bg-white/[0.025] p-3">
          <span className="font-mono text-[0.56rem] font-semibold uppercase tracking-[0.14em] text-slate-600">Active tenant</span>
          <select value={platform.selectedCustomerId} onChange={(event) => platform.setSelectedCustomerId(event.target.value)} className="mt-2 w-full truncate bg-transparent text-xs font-extrabold text-white outline-none">
            {!platform.customers.length && <option value="">No tenant</option>}
            {platform.customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}
          </select>
          {platform.selectedCustomer && <p className="mt-2 flex items-center gap-2 text-[0.62rem] font-semibold capitalize text-slate-600"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />{platform.user?.globalRole === "system_admin" ? "System administrator" : `${customerRole || "viewer"} access`}</p>}
        </label>

        <nav className="mt-5 min-h-0 flex-1 space-y-5 overflow-y-auto pr-1">
          {navigation.map((group) => (
            <div key={group.label}>
              <p className="px-3 font-mono text-[0.54rem] font-semibold uppercase tracking-[0.17em] text-slate-700">{group.label}</p>
              <div className="mt-2 space-y-1">
                {group.items.map(({ id, label, icon: Icon }) => {
                  const isActive = id === activePage;
                  return (
                    <button key={id} type="button" onClick={() => onNavigate?.(id)} className={`group flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left text-xs font-bold transition ${isActive ? "border-red-400/25 bg-red-500/[0.09] text-white" : "border-transparent text-slate-500 hover:border-white/[0.07] hover:bg-white/[0.03] hover:text-slate-200"}`}>
                      <Icon className={`h-4 w-4 ${isActive ? "text-red-300" : "text-slate-600 group-hover:text-slate-400"}`} />{label}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="mt-4 border-t border-white/[0.07] pt-4">
          <div className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-red-500/[0.09] text-[0.65rem] font-extrabold text-red-200">{initials(platform.user?.fullName)}</div>
            <div className="min-w-0 flex-1"><p className="truncate text-xs font-extrabold text-white">{platform.user?.fullName}</p><p className="mt-0.5 truncate text-[0.6rem] font-semibold text-slate-600">{platform.user?.email}</p></div>
            <button type="button" onClick={platform.logout} aria-label="Sign out" className="rounded-lg p-2 text-slate-600 transition hover:bg-red-500/[0.08] hover:text-red-300"><LogOut className="h-4 w-4" /></button>
          </div>
          <div className="mt-3 flex items-center justify-between gap-3 px-2">
            <div className="flex items-center gap-2 font-mono text-[0.54rem] font-semibold uppercase tracking-wider text-slate-700"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /><Boxes className="h-3 w-3" />Operational</div>
            <HelpAgLogo className="w-20" />
          </div>
        </div>
      </aside>

      <nav aria-label="Mobile navigation" className="fixed inset-x-3 bottom-3 z-50 flex gap-1 overflow-x-auto rounded-2xl border border-white/10 bg-black/92 p-2 shadow-2xl backdrop-blur-2xl lg:hidden">
        {mobileItems.map(({ id, label, icon: Icon }) => {
          const isActive = id === activePage;
          return <button key={id} type="button" aria-label={label} onClick={() => onNavigate?.(id)} className={`flex min-w-[4.3rem] flex-1 flex-col items-center gap-1 rounded-xl px-2 py-2 text-[0.56rem] font-extrabold ${isActive ? "bg-red-600 text-white" : "text-slate-500"}`}><Icon className="h-4 w-4" /><span className="max-w-[4.5rem] truncate">{label}</span></button>;
        })}
      </nav>
    </>
  );
}

function initials(name = "MVA") {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}
