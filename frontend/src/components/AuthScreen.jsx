import { useState } from "react";
import { ArrowRight, Database, KeyRound, LockKeyhole, ShieldCheck, Users } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { HelpAgLogo } from "./Branding.jsx";
import { MvaLogo } from "./ToolIcons.jsx";

export function AuthScreen() {
  const platform = usePlatform();
  const isSetup = platform.status === "setup";
  const [form, setForm] = useState({ fullName: "", email: "", password: "", confirmPassword: "" });
  const [submitState, setSubmitState] = useState({ busy: false, error: "" });

  const update = (field) => (event) => setForm((current) => ({ ...current, [field]: event.target.value }));

  const submit = async (event) => {
    event.preventDefault();
    if (isSetup && form.password !== form.confirmPassword) {
      setSubmitState({ busy: false, error: "Passwords do not match." });
      return;
    }
    setSubmitState({ busy: true, error: "" });
    try {
      const payload = { email: form.email, password: form.password };
      if (isSetup) payload.fullName = form.fullName;
      await (isSetup ? platform.bootstrap(payload) : platform.login(payload));
    } catch (error) {
      setSubmitState({ busy: false, error: error.message });
    }
  };

  if (platform.status === "loading") return <LoadingGate />;

  return (
    <main className="relative grid min-h-screen overflow-hidden bg-[#050506] lg:grid-cols-[1.08fr_.92fr]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,rgba(220,38,38,.20),transparent_26rem),radial-gradient(circle_at_76%_72%,rgba(127,29,29,.13),transparent_30rem)]" />
      <section className="relative hidden min-h-screen overflow-hidden border-r border-white/10 p-12 lg:flex lg:flex-col lg:justify-between xl:p-16">
        <div className="absolute inset-0 bg-cyber-grid bg-[length:64px_64px] opacity-30" />
        <div className="absolute -left-36 top-1/3 h-96 w-96 rotate-45 border border-red-500/20" />
        <div className="relative flex items-center gap-4">
          <MvaLogo className="h-16 w-16 shrink-0" />
          <div>
            <p className="font-mono text-xs font-bold uppercase tracking-[0.2em] text-red-300">MVA Enterprise Platform</p>
            <p className="mt-1 text-sm font-semibold text-slate-400">Unified Vulnerability Management Platform</p>
          </div>
          <span className="mx-2 h-10 w-px bg-white/10" />
          <HelpAgLogo className="w-36" />
        </div>

        <div className="relative max-w-3xl">
          <p className="font-mono text-xs font-bold uppercase tracking-[0.24em] text-red-300">Vulnerability Management Platform</p>
          <h1 className="mt-5 text-5xl font-bold leading-[1.02] tracking-[-0.05em] text-white xl:text-7xl">
            MVA Unified<br />Vulnerability<br />Management
          </h1>
          <p className="mt-7 max-w-2xl text-lg font-medium leading-8 text-slate-400">
            Run ad hoc, monthly, quarterly, discovery coverage, and multi-scanner analysis with governed tenant dashboards and remediation reporting.
          </p>
        </div>

        <div className="relative grid gap-3 xl:grid-cols-3">
          <Capability icon={ShieldCheck} title="Scanner intelligence" detail="Ad hoc, monthly, and quarterly analysis" />
          <Capability icon={Users} title="Tenant dashboards" detail="Isolated asset-scoped operations" />
          <Capability icon={Database} title="Reporting and remediation" detail="Excel, PDF, and persistent evidence" />
        </div>
      </section>

      <section className="relative flex min-h-screen items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-lg">
          <div className="mb-9 flex items-center gap-3 lg:hidden">
            <MvaLogo className="h-14 w-14" />
            <div>
              <p className="text-2xl font-black text-white">MVA</p>
              <p className="text-xs font-bold text-slate-500">Unified Vulnerability Management Platform</p>
            </div>
            <HelpAgLogo className="ml-auto w-24" />
          </div>

          <div className="rounded-[2rem] border border-white/10 bg-[#0b0b0d]/90 p-6 shadow-[0_32px_120px_rgba(0,0,0,.72)] backdrop-blur-2xl sm:p-9">
            <div className="mb-8 flex h-12 w-12 items-center justify-center rounded-2xl border border-red-400/25 bg-red-500/10 text-red-300">
              {isSetup ? <ShieldCheck className="h-6 w-6" /> : <LockKeyhole className="h-6 w-6" />}
            </div>
            <p className="mini-label">{isSetup ? "First-run setup" : "Secure workspace"}</p>
            <h2 className="mt-2 text-3xl font-black tracking-tight text-white">
              {isSetup ? "Create the platform administrator" : "Sign in to MVA"}
            </h2>
            <p className="mt-3 text-sm font-semibold leading-6 text-slate-400">
              {isSetup
                ? "This one-time account can create tenants, assign users, and control asset scope. Public registration closes automatically afterward."
                : "Use the account issued by your MVA administrator. Tenant access is enforced by the API, not the browser."}
            </p>

            {platform.status === "unavailable" ? (
              <div className="mt-7 rounded-2xl border border-red-400/25 bg-red-500/10 p-4 text-sm font-semibold leading-6 text-red-100">
                <p>{platform.error}</p>
                <button type="button" onClick={platform.initialize} className="mt-4 font-black text-white underline decoration-red-400 underline-offset-4">Retry connection</button>
              </div>
            ) : (
              <form className="mt-8 space-y-4" onSubmit={submit}>
                {isSetup && <Field label="Full name" value={form.fullName} onChange={update("fullName")} autoComplete="name" placeholder="Platform Administrator" />}
                <Field label="Work email" type="email" value={form.email} onChange={update("email")} autoComplete="username" placeholder="admin@organization.com" />
                <Field label="Password" type="password" value={form.password} onChange={update("password")} autoComplete={isSetup ? "new-password" : "current-password"} placeholder="12 or more characters" />
                {isSetup && <Field label="Confirm password" type="password" value={form.confirmPassword} onChange={update("confirmPassword")} autoComplete="new-password" placeholder="Repeat password" />}

                {isSetup && (
                  <div className="flex items-start gap-3 rounded-2xl border border-white/[0.08] bg-white/[0.025] p-4 text-xs font-semibold leading-5 text-slate-500">
                    <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-red-300" />
                    Use at least 12 characters. Passwords are salted and hashed on the API; plaintext is never stored.
                  </div>
                )}

                {submitState.error && <p role="alert" className="rounded-xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm font-bold text-red-100">{submitState.error}</p>}

                <button type="submit" disabled={submitState.busy} className="neon-button mt-2 flex w-full items-center justify-center gap-2 py-4 disabled:cursor-wait disabled:opacity-60">
                  {submitState.busy ? "Securing session..." : isSetup ? "Initialize MVA Platform" : "Sign in"}
                  {!submitState.busy && <ArrowRight className="h-4 w-4" />}
                </button>
              </form>
            )}
          </div>
          <p className="mt-5 text-center font-mono text-[0.63rem] font-bold uppercase tracking-[0.16em] text-slate-600">HttpOnly session · Tenant-scoped access · PostgreSQL evidence</p>
        </div>
      </section>
    </main>
  );
}

function Field({ label, ...props }) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs font-black uppercase tracking-[0.12em] text-slate-500">{label}</span>
      <input required {...props} className="w-full rounded-2xl border border-white/10 bg-black/35 px-4 py-3.5 text-sm font-bold text-white outline-none transition placeholder:text-slate-700 focus:border-red-400/55 focus:ring-4 focus:ring-red-500/10" />
    </label>
  );
}

function Capability({ icon: Icon, title, detail }) {
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-black/25 p-4 backdrop-blur-xl">
      <Icon className="h-5 w-5 text-red-300" />
      <p className="mt-3 text-sm font-black text-white">{title}</p>
      <p className="mt-1 text-xs font-semibold text-slate-500">{detail}</p>
    </div>
  );
}

function LoadingGate() {
  return (
    <main className="grid min-h-screen place-items-center bg-[#050506]">
      <div className="text-center">
        <MvaLogo className="mx-auto h-20 w-20 animate-pulse" />
        <p className="mt-5 font-mono text-xs font-bold uppercase tracking-[0.22em] text-red-300">Loading MVA platform</p>
      </div>
    </main>
  );
}
