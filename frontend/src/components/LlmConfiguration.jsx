import { useEffect, useState } from "react";
import { ArrowLeft, Bot, CheckCircle2, Database, LockKeyhole, Server, ShieldCheck, Wifi } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { fetchLocalLlmStatus, testLocalLlm } from "../lib/platformApi.jsx";

export function LlmConfiguration({ onBackToDashboard }) {
  const platform = usePlatform();
  const [configuration, setConfiguration] = useState(null);
  const [connection, setConnection] = useState({ state: "loading", message: "Reading the API-managed local model configuration..." });
  const busy = connection.state === "testing";
  const canTest = Boolean(platform.selectedCustomerId && platform.csrfToken)
    && (platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(platform.selectedCustomer?.membershipRole));

  useEffect(() => {
    let active = true;
    fetchLocalLlmStatus()
      .then((payload) => {
        if (!active) return;
        setConfiguration(payload.llm);
        setConnection({
          state: payload.llm.configured ? "idle" : "error",
          message: payload.llm.configured
            ? "Configuration loaded. Run the connectivity test to verify that the private AI endpoint and model are ready."
            : "Set AI_BASE_URL, AI_MODEL, and AI_API_STYLE on the MVA Python API.",
        });
      })
      .catch((error) => active && setConnection({ state: "error", message: error.message }));
    return () => { active = false; };
  }, []);

  const testConnection = async () => {
    if (!canTest) {
      setConnection({ state: "error", message: "An owner, analyst, or system administrator can test the local model." });
      return;
    }
    setConnection({ state: "testing", message: "Checking the Python API-to-model route and configured model..." });
    try {
      const payload = await testLocalLlm(platform.selectedCustomerId, platform.csrfToken);
      setConfiguration(payload.llm);
      setConnection({ state: "success", message: `${payload.llm.model} is installed and reachable through the MVA API.` });
    } catch (error) {
      setConnection({ state: "error", message: error.message || "Private AI connectivity failed." });
    }
  };

  return (
    <div className="space-y-4">
      <section className="enterprise-panel relative overflow-hidden p-5 sm:p-6">
        <div className="pointer-events-none absolute -right-24 -top-28 h-72 w-72 rounded-full border border-red-400/10 shadow-[0_0_0_42px_rgba(239,68,68,.018),0_0_0_84px_rgba(239,68,68,.012)]" />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-red-400/20 bg-red-500/[0.08]"><Bot className="h-6 w-6 text-red-300" /></span>
            <div>
              <p className="mini-label">Private model integration</p>
              <h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">Local LLM configuration</h2>
              <p className="mt-2 max-w-3xl text-sm font-medium leading-6 text-slate-400">Ollama or an OpenAI-compatible internal model is configured only on the MVA Python API. Analysts never paste model URLs or credentials into the browser.</p>
            </div>
          </div>
          <button type="button" onClick={onBackToDashboard} className="secondary-button flex items-center gap-2"><ArrowLeft className="h-4 w-4" />Back to Dashboards</button>
        </div>
      </section>

      <section className="enterprise-panel p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/[0.07] pb-5">
          <div>
            <p className="mini-label">Active backend route</p>
            <h3 className="mt-1 text-xl font-extrabold text-white">MVA Python API to private AI</h3>
            <p className="mt-2 text-xs font-medium leading-5 text-slate-500">Environment-managed settings are read-only in the UI and apply to all authorized tenants.</p>
          </div>
          <button type="button" onClick={testConnection} disabled={busy || !canTest} className="primary-button flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-40">
            <Wifi className={`h-4 w-4 ${busy ? "animate-pulse" : ""}`} />
            {busy ? "Testing private model..." : "Test private model"}
          </button>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <RouteCard icon={Server} label="Inference provider" value={configuration?.provider || "Local Ollama"} />
          <RouteCard icon={ShieldCheck} label="API protocol" value={configuration?.apiStyle || "ollama"} />
          <RouteCard icon={Bot} label="Model" value={configuration?.model || "Not configured"} />
          <RouteCard icon={Database} label="AI base URL" value={configuration?.baseUrl || "Not configured"} mono />
        </div>

        <ConnectionStatus state={connection} />

        <div className="mt-5 grid gap-3 md:grid-cols-3">
          <SecurityPoint icon={LockKeyhole} title="No browser secrets" detail="No provider key, token, or editable model endpoint is stored in React state." />
          <SecurityPoint icon={ShieldCheck} title="Tenant authorized" detail="AI actions require an authenticated owner or analyst session plus CSRF validation." />
          <SecurityPoint icon={Server} title="Private network route" detail="Only the Python backend can call the organization-managed inference endpoint." />
        </div>
      </section>

      <section className="enterprise-panel p-5 sm:p-6">
        <p className="mini-label">Server settings</p>
        <h3 className="mt-1 text-xl font-extrabold text-white">Deployment contract</h3>
        <div className="mt-4 overflow-hidden rounded-2xl border border-white/[0.07] bg-black/30">
          <pre className="overflow-auto p-5 font-mono text-xs leading-6 text-slate-300">{`AI_API_STYLE=ollama
AI_BASE_URL=http://ai-server.internal:11434
AI_MODEL=gemma3:12b
AI_TIMEOUT_SECONDS=600
AI_API_KEY_FILE=/run/secrets/ai_api_key`}</pre>
        </div>
        <p className="mt-3 text-xs font-medium leading-5 text-slate-500">Use `AI_API_STYLE=openai` for an OpenAI-compatible local endpoint. Change deployment environment values, not React or route code; edit `backend/local_llm.py` only if your server uses a third protocol.</p>
      </section>
    </div>
  );
}

function RouteCard({ icon: Icon, label, value, mono = false }) {
  return <article className="rounded-2xl border border-white/[0.07] bg-black/20 p-4"><Icon className="h-5 w-5 text-red-300" /><p className="mt-3 font-mono text-[0.58rem] font-bold uppercase tracking-[0.12em] text-slate-600">{label}</p><p className={`mt-2 break-all text-sm font-extrabold text-white ${mono ? "font-mono text-xs" : ""}`}>{value}</p></article>;
}

function SecurityPoint({ icon: Icon, title, detail }) {
  return <article className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-4"><Icon className="h-5 w-5 text-red-300" /><p className="mt-3 text-xs font-extrabold text-white">{title}</p><p className="mt-1 text-[0.68rem] font-medium leading-5 text-slate-600">{detail}</p></article>;
}

function ConnectionStatus({ state }) {
  const classes = state.state === "success"
    ? "border-emerald-300/20 bg-emerald-400/[0.07] text-emerald-200"
    : state.state === "error"
      ? "border-red-300/25 bg-red-500/[0.08] text-red-200"
      : state.state === "testing" || state.state === "loading"
        ? "border-amber-300/20 bg-amber-400/[0.06] text-amber-100"
        : "border-white/[0.07] bg-white/[0.02] text-slate-500";
  return <div aria-live="polite" className={`mt-4 flex items-start gap-2 rounded-xl border px-4 py-3 text-xs font-bold ${classes}`}><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />{state.message}</div>;
}
