import { useState } from "react";
import { Bot, CheckCircle2, ChevronDown, FileText, LockKeyhole } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { buildRemediationPrompt, buildTemplateMarkdown, downloadRemediationPdf } from "../lib/pdfReport.jsx";
import { generateRemediationWithLocalLlm } from "../lib/platformApi.jsx";

export function AiReportBuilder({ analysis, selectedMonth, onMonthChange, monthOptions = [], compact = false, workflow = "adhoc" }) {
  const platform = usePlatform();
  const [reportState, setReportState] = useState({ status: "idle", message: "No report generated yet" });
  const periodName = workflow === "monthly" ? "Month" : workflow === "quarterly" ? "Quarter" : "Period";
  const hasPeriods = monthOptions.length > 0 && !monthOptions.some((value) => /^No .*detected/i.test(value));
  const targetPeriod = selectedMonth && !/^No .*detected/i.test(selectedMonth) ? selectedMonth : hasPeriods ? monthOptions.at(-1) : "";
  const busy = reportState.status === "generating";
  const canUseAi = Boolean(platform.selectedCustomerId && platform.csrfToken)
    && (platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(platform.selectedCustomer?.membershipRole));

  const generateAiReport = async () => {
    const readinessError = reportReadinessError({ analysis, targetPeriod, periodName });
    if (readinessError || !canUseAi) {
      setReportState({ status: "error", message: readinessError || "Your tenant role cannot request local AI generation." });
      return;
    }
    setReportState({ status: "generating", message: `Generating the ${targetPeriod} guide through the configured private AI service. This can take several minutes.` });
    try {
      const response = await generateRemediationWithLocalLlm(platform.selectedCustomerId, {
        prompt: buildRemediationPrompt({ analysis, targetMonth: targetPeriod }),
        targetPeriod,
        sourceLabel: analysis.sourceLabel,
      }, platform.csrfToken);
      if (!response.markdown?.trim()) throw new Error("The local model returned no final report content.");
      await downloadRemediationPdf({ markdown: response.markdown, sourceLabel: analysis.sourceLabel, targetMonth: targetPeriod, workflow });
      setReportState({ status: "success", message: `AI Remediation Guide downloaded for ${targetPeriod} using ${response.model}.` });
    } catch (error) {
      setReportState({ status: "error", message: localAiError(error) });
    }
  };

  const generateLocalReport = async () => {
    const readinessError = reportReadinessError({ analysis, targetPeriod, periodName });
    if (readinessError) {
      setReportState({ status: "error", message: readinessError });
      return;
    }
    setReportState({ status: "generating", message: `Building the ${targetPeriod} local Remediation Guide...` });
    try {
      const markdown = buildTemplateMarkdown({ analysis, targetMonth: targetPeriod });
      await downloadRemediationPdf({ markdown, sourceLabel: analysis.sourceLabel, targetMonth: targetPeriod, workflow });
      setReportState({ status: "success", message: `Local Remediation Guide downloaded for ${targetPeriod}.` });
    } catch (error) {
      setReportState({ status: "error", message: error.message || "Local PDF generation failed." });
    }
  };

  return (
    <section className="enterprise-panel p-5">
      <div className="mb-5 flex items-center gap-3 border-b border-white/[0.07] pb-4">
        <span className="grid h-10 w-10 place-items-center rounded-xl border border-red-400/20 bg-red-500/[0.07]"><Bot className="h-5 w-5 text-red-300" /></span>
        <div><p className="mini-label">Report delivery</p><h2 className="text-lg font-extrabold text-white">Remediation Guide</h2></div>
      </div>

      <div className="space-y-4">
        <label className="block">
          <span className="admin-label">PDF Target {periodName}</span>
          <div className="relative">
            <select value={targetPeriod} onChange={(event) => onMonthChange?.(event.target.value)} disabled={!hasPeriods} className="admin-input appearance-none pr-11 disabled:opacity-50">
              {hasPeriods ? monthOptions.map((period) => <option key={period}>{period}</option>) : <option value="">No {periodName.toLowerCase()} detected yet</option>}
            </select>
            <ChevronDown className="pointer-events-none absolute right-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-600" />
          </div>
        </label>

        {!compact && (
          <p className="flex items-start gap-2 text-xs font-medium leading-5 text-slate-500">
            <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0" />
            Parsing, scoring, comparison, and PDF rendering stay inside MVA. AI requests travel through the authenticated tenant API to the configured private model.
          </p>
        )}
        <div className="rounded-xl border border-emerald-300/15 bg-emerald-400/[0.05] px-3 py-3 text-xs font-bold text-emerald-200">
          <p className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />Local template generation is always available. Test the private model from LLM Configuration before a live AI report.</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <button type="button" onClick={generateAiReport} disabled={busy || !canUseAi} className="primary-button flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-40"><FileText className="h-4 w-4" />Generate AI PDF</button>
          <button type="button" onClick={generateLocalReport} disabled={busy} className="secondary-button flex items-center gap-2 disabled:opacity-50"><FileText className="h-4 w-4" />Generate Local PDF</button>
        </div>
        <StatusBox state={reportState} />
      </div>
    </section>
  );
}

function reportReadinessError({ analysis, targetPeriod, periodName }) {
  if (!analysis) return "Analyze an upload before generating the PDF.";
  if (!targetPeriod) return `Select the PDF target ${periodName.toLowerCase()} first.`;
  return "";
}

function StatusBox({ state }) {
  const classes = state.status === "success"
    ? "border-emerald-300/20 bg-emerald-400/[0.06] text-emerald-200"
    : state.status === "error"
      ? "border-red-300/25 bg-red-500/[0.08] text-red-200"
      : state.status === "generating"
        ? "border-amber-300/20 bg-amber-400/[0.06] text-amber-100"
        : "border-white/[0.07] bg-white/[0.02] text-slate-500";
  return <div aria-live="polite" className={`rounded-xl border px-4 py-3 text-xs font-bold ${classes}`}>{state.message}</div>;
}

function localAiError(error) {
  const message = error?.message || "The local AI request failed.";
  if (/cannot reach the MVA API/i.test(message)) return message;
  if (/cannot reach|not installed|not available|not configured/i.test(message)) return `${message} Open LLM Configuration for the exact server-side check.`;
  if (/timed out/i.test(message)) return "The private model request timed out. Use Local PDF now or increase AI_TIMEOUT_SECONDS on the API server.";
  return message;
}
