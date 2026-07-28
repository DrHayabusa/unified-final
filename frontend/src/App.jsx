import { useEffect, useMemo, useRef, useState } from "react";
import { BrainCircuit, DatabaseZap, ShieldCheck } from "lucide-react";
import { AdminConsole, AssetInventoryWorkspace } from "./components/AdminConsole.jsx";
import { AiReportBuilder } from "./components/AiReportBuilder.jsx";
import { AuthScreen } from "./components/AuthScreen.jsx";
import { CustomerDashboard } from "./components/CustomerDashboard.jsx";
import { FieldMappingPanel } from "./components/FieldMappingPanel.jsx";
import { HeroHeader } from "./components/HeroHeader.jsx";
import { HostDiscoveryCoverage } from "./components/HostDiscoveryCoverage.jsx";
import { LlmConfiguration } from "./components/LlmConfiguration.jsx";
import { MetricsRow } from "./components/MetricsRow.jsx";
import { MonthlyComparison } from "./components/MonthlyComparison.jsx";
import { OperationMode } from "./components/OperationMode.jsx";
import { OpenShiftInsights } from "./components/OpenShiftInsights.jsx";
import { PriorityMatrix } from "./components/PriorityMatrix.jsx";
import { AnalysisLineChart } from "./components/AnalysisLineChart.jsx";
import { RemediationQueue } from "./components/RemediationQueue.jsx";
import { Sidebar } from "./components/Sidebar.jsx";
import { SourceChoice } from "./components/SourceChoice.jsx";
import { TrendPanel } from "./components/TrendPanel.jsx";
import { ThreatIntelPanel } from "./components/ThreatIntelPanel.jsx";
import { UploadPanel } from "./components/UploadPanel.jsx";
import { SourceCoveragePanel } from "./components/SourceCoveragePanel.jsx";
import { UnifiedAnalysisDashboard } from "./components/UnifiedAnalysisDashboard.jsx";
import { CustomerValueDashboards } from "./components/CustomerValueDashboards.jsx";
import { CrowdStrikeInsights } from "./components/CrowdStrikeInsights.jsx";
import { PersistencePanel } from "./components/PersistencePanel.jsx";
import { QualysInsights } from "./components/QualysInsights.jsx";
import { usePlatform } from "./context/PlatformContext.jsx";
import { implementedSourceTools, sourceTools, unifiedSourceTool } from "./data/dashboardData.jsx";
import { analyzeAdhocFiles, analyzeMonthlyFiles, analyzeQuarterlyScan } from "./lib/vulnerabilityEngine.jsx";

export default function App() {
  const platform = usePlatform();
  const [sourceSelectionMode, setSourceSelectionMode] = useState("single");
  const [selectedSourceIds, setSelectedSourceIds] = useState(["tenable-sc"]);
  const [mode, setMode] = useState("portfolio");
  const [adhocAnalysis, setAdhocAnalysis] = useState(null);
  const [adhocFiles, setAdhocFiles] = useState([]);
  const [monthlyAnalysis, setMonthlyAnalysis] = useState(null);
  const [monthlyFiles, setMonthlyFiles] = useState([]);
  const [quarterlyAnalysis, setQuarterlyAnalysis] = useState(null);
  const [quarterlyFiles, setQuarterlyFiles] = useState([]);
  const [selectedMonth, setSelectedMonth] = useState("");
  const [lastAnalysis, setLastAnalysis] = useState(null);
  const customerWorkspaceRef = useRef("");

  const selectedSource = useMemo(
    () => sourceSelectionMode === "multi"
      ? { ...unifiedSourceTool, sourceIds: selectedSourceIds }
      : sourceTools.find((source) => source.id === selectedSourceIds[0]) ?? sourceTools[0],
    [selectedSourceIds, sourceSelectionMode],
  );
  const sourceSelection = useMemo(
    () => sourceSelectionMode === "multi" ? { mode: "multi", sourceIds: selectedSourceIds } : selectedSourceIds[0],
    [selectedSourceIds, sourceSelectionMode],
  );
  const unifiedSelectionReady = sourceSelectionMode !== "multi" || selectedSourceIds.length >= 2;
  const focusComparisonDashboard = mode === "monthly" && Boolean(monthlyAnalysis);
  const platformPage = ["portfolio", "admin", "assets", "discovery", "llm-config"].includes(mode);
  const focusWorkspace = platformPage || focusComparisonDashboard || mode === "threat-intel";

  useEffect(() => {
    if (platform.status === "authenticated" && mode === "admin" && platform.user?.globalRole !== "system_admin") setMode("portfolio");
    if (platform.status === "authenticated" && mode === "assets" && platform.user?.globalRole !== "system_admin" && !["owner", "analyst"].includes(platform.selectedCustomer?.membershipRole)) setMode("portfolio");
  }, [mode, platform.selectedCustomer?.membershipRole, platform.status, platform.user?.globalRole]);

  const handleModeChange = (nextMode) => {
    if (!unifiedSelectionReady) return;
    setMode(nextMode);
  };

  const handleNavigation = (page) => {
    if (page === "dashboard" || page === "scanner") {
      handleBackToDashboard();
      return;
    }

    if (["portfolio", "admin", "assets", "discovery", "llm-config"].includes(page)) {
      setMode(page);
      return;
    }

    if (!unifiedSelectionReady) return;
    setMode(page);
  };

  const resetSourceWorkspace = () => {
    setAdhocAnalysis(null);
    setAdhocFiles([]);
    setMonthlyAnalysis(null);
    setMonthlyFiles([]);
    setQuarterlyAnalysis(null);
    setQuarterlyFiles([]);
    setSelectedMonth("");
    setLastAnalysis(null);
  };

  useEffect(() => {
    const previousCustomerId = customerWorkspaceRef.current;
    customerWorkspaceRef.current = platform.selectedCustomerId;
    if (!previousCustomerId || !platform.selectedCustomerId || previousCustomerId === platform.selectedCustomerId) return;
    resetSourceWorkspace();
    setMode((current) => ["admin", "assets", "portfolio", "discovery", "llm-config"].includes(current) ? current : "portfolio");
  }, [platform.selectedCustomerId]);

  const handleSourceModeChange = (nextMode) => {
    if (nextMode === sourceSelectionMode) return;
    setSourceSelectionMode(nextMode);
    setSelectedSourceIds(nextMode === "multi" ? [] : [selectedSourceIds[0] ?? "tenable-sc"]);
    resetSourceWorkspace();
  };

  const handleSourceToggle = (sourceId) => {
    if (sourceSelectionMode === "single") {
      if (selectedSourceIds[0] === sourceId) return;
      setSelectedSourceIds([sourceId]);
      resetSourceWorkspace();
      return;
    }
    setSelectedSourceIds((current) => current.includes(sourceId) ? current.filter((id) => id !== sourceId) : [...current, sourceId]);
    resetSourceWorkspace();
  };

  const handleSelectAllSources = () => {
    // Custom Qualys is an alternative rating profile for Qualys, not another
    // scanner feed, so the two profiles must never be selected together.
    setSelectedSourceIds(implementedSourceTools.filter((source) => source.id !== "custom-qualys").map((source) => source.id));
    resetSourceWorkspace();
  };

  const handleClearSources = () => {
    setSelectedSourceIds([]);
    resetSourceWorkspace();
  };

  const handleAdhocAnalyze = async (files, options = {}) => {
    const customer = requireAnalysisCustomer(platform);
    const result = await analyzeAdhocFiles(files, sourceSelection, options);
    const scopedResult = bindAnalysisToCustomer(result, customer);
    setAdhocFiles(Array.from(files ?? []));
    setAdhocAnalysis(scopedResult);
    setLastAnalysis(scopedResult);
    setSelectedMonth(scopedResult.reportMonth);
    return scopedResult;
  };

  const handleMonthlyAnalyze = async (files, options = {}) => {
    const customer = requireAnalysisCustomer(platform);
    const result = await analyzeMonthlyFiles(files, sourceSelection, options);
    const scopedResult = bindAnalysisToCustomer(result, customer);
    setMonthlyFiles(Array.from(files ?? []));
    setMonthlyAnalysis(scopedResult);
    setLastAnalysis(scopedResult);
    setSelectedMonth(scopedResult.dashboard.uploadedMonths.at(-1));
    return scopedResult;
  };

  const handleQuarterlyAnalyze = async (files, options = {}) => {
    const customer = requireAnalysisCustomer(platform);
    const result = await analyzeQuarterlyScan(files, sourceSelection, options);
    const scopedResult = bindAnalysisToCustomer(result, customer);
    setQuarterlyFiles(Array.from(files ?? []));
    setQuarterlyAnalysis(scopedResult);
    setLastAnalysis(scopedResult);
    setSelectedMonth(scopedResult.reportPeriod);
    return scopedResult;
  };

  const handleAdhocFilesChange = (nextFiles) => {
    setAdhocFiles((currentFiles) => typeof nextFiles === "function" ? nextFiles(currentFiles) : nextFiles);
    setAdhocAnalysis(null);
    setSelectedMonth("");
  };

  const handleQuarterlyFilesChange = (nextFiles) => {
    setQuarterlyFiles((currentFiles) => typeof nextFiles === "function" ? nextFiles(currentFiles) : nextFiles);
    setQuarterlyAnalysis(null);
    setSelectedMonth("");
  };

  const handleEditMonthlyUploads = () => {
    setMonthlyAnalysis(null);
    setSelectedMonth("");
  };

  const handleResetMonthlyUploads = () => {
    setMonthlyAnalysis(null);
    setMonthlyFiles([]);
    setSelectedMonth("");
  };

  const handleBackToDashboard = () => {
    setMode(null);
    setAdhocAnalysis(null);
    setAdhocFiles([]);
    setMonthlyAnalysis(null);
    setMonthlyFiles([]);
    setQuarterlyAnalysis(null);
    setQuarterlyFiles([]);
    setSelectedMonth("");
  };

  if (platform.status !== "authenticated") return <AuthScreen />;

  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_72%_0%,rgba(220,38,38,.055),transparent_32rem)]" />
      <div className="relative z-10 flex">
        <Sidebar activePage={mode ?? "scanner"} onNavigate={handleNavigation} />

        <main className="min-w-0 flex-1 px-4 pb-28 pt-4 sm:px-5 lg:px-6 lg:pb-7">
          <div className="mx-auto flex max-w-[1740px] flex-col gap-4">
            <HeroHeader />

            <div className={focusWorkspace ? "grid gap-5" : "grid gap-5 2xl:grid-cols-[1fr_390px]"}>
              <div className="flex min-w-0 flex-col gap-5">
                {mode === "portfolio" && <CustomerDashboard onNavigate={handleNavigation} />}
                {mode === "admin" && <AdminConsole onNavigate={handleNavigation} />}
                {mode === "assets" && <AssetInventoryWorkspace platform={platform} onOpenValidation={() => setMode("discovery")} />}
                {mode === "discovery" && <HostDiscoveryCoverage platform={platform} onBackToDashboard={() => setMode("portfolio")} onManageInventory={() => setMode("assets")} />}
                {mode === "llm-config" && <LlmConfiguration onBackToDashboard={() => setMode("portfolio")} />}

                {!focusWorkspace && (
                  <>
                    <SourceChoice
                      selectionMode={sourceSelectionMode}
                      selectedSourceIds={selectedSourceIds}
                      onModeChange={handleSourceModeChange}
                      onToggle={handleSourceToggle}
                      onSelectAll={handleSelectAllSources}
                      onClear={handleClearSources}
                    />
                    <OperationMode
                      mode={mode}
                      onModeChange={handleModeChange}
                      disabled={!unifiedSelectionReady}
                      disabledMessage="Select at least two source tools before choosing a unified workflow."
                    />
                  </>
                )}

                {!mode && <LandingHint selectedSource={selectedSource} />}

                {mode === "adhoc" && (
                  <>
                    <UploadPanel selectedSource={selectedSource} analysis={adhocAnalysis} files={adhocFiles} onFilesChange={handleAdhocFilesChange} onAnalyze={handleAdhocAnalyze} onBackToDashboard={handleBackToDashboard} />

                    {adhocAnalysis ? (
                      <>
                        <MetricsRow dashboard={adhocAnalysis.dashboard} />
                        <UnifiedAnalysisDashboard dashboard={adhocAnalysis.dashboard} />
                        <SourceCoveragePanel dashboard={adhocAnalysis.dashboard} inputSummary={adhocAnalysis.inputSummary} />
                        <CustomerValueDashboards analysis={adhocAnalysis} />
                        <QualysInsights insights={adhocAnalysis.dashboard.qualysInsights} />
                        <CrowdStrikeInsights insights={adhocAnalysis.dashboard.crowdstrikeInsights} />
                        <OpenShiftInsights insights={adhocAnalysis.dashboard.openshiftInsights} />
                        <PersistencePanel analysis={adhocAnalysis} />
                        <AnalysisLineChart dashboard={adhocAnalysis.dashboard} />
                        <TrendPanel dashboard={adhocAnalysis.dashboard} />
                        <div className="grid gap-5 xl:grid-cols-[1fr_1fr] 2xl:grid-cols-[1.1fr_1fr]">
                          <FieldMappingPanel source={selectedSource} exportType={adhocAnalysis.exportType} />
                          <PriorityMatrix />
                        </div>
                        <RemediationQueue findings={adhocAnalysis.findings} />
                      </>
                    ) : (
                      <EmptyWorkflow />
                    )}
                  </>
                )}

                {mode === "monthly" && (
                  <>
                    <MonthlyComparison
                      analysis={monthlyAnalysis}
                      onAnalyze={handleMonthlyAnalyze}
                      selectedSource={selectedSource}
                      selectedMonth={selectedMonth}
                      onMonthChange={setSelectedMonth}
                      files={monthlyFiles}
                      onFilesChange={setMonthlyFiles}
                      onEditUploads={handleEditMonthlyUploads}
                      onResetUploads={handleResetMonthlyUploads}
                      onBackToDashboard={handleBackToDashboard}
                      cadence="monthly"
                    />
                    {monthlyAnalysis && <PersistencePanel analysis={monthlyAnalysis} />}
                  </>
                )}

                {mode === "quarterly" && (
                  <>
                    <UploadPanel selectedSource={selectedSource} analysis={quarterlyAnalysis} files={quarterlyFiles} onFilesChange={handleQuarterlyFilesChange} onAnalyze={handleQuarterlyAnalyze} onBackToDashboard={handleBackToDashboard} workflow="quarterly-scan" />
                    {quarterlyAnalysis ? (
                      <>
                        <MetricsRow dashboard={quarterlyAnalysis.dashboard} />
                        <UnifiedAnalysisDashboard dashboard={quarterlyAnalysis.dashboard} />
                        <SourceCoveragePanel dashboard={quarterlyAnalysis.dashboard} inputSummary={quarterlyAnalysis.inputSummary} />
                        <CustomerValueDashboards analysis={quarterlyAnalysis} />
                        <QualysInsights insights={quarterlyAnalysis.dashboard.qualysInsights} />
                        <CrowdStrikeInsights insights={quarterlyAnalysis.dashboard.crowdstrikeInsights} />
                        <OpenShiftInsights insights={quarterlyAnalysis.dashboard.openshiftInsights} />
                        <PersistencePanel analysis={quarterlyAnalysis} />
                        <AnalysisLineChart dashboard={quarterlyAnalysis.dashboard} />
                        <TrendPanel dashboard={quarterlyAnalysis.dashboard} />
                        <div className="grid gap-5 xl:grid-cols-[1fr_1fr] 2xl:grid-cols-[1.1fr_1fr]">
                          <FieldMappingPanel source={selectedSource} exportType={quarterlyAnalysis.exportType} />
                          <PriorityMatrix />
                        </div>
                        <RemediationQueue findings={quarterlyAnalysis.findings} />
                      </>
                    ) : (
                      <EmptyQuarterlyWorkflow unified={selectedSource.id === "unified"} />
                    )}
                  </>
                )}

                {mode === "threat-intel" && (
                  <ThreatIntelPanel analysis={lastAnalysis} onBackToDashboard={handleBackToDashboard} />
                )}
              </div>

              {!focusWorkspace && (
                <aside className="flex flex-col gap-5">
                  {!mode && <PriorityMatrix compact />}
                  <StatusPanel
                    selectedSource={selectedSource}
                    mode={mode}
                    adhocUploaded={Boolean(adhocAnalysis)}
                    monthlyUploaded={Boolean(monthlyAnalysis)}
                    quarterlyUploaded={Boolean(quarterlyAnalysis)}
                  />
                  {mode !== "monthly" && (
                    <AiReportBuilder
                      selectedMonth={selectedMonth || "No period detected"}
                      onMonthChange={setSelectedMonth}
                      monthOptions={(mode === "quarterly" ? quarterlyAnalysis : adhocAnalysis) ? [mode === "quarterly" ? quarterlyAnalysis.reportPeriod : adhocAnalysis.reportMonth] : ["No period detected"]}
                      analysis={mode === "quarterly" ? quarterlyAnalysis : adhocAnalysis}
                      workflow={mode === "quarterly" ? "quarterly-scan" : "adhoc"}
                      compact
                    />
                  )}
                </aside>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function requireAnalysisCustomer(platform) {
  if (!platform.selectedCustomerId || !platform.selectedCustomer) throw new Error("Create or select a tenant before analyzing scanner data.");
  return platform.selectedCustomer;
}

function bindAnalysisToCustomer(analysis, customer) {
  return {
    ...analysis,
    customerWorkspaceId: customer.id,
    customerWorkspaceName: customer.name,
  };
}

function LandingHint({ selectedSource }) {
  return (
    <section className="cyber-panel rounded-[1.75rem] p-6">
      <div className="grid gap-5 lg:grid-cols-3">
        {[
          [DatabaseZap, "Source-aware dashboards", `${selectedSource.name} mapping is selected and ready.`],
          [ShieldCheck, "Exploit-aware priority", "Each supported scanner's exploit signal feeds the same approved P1-P4 matrix."],
          [BrainCircuit, "Private AI reports", "Prioritized findings can be sent through the authenticated MVA API to the organization-managed local AI model."],
        ].map(([Icon, title, body]) => (
          <div key={title} className="rounded-2xl border border-white/10 bg-white/[0.035] p-5">
            <Icon className="mb-4 h-8 w-8 text-red-300" />
            <h3 className="text-lg font-black text-white">{title}</h3>
            <p className="mt-2 text-sm font-semibold leading-6 text-slate-400">{body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function EmptyWorkflow() {
  return (
    <section className="rounded-[1.75rem] border border-dashed border-red-300/20 bg-slate-950/50 p-8 text-center">
      <p className="mini-label">Waiting for data</p>
      <h2 className="mt-2 text-2xl font-black text-white">Upload an export to unlock ad hoc metrics</h2>
      <p className="mx-auto mt-2 max-w-2xl text-sm font-semibold leading-6 text-slate-400">
        Once a CSV or XLSX is uploaded, MVA renders Total Open, Critical, High, Medium, Low, and Immediate Patch Needed with live trend sparklines.
      </p>
    </section>
  );
}

function EmptyQuarterlyWorkflow({ unified = false }) {
  return (
    <section className="rounded-[1.75rem] border border-dashed border-red-300/20 bg-slate-950/50 p-8 text-center">
      <p className="mini-label">Waiting for quarterly scan data</p>
      <h2 className="mt-2 text-2xl font-black text-white">{unified ? "Upload one current export per selected scanner" : "Upload one current scan export"}</h2>
      <p className="mx-auto mt-2 max-w-2xl text-sm font-semibold leading-6 text-slate-400">
        {unified ? "MVA will consolidate the current scanner exports, retain source provenance, and chart vulnerabilities first discovered during the latest three months." : "MVA will summarize all open findings and build a line chart for vulnerabilities first discovered in the export's latest three months."}
      </p>
    </section>
  );
}

function StatusPanel({ selectedSource, mode, adhocUploaded, monthlyUploaded, quarterlyUploaded }) {
  const uploadState =
    mode === "monthly"
      ? monthlyUploaded
        ? "Monthly report analyzed"
        : "Waiting for monthly exports"
      : mode === "quarterly"
        ? quarterlyUploaded
          ? "Quarterly report analyzed"
          : selectedSource.id === "unified" ? "Waiting for current scanner exports" : "Waiting for one quarterly scan export"
      : adhocUploaded
          ? "Ad hoc report analyzed"
        : "Waiting";

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <p className="mini-label">Session State</p>
      <h2 className="mt-1 text-xl font-black text-white">Current workflow</h2>

      <div className="mt-5 space-y-3">
        {[
          ["Source Tool", selectedSource.name],
          ["Operation Mode", mode ? (mode === "adhoc" ? "Ad hoc scan" : mode === "quarterly" ? "Quarterly analysis" : "Monthly data comparison") : "Not selected"],
          ["Upload State", uploadState],
          ["Output", "CSV / Excel / Remediation Guide PDF"],
        ].map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3">
            <span className="text-sm font-bold text-slate-500">{label}</span>
            <span className="text-right text-sm font-black text-slate-100">{value}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
