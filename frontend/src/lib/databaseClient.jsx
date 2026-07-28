const DEFAULT_API_URL = "";
const CHUNK_SIZE = 500;

export function databaseApiUrl() {
  const configured = String(import.meta.env?.VITE_MVA_DATABASE_API_URL || "").trim();
  if (configured.toLowerCase() === "same-origin") return "";
  return (configured || DEFAULT_API_URL).replace(/\/+$/, "");
}

export async function checkDatabaseHealth({ fetchImpl = fetch } = {}) {
  return requestJson("/health", { fetchImpl, timeoutMs: 5000 });
}

export async function fetchScanHistory({ customerId, limit = 5, fetchImpl = fetch } = {}) {
  if (!customerId) throw new Error("Select a customer before loading report history.");
  const response = await requestJson(`/api/v1/customers/${encodeURIComponent(customerId)}/scan-runs?limit=${Math.min(100, Math.max(1, limit))}`, { fetchImpl });
  return response.runs ?? [];
}

export async function persistAnalysis(analysis, { customerId, customerName = "Customer", csrfToken, fetchImpl = fetch, onProgress } = {}) {
  if (!analysis) throw new Error("Analyze scanner data before saving it to PostgreSQL.");
  if (!customerId) throw new Error("Select a customer before saving scanner results.");
  if (!csrfToken) throw new Error("Your secure session is missing. Sign in again.");
  const findings = persistenceFindings(analysis);
  if (!findings.length) throw new Error("The analysis does not contain normalized findings to save.");
  const ingestionKey = await analysisIngestionKey(analysis, findings);
  const expectedChunks = Math.ceil(findings.length / CHUNK_SIZE);
  const metadata = {
    customerName,
    ingestionKey,
    workflow: normalizedWorkflow(analysis.workflow),
    sourceTool: analysis.sourceTool || "unknown",
    sourceLabel: analysis.sourceLabel || "Unknown source",
    reportPeriod: analysis.reportMonth || analysis.reportPeriod || analysis.dashboard?.reportRange || "Unspecified period",
    fileNames: analysisFileNames(analysis),
    sourceIds: analysis.sourceIds ?? [],
    expectedFindings: findings.length,
    expectedChunks,
    dashboard: jsonSafe(analysis.dashboard),
    inputSummary: jsonSafe(analysis.inputSummary),
  };
  const customerPath = `/api/v1/customers/${encodeURIComponent(customerId)}/scan-runs`;
  const created = await requestJson(customerPath, {
    method: "POST",
    body: metadata,
    csrfToken,
    fetchImpl,
    timeoutMs: 20_000,
  });
  const run = created.run;
  if (run.status === "ready") {
    onProgress?.({ completed: findings.length, total: findings.length, message: "This analysis was already saved." });
    return run;
  }

  for (let startIndex = 0; startIndex < findings.length; startIndex += CHUNK_SIZE) {
    const chunkIndex = Math.floor(startIndex / CHUNK_SIZE);
    const chunk = findings.slice(startIndex, startIndex + CHUNK_SIZE);
    await requestJson(`${customerPath}/${run.id}/chunks`, {
      method: "POST",
      body: { chunkIndex, startIndex, findings: chunk },
      csrfToken,
      fetchImpl,
      timeoutMs: 60_000,
    });
    onProgress?.({
      completed: Math.min(findings.length, startIndex + chunk.length),
      total: findings.length,
      message: `Stored chunk ${chunkIndex + 1} of ${expectedChunks}`,
    });
  }

  onProgress?.({ completed: findings.length, total: findings.length, message: "Indexing customer assets and finalizing history..." });
  const finalized = await requestJson(`${customerPath}/${run.id}/finalize`, {
    method: "POST",
    body: {},
    csrfToken,
    fetchImpl,
    timeoutMs: 180_000,
  });
  return finalized.run;
}

export function persistenceFindings(analysis) {
  if (Array.isArray(analysis?.snapshots) && analysis.snapshots.length) {
    return analysis.snapshots.flatMap((snapshot) => (snapshot.findings ?? []).map((finding) => ({
      ...finding,
      reportPeriod: snapshot.period || snapshot.month || analysis.reportPeriod || "Unspecified period",
    })));
  }
  const reportPeriod = analysis?.reportMonth || analysis?.reportPeriod || "Adhoc Report";
  return (analysis?.findings ?? analysis?.currentFindings ?? []).map((finding) => ({ ...finding, reportPeriod }));
}

export async function analysisIngestionKey(analysis, findings = persistenceFindings(analysis)) {
  const identity = [
    normalizedWorkflow(analysis?.workflow),
    analysis?.sourceTool || "unknown",
    analysis?.reportMonth || analysis?.reportPeriod || analysis?.dashboard?.reportRange || "",
    analysisFileNames(analysis).sort().join("|"),
    ...findings.map((finding) => [
      finding.reportPeriod,
      finding.findingKey,
      finding.recordCount,
      finding.severity,
      finding.patchPriority,
      finding.exploitAvailable ? 1 : 0,
      finding.firstDiscovered,
      finding.lastObserved,
    ].join("\u001f")),
  ].join("\n");
  return `mva:${await sha256(identity)}`;
}

function analysisFileNames(analysis) {
  const names = analysis?.fileNames?.length
    ? analysis.fileNames
    : (analysis?.snapshots ?? []).flatMap((snapshot) => snapshot.fileNames?.length ? snapshot.fileNames : [snapshot.fileName].filter(Boolean));
  if (!names.length && analysis?.fileName) names.push(analysis.fileName);
  return [...new Set(names.filter(Boolean))];
}

function normalizedWorkflow(workflow) {
  if (workflow === "quarterly-scan") return "quarterly-scan";
  if (workflow === "quarterly") return "quarterly";
  if (workflow === "monthly") return "monthly";
  return "adhoc";
}

async function sha256(value) {
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  return (hash >>> 0).toString(16).padStart(8, "0");
}

async function requestJson(path, { method = "GET", body, csrfToken, fetchImpl, timeoutMs = 15_000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) headers["X-MVA-CSRF"] = csrfToken;
    const response = await fetchImpl(`${databaseApiUrl()}${path}`, {
      method,
      headers,
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `PostgreSQL API returned HTTP ${response.status}.`);
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The PostgreSQL API request timed out.");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value ?? {}));
}
