const DEFAULT_API_URL = "";

export function platformApiUrl() {
  const configured = String(import.meta.env?.VITE_MVA_DATABASE_API_URL || "").trim();
  if (configured.toLowerCase() === "same-origin") return "";
  return (configured || DEFAULT_API_URL).replace(/\/+$/, "");
}

export function getSetupStatus(options = {}) {
  return request("/api/v1/auth/setup-status", options);
}

export function bootstrapAdministrator(payload, options = {}) {
  return request("/api/v1/auth/bootstrap", { ...options, method: "POST", body: payload });
}

export function login(payload, options = {}) {
  return request("/api/v1/auth/login", { ...options, method: "POST", body: payload });
}

export function getCurrentSession(options = {}) {
  return request("/api/v1/auth/me", options);
}

export function logout(csrfToken, options = {}) {
  return request("/api/v1/auth/logout", { ...options, method: "POST", body: {}, csrfToken });
}

export function fetchCustomers(options = {}) {
  return request("/api/v1/customers", options);
}

export function createCustomer(payload, csrfToken, options = {}) {
  return request("/api/v1/customers", { ...options, method: "POST", body: payload, csrfToken });
}

export function updateCustomer(customerId, payload, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}`, { ...options, method: "PUT", body: payload, csrfToken });
}

export function deleteCustomer(customerId, confirmation, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}`, { ...options, method: "DELETE", body: { confirmation }, csrfToken });
}

export function fetchCustomerDashboard(customerId, { teamId = "", assetId = "", ...options } = {}) {
  const query = filterQuery({ teamId, assetId });
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/dashboard${query}`, options);
}

export async function downloadCustomerFindingsCsv(customerId, { teamId = "", assetId = "", fetchImpl = fetch } = {}) {
  const response = await fetchImpl(`${platformApiUrl()}/api/v1/customers/${encodeURIComponent(customerId)}/findings.csv${filterQuery({ teamId, assetId })}`, {
    method: "GET",
    headers: { Accept: "text/csv" },
    credentials: "include",
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = new Error(payload.error || `MVA API returned HTTP ${response.status}.`);
    error.status = response.status;
    throw error;
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "MVA_Vulnerability_Findings.csv";
  return { blob: await response.blob(), filename };
}

export function fetchCustomerAssets(customerId, { limit = 500, ...options } = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/assets?limit=${Math.min(100_000, Math.max(1, limit))}`, options);
}

export function fetchCustomerScanAssetCoverage(customerId, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/scan-asset-coverage`, options);
}

export function fetchCustomerTeams(customerId, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/teams`, options);
}

export function fetchLocalLlmStatus(options = {}) {
  return request("/api/v1/llm/status", options);
}

export function testLocalLlm(customerId, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/llm/test`, {
    ...options,
    method: "POST",
    body: {},
    csrfToken,
    timeoutMs: 120_000,
  });
}

export function generateRemediationWithLocalLlm(customerId, payload, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/ai/remediation`, {
    ...options,
    method: "POST",
    body: payload,
    csrfToken,
    timeoutMs: 12 * 60_000,
  });
}

export async function importThreatIntelRecords(customerId, {
  ingestionKey,
  sourceLabel,
  fileNames,
  records,
  csrfToken,
  onProgress,
  fetchImpl = fetch,
}) {
  const created = await request(`/api/v1/customers/${encodeURIComponent(customerId)}/threat-intel/imports`, {
    method: "POST",
    body: { ingestionKey, sourceLabel, fileNames, expectedRecords: records.length },
    csrfToken,
    fetchImpl,
    timeoutMs: 30_000,
  });
  const imported = created.import;
  if (imported.status === "ready") return imported;

  const chunkSize = 500;
  for (let startIndex = 0; startIndex < records.length; startIndex += chunkSize) {
    const chunk = records.slice(startIndex, startIndex + chunkSize);
    await request(`/api/v1/customers/${encodeURIComponent(customerId)}/threat-intel/imports/${encodeURIComponent(imported.id)}/chunks`, {
      method: "POST",
      body: { startIndex, records: chunk },
      csrfToken,
      fetchImpl,
      timeoutMs: 60_000,
    });
    onProgress?.({ completed: Math.min(records.length, startIndex + chunk.length), total: records.length });
  }

  const finalized = await request(`/api/v1/customers/${encodeURIComponent(customerId)}/threat-intel/imports/${encodeURIComponent(imported.id)}/finalize`, {
    method: "POST",
    body: {},
    csrfToken,
    fetchImpl,
    timeoutMs: 120_000,
  });
  return finalized.import;
}

export function searchThreatIntelRecords(customerId, query = "", options = {}) {
  const params = new URLSearchParams();
  if (query.trim()) params.set("q", query.trim());
  params.set("limit", String(options.limit ?? 100));
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/threat-intel?${params}`, options);
}

export function enrichThreatIntelWithLocalLlm(customerId, query, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/threat-intel/enrich`, {
    ...options,
    method: "POST",
    body: { query },
    csrfToken,
    timeoutMs: 6 * 60_000,
  });
}

export function createCustomerTeam(customerId, payload, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/teams`, {
    ...options,
    method: "POST",
    body: payload,
    csrfToken,
  });
}

export function updateCustomerTeam(customerId, teamId, payload, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/teams/${encodeURIComponent(teamId)}`, {
    ...options,
    method: "PUT",
    body: payload,
    csrfToken,
  });
}

export function importCustomerAssets(customerId, assets, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/assets`, {
    ...options,
    method: "POST",
    body: { assets },
    csrfToken,
    timeoutMs: 60_000,
  });
}

export function updateAssetScope(customerId, assetId, inScope, csrfToken, options = {}) {
  return updateCustomerAsset(customerId, assetId, { inScope }, csrfToken, options);
}

export function updateCustomerAsset(customerId, assetId, payload, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/assets/${encodeURIComponent(assetId)}`, {
    ...options,
    method: "PATCH",
    body: payload,
    csrfToken,
  });
}

export function deleteCustomerAssets(customerId, assetIds, csrfToken, options = {}) {
  return request(`/api/v1/customers/${encodeURIComponent(customerId)}/assets`, {
    ...options,
    method: "DELETE",
    body: { assetIds },
    csrfToken,
    timeoutMs: 60_000,
  });
}

export function fetchUsers(options = {}) {
  return request("/api/v1/admin/users", options);
}

export function createUser(payload, csrfToken, options = {}) {
  return request("/api/v1/admin/users", { ...options, method: "POST", body: payload, csrfToken });
}

export async function request(path, {
  method = "GET",
  body,
  csrfToken,
  fetchImpl = fetch,
  timeoutMs = 15_000,
} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrfToken) headers["X-MVA-CSRF"] = csrfToken;
    const response = await fetchImpl(`${platformApiUrl()}${path}`, {
      method,
      headers,
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.error || `MVA API returned HTTP ${response.status}.`);
      error.status = response.status;
      throw error;
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The MVA API request timed out.");
    if (error instanceof TypeError) throw new Error(`Cannot reach the MVA API at ${platformApiUrl()}.`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function filterQuery({ teamId = "", assetId = "" } = {}) {
  const query = new URLSearchParams();
  if (teamId) query.set("teamId", teamId);
  if (assetId) query.set("assetId", assetId);
  const value = query.toString();
  return value ? `?${value}` : "";
}
