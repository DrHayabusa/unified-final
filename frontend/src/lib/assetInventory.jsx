import Papa from "papaparse";

const FIELD_ALIASES = {
  ipAddress: ["ip address", "ip", "host ip", "ipv4 address", "ipv4"],
  dnsName: ["dns name", "dns", "fqdn", "display fqdn"],
  hostName: ["host name", "hostname", "netbios", "netbios name", "asset name"],
  externalId: ["asset id", "external id", "device id", "host id"],
  assetType: ["asset type", "asset category", "device type", "system type", "category"],
  platform: ["platform", "operating system", "os", "os name"],
  businessUnit: ["business unit", "business unit name", "department", "owner group"],
  criticality: ["criticality", "asset criticality", "acr"],
  responsibleTeam: ["responsible team", "team", "team name", "owner", "asset owner", "owner team", "support team", "resolver group"],
  onboardingTool: ["tool", "scanner", "scanner tool", "source tool", "onboarded tool", "vulnerability tool"],
  internetExposed: ["internet exposed", "internet exposure", "external", "public facing"],
  inScope: ["in scope", "scope", "included"],
};

export const ASSET_TYPES = ["Network Device", "Linux Server", "Windows Server", "Endpoint", "Database", "Cloud Asset", "Security Appliance", "Virtualization Host", "Container Platform", "OT Device", "Other"];
export const ASSET_ONBOARDING_TOOLS = [
  { id: "manual", label: "Manual inventory" },
  { id: "tenable-sc", label: "Tenable.sc" },
  { id: "tenable-io", label: "Tenable.io" },
  { id: "qualys", label: "Qualys VMDR" },
  { id: "crowdstrike", label: "CrowdStrike" },
  { id: "mdvm", label: "Microsoft Defender VM" },
  { id: "openshift", label: "Red Hat OpenShift" },
  { id: "multi-tool", label: "Multiple tools" },
  { id: "other", label: "Other tool" },
];

const TOOL_ALIASES = new Map([
  ["manual", "manual"],
  ["manual inventory", "manual"],
  ["tenable sc", "tenable-sc"],
  ["tenable.sc", "tenable-sc"],
  ["tenable security center", "tenable-sc"],
  ["tenable io", "tenable-io"],
  ["tenable.io", "tenable-io"],
  ["tenable vulnerability management", "tenable-io"],
  ["qualys", "qualys"],
  ["qualys vmdr", "qualys"],
  ["crowdstrike", "crowdstrike"],
  ["crowdstrike exposure management", "crowdstrike"],
  ["mdvm", "mdvm"],
  ["microsoft defender vm", "mdvm"],
  ["microsoft defender vulnerability management", "mdvm"],
  ["openshift", "openshift"],
  ["red hat openshift", "openshift"],
  ["openshift container platform", "openshift"],
  ["multi tool", "multi-tool"],
  ["multiple tools", "multi-tool"],
  ["other", "other"],
  ["other tool", "other"],
]);

export async function parseAssetInventory(file, { defaultAssetType = "", defaultOnboardingTool = "manual", defaultPlatform = "" } = {}) {
  if (!file) throw new Error("Choose a CSV or XLSX asset inventory.");
  const rows = /\.xlsx$/i.test(file.name) ? await xlsxRows(file) : csvRows(await file.text());
  if (!rows.length) throw new Error("The asset inventory has no data rows.");
  const assets = rows.map((row) => normalizeAssetRow(row, { defaultAssetType, defaultOnboardingTool, defaultPlatform })).filter(Boolean);
  if (!assets.length) throw new Error("No asset identity was found. Include IP Address, DNS Name, Host Name, or Asset ID.");
  return deduplicateAssets(assets);
}

export function parsePastedAssetInventory(text, { defaultAssetType = "", defaultOnboardingTool = "manual", defaultPlatform = "" } = {}) {
  const source = String(text ?? "").trim();
  if (!source) throw new Error("Paste at least one IP address or DNS name.");
  const normalizedSource = source.split(/\r?\n/).map((line) => (
    line.includes("|") && !/[,;\t]/.test(line) ? line.split("|").map((cell) => cell.trim()).join(",") : line
  )).join("\n");
  const result = Papa.parse(normalizedSource, { header: false, skipEmptyLines: "greedy" });
  if (result.errors.length && !result.data.length) throw new Error(result.errors[0].message || "The pasted asset list could not be read.");
  const rows = result.data.map((row) => Array.isArray(row) ? row.map(clean) : []).filter((row) => row.some(Boolean));
  if (!rows.length) throw new Error("The pasted asset list has no data rows.");

  const knownHeaders = new Set(Object.values(FIELD_ALIASES).flat());
  const hasHeader = rows[0].some((value) => knownHeaders.has(normalizeHeader(value)));
  const assets = hasHeader
    ? rows.slice(1).map((values) => normalizeAssetRow(Object.fromEntries(rows[0].map((header, index) => [header, values[index] ?? ""])), { defaultAssetType, defaultOnboardingTool, defaultPlatform }))
    : rows.map((values) => normalizePastedRow(values, { defaultAssetType, defaultOnboardingTool, defaultPlatform }));
  const normalized = assets.filter(Boolean);
  if (!normalized.length) throw new Error("No valid asset identity was found in the pasted list.");
  return deduplicateAssets(normalized);
}

export function normalizeAssetRow(row, { defaultAssetType = "", defaultOnboardingTool = "manual", defaultPlatform = "" } = {}) {
  const normalized = Object.fromEntries(Object.entries(row ?? {}).map(([key, value]) => [normalizeHeader(key), clean(value)]));
  const value = (field) => FIELD_ALIASES[field].map((alias) => normalized[alias]).find(Boolean) ?? "";
  const ipAddress = value("ipAddress");
  const dnsName = value("dnsName");
  const hostName = value("hostName");
  const externalId = value("externalId");
  const assetKey = clean(ipAddress || dnsName || hostName || externalId).toLowerCase();
  if (!assetKey) return null;
  const platform = value("platform") || clean(defaultPlatform);
  return {
    assetKey,
    ipAddress,
    dnsName,
    hostName,
    externalId,
    assetType: normalizeAssetType(value("assetType") || defaultAssetType, platform),
    platform,
    businessUnit: value("businessUnit"),
    criticality: value("criticality"),
    responsibleTeam: value("responsibleTeam"),
    onboardingTool: normalizeOnboardingTool(value("onboardingTool") || defaultOnboardingTool),
    internetExposed: nullableBoolean(value("internetExposed")),
    inScope: true,
  };
}

export function assetInventoryTemplateCsv() {
  return "Tool,Asset Type,IP Address,DNS Name,Host Name,Team Name,OS Name\nTenable.sc,Windows Server,10.20.1.10,server01.example.com,server01,Windows Operations,Windows Server 2022\n";
}

export function normalizeOnboardingTool(value, fallback = "manual") {
  const normalized = clean(value).toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
  return TOOL_ALIASES.get(normalized) ?? ASSET_ONBOARDING_TOOLS.find((tool) => tool.id === value)?.id ?? fallback;
}

export function onboardingToolLabel(value) {
  return ASSET_ONBOARDING_TOOLS.find((tool) => tool.id === value)?.label ?? "Other tool";
}

export function normalizeAssetType(value, platform = "") {
  const requested = clean(value).toLowerCase();
  const exact = ASSET_TYPES.find((assetType) => assetType.toLowerCase() === requested);
  if (exact) return exact;
  const evidence = `${requested} ${clean(platform).toLowerCase()}`;
  if (/\b(router|switch|wireless|network|load balancer)\b/.test(evidence)) return "Network Device";
  if (/\b(firewall|waf|ids|ips|security appliance)\b/.test(evidence)) return "Security Appliance";
  if (/\b(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)\b/.test(evidence)) return "Linux Server";
  if (/\bwindows server\b/.test(evidence)) return "Windows Server";
  if (/\b(windows 10|windows 11|macos|desktop|laptop|workstation|endpoint)\b/.test(evidence)) return "Endpoint";
  if (/\b(postgres|postgresql|mysql|oracle database|sql server|database|db)\b/.test(evidence)) return "Database";
  if (/\b(aws|azure|gcp|cloud)\b/.test(evidence)) return "Cloud Asset";
  if (/\b(vmware|esxi|hyper-v|virtualization|hypervisor)\b/.test(evidence)) return "Virtualization Host";
  if (/\b(kubernetes|openshift|container|k8s)\b/.test(evidence)) return "Container Platform";
  if (/\b(scada|plc|industrial|ot device|operational technology)\b/.test(evidence)) return "OT Device";
  return "Other";
}

function csvRows(text) {
  const result = Papa.parse(text, { header: true, skipEmptyLines: "greedy", transformHeader: (header) => header.trim() });
  if (result.errors.length && !result.data.length) throw new Error(result.errors[0].message || "The CSV could not be read.");
  return result.data;
}

async function xlsxRows(file) {
  const { default: ExcelJS } = await import("exceljs");
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(await file.arrayBuffer());
  const sheet = workbook.worksheets[0];
  if (!sheet) return [];
  const headers = [];
  sheet.getRow(1).eachCell({ includeEmpty: true }, (cell, column) => { headers[column - 1] = clean(cell.value); });
  const rows = [];
  sheet.eachRow((row, rowNumber) => {
    if (rowNumber === 1) return;
    const record = {};
    headers.forEach((header, index) => { if (header) record[header] = clean(row.getCell(index + 1).value); });
    if (Object.values(record).some(Boolean)) rows.push(record);
  });
  return rows;
}

function deduplicateAssets(assets) {
  return [...new Map(assets.map((asset) => [asset.assetKey, asset])).values()];
}

function normalizePastedRow(values, { defaultAssetType = "", defaultOnboardingTool = "manual", defaultPlatform = "" } = {}) {
  const identity = clean(values[0]);
  if (!identity) return null;
  const hasAssetName = values.length >= 3;
  const assetName = hasAssetName ? clean(values[1]) : "";
  const responsibleTeam = clean(hasAssetName ? values[2] : values[1]);
  const platform = clean(hasAssetName ? values[3] : "") || clean(defaultPlatform);
  const ipAddress = isIpAddress(identity) ? identity : "";
  const dnsName = ipAddress ? "" : identity.toLowerCase();
  return {
    assetKey: identity.toLowerCase(),
    ipAddress,
    dnsName,
    hostName: assetName,
    externalId: "",
    assetType: normalizeAssetType(defaultAssetType, platform),
    platform,
    businessUnit: "",
    criticality: "",
    responsibleTeam,
    onboardingTool: normalizeOnboardingTool(defaultOnboardingTool),
    internetExposed: null,
    inScope: true,
  };
}

function isIpAddress(value) {
  if (value.includes(":")) return /^[0-9a-f:]+$/i.test(value);
  const octets = value.split(".");
  return octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function normalizeHeader(value) {
  return clean(value).toLowerCase().replace(/[._-]+/g, " ").replace(/\s+/g, " ");
}

function nullableBoolean(value) {
  if (!value) return null;
  const normalized = value.toLowerCase();
  if (["yes", "true", "1", "y", "included", "in scope"].includes(normalized)) return true;
  if (["no", "false", "0", "n", "excluded", "out of scope"].includes(normalized)) return false;
  return null;
}

function clean(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object" && "text" in value) return String(value.text).trim();
  if (typeof value === "object" && "result" in value) return String(value.result ?? "").trim();
  return String(value).trim();
}
