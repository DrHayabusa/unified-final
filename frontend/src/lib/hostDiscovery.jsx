import Papa from "papaparse";

const IDENTITY_FIELDS = {
  ipAddress: [
    "ip",
    "ip address",
    "host ip",
    "host address",
    "ipv4",
    "ipv4 address",
    "ipv6",
    "ipv6 address",
    "asset ip",
    "discovered ip",
    "asset display ipv4 address",
    "asset display ipv6 address",
  ],
  dnsName: ["dns", "dns name", "fqdn", "display fqdn", "asset display fqdn", "domain name"],
  hostName: ["host", "host name", "hostname", "netbios", "netbios name", "computer name", "device name", "asset name", "name"],
  externalId: ["asset id", "external id", "device id", "host id", "agent id"],
};

const STATUS_FIELDS = ["host status", "ip status", "discovery status", "reachability", "reachable", "alive", "online", "status", "state"];
const NEGATIVE_STATUS = /^(?:0|false|no|down|offline|unreachable|dead|inactive|failed|not\s+(?:alive|discovered|reachable|scanned))$/i;
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const ALL_IDENTITY_HEADERS = new Set(Object.values(IDENTITY_FIELDS).flat());

export function isHostDiscoveryFile(file) {
  return /\.(?:csv|xlsx)$/i.test(String(file?.name ?? ""));
}

export function extractDiscoveryPeriod(fileName) {
  const name = String(fileName ?? "");
  const namedMonth = name.match(new RegExp(`(?:^|[^a-z0-9])(${MONTHS.join("|")})[ _.-]+(20\\d{2})(?=$|[^0-9])`, "i"));
  if (namedMonth) {
    const month = MONTHS.findIndex((value) => value.toLowerCase() === namedMonth[1].toLowerCase()) + 1;
    return `${namedMonth[2]}-${String(month).padStart(2, "0")}`;
  }
  const yearMonth = name.match(/(?:^|[^0-9])(20\d{2})[ _.-]?(0?[1-9]|1[0-2])(?=$|[^0-9])/);
  return yearMonth ? `${yearMonth[1]}-${String(Number(yearMonth[2])).padStart(2, "0")}` : "";
}

export function formatDiscoveryPeriod(period) {
  const match = String(period ?? "").match(/^(20\d{2})-(0[1-9]|1[0-2])$/);
  return match ? `${MONTHS[Number(match[2]) - 1]} ${match[1]}` : String(period ?? "Unspecified period");
}

export function hostDiscoveryTemplateCsv() {
  return [
    ["IP Address", "DNS Name"],
    ["10.20.1.10", "server-01.example.internal"],
  ].map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export async function parseHostDiscoveryFile(file) {
  if (!isHostDiscoveryFile(file)) throw new Error(`${file?.name ?? "The selected file"} is not supported. Upload CSV or XLSX.`);
  const matrix = /\.xlsx$/i.test(file.name) ? await xlsxMatrix(file) : csvMatrix(await file.text(), file.name);
  const parsed = matrixToHosts(matrix, file.name);
  if (!parsed.hosts.length) throw new Error(`${file.name} contains no positively discovered host identities.`);
  return parsed;
}

export async function analyzeHostDiscoveryCoverage({ inventory = [], uploads = [] }) {
  if (!Array.isArray(uploads) || uploads.length < 1 || uploads.length > 5) throw new Error("Upload between one and five monthly host discovery files.");
  const invalidPeriod = uploads.find((upload) => !/^(?:20\d{2})-(?:0[1-9]|1[0-2])$/.test(String(upload.period ?? "")));
  if (invalidPeriod) throw new Error(`Select a valid month for ${invalidPeriod.file?.name ?? "every discovery file"}.`);
  const duplicatePeriod = firstDuplicate(uploads.map((upload) => upload.period));
  if (duplicatePeriod) throw new Error(`${formatDiscoveryPeriod(duplicatePeriod)} has more than one host discovery file. Use one consolidated file per month.`);

  const scopedAssets = inventory.filter((asset) => asset.inScope !== false);
  if (!scopedAssets.length) throw new Error("The selected customer has no in-scope inventory assets. Import or enable the asset inventory first.");

  const parsedUploads = [];
  for (const upload of uploads) {
    parsedUploads.push({ ...upload, parsed: await parseHostDiscoveryFile(upload.file) });
  }
  parsedUploads.sort((left, right) => left.period.localeCompare(right.period));

  const scopedIndex = buildInventoryIndex(scopedAssets);
  const fullIndex = buildInventoryIndex(inventory);
  const assetById = new Map(scopedAssets.map((asset) => [asset.id || asset.assetKey, asset]));
  const periodResults = [];
  let previousScanned = new Set();

  for (const upload of parsedUploads) {
    const scannedAssetIds = new Set();
    const unmatchedHosts = [];
    const ambiguousHosts = [];
    const outOfScopeHosts = [];
    const matches = [];

    for (const host of upload.parsed.hosts) {
      const scopedMatch = matchHost(host, scopedIndex);
      if (scopedMatch.status === "matched") {
        scannedAssetIds.add(scopedMatch.assetId);
        matches.push({ ...scopedMatch, host });
        continue;
      }
      if (scopedMatch.status === "ambiguous") {
        ambiguousHosts.push({ ...host, candidateCount: scopedMatch.assetIds.length });
        continue;
      }
      const fullMatch = matchHost(host, fullIndex);
      if (fullMatch.status === "matched") outOfScopeHosts.push(host);
      else if (fullMatch.status === "ambiguous") ambiguousHosts.push({ ...host, candidateCount: fullMatch.assetIds.length });
      else unmatchedHosts.push(host);
    }

    const newCoverage = [...scannedAssetIds].filter((assetId) => !previousScanned.has(assetId)).length;
    const lostCoverage = [...previousScanned].filter((assetId) => !scannedAssetIds.has(assetId)).length;
    const scannedAssets = scannedAssetIds.size;
    const notScannedAssets = Math.max(0, scopedAssets.length - scannedAssets);
    const result = {
      period: upload.period,
      periodLabel: formatDiscoveryPeriod(upload.period),
      fileName: upload.file.name,
      inventoryAssets: scopedAssets.length,
      sourceRows: upload.parsed.sourceRows,
      discoveredHosts: upload.parsed.hosts.length,
      rowsWithIpAddress: upload.parsed.rowsWithIpAddress,
      rowsWithDnsName: upload.parsed.rowsWithDnsName,
      rowsWithIpAndDns: upload.parsed.rowsWithIpAndDns,
      scannedAssets,
      notScannedAssets,
      coveragePercentage: percentage(scannedAssets, scopedAssets.length),
      newCoverage,
      lostCoverage,
      unmatchedHosts,
      ambiguousHosts,
      outOfScopeHosts,
      excludedOfflineRows: upload.parsed.excludedOfflineRows,
      duplicateRowsRemoved: upload.parsed.duplicateRowsRemoved,
      scannedAssetIds,
      exactMatches: matches.filter((match) => match.matchMethod !== "unique-short-dns").length,
      uniqueShortDnsMatches: matches.filter((match) => match.matchMethod === "unique-short-dns").length,
    };
    const matchEvidence = matches.reduce((counts, match) => {
      const evidence = classifyMatchEvidence(match.host, assetById.get(match.assetId));
      counts[evidence] += 1;
      return counts;
    }, { ipAndDns: 0, ipOnly: 0, dnsOnly: 0, other: 0 });
    result.matchedByIpAndDns = matchEvidence.ipAndDns;
    result.matchedByIpOnly = matchEvidence.ipOnly;
    result.matchedByDnsOnly = matchEvidence.dnsOnly;
    result.matchedByOtherIdentity = matchEvidence.other;
    result.byAssetType = coverageBreakdown(scopedAssets, scannedAssetIds, (asset) => asset.assetType || "Other");
    result.byTeam = coverageBreakdown(scopedAssets, scannedAssetIds, (asset) => asset.teamName || "Unassigned");
    periodResults.push(result);
    previousScanned = scannedAssetIds;
  }

  const assetCoverage = scopedAssets.map((asset) => {
    const assetId = asset.id || asset.assetKey;
    const statuses = Object.fromEntries(periodResults.map((period) => [period.period, period.scannedAssetIds.has(assetId)]));
    const monthsScanned = Object.values(statuses).filter(Boolean).length;
    const reversed = periodResults.toReversed();
    const consecutiveMissed = reversed.findIndex((period) => period.scannedAssetIds.has(assetId));
    const lastScanned = reversed.find((period) => period.scannedAssetIds.has(assetId));
    return {
      ...asset,
      id: assetId,
      displayName: asset.dnsName || asset.hostName || asset.ipAddress || asset.assetKey,
      statuses,
      monthsScanned,
      monthsMissed: periodResults.length - monthsScanned,
      coveragePercentage: percentage(monthsScanned, periodResults.length),
      consecutiveMissed: consecutiveMissed === -1 ? periodResults.length : consecutiveMissed,
      lastScannedPeriod: lastScanned?.period ?? "",
      latestScanned: periodResults.at(-1).scannedAssetIds.has(assetId),
    };
  });

  return {
    periods: periodResults,
    periodLabels: periodResults.map((period) => period.periodLabel),
    inventoryAssetCount: scopedAssets.length,
    latestPeriod: periodResults.at(-1).period,
    latest: periodResults.at(-1),
    assetCoverage,
    neverScanned: assetCoverage.filter((asset) => asset.monthsScanned === 0).length,
    consistentlyScanned: assetCoverage.filter((asset) => asset.monthsScanned === periodResults.length).length,
    sourceFiles: parsedUploads.map((upload) => upload.file.name),
    assetById,
  };
}

export function buildThreeLayerCoverage({ inventory = [], discoveryPeriod, scanCoverage } = {}) {
  const inventoryIds = new Set(inventory.filter((asset) => asset.inScope !== false).map((asset) => asset.id || asset.assetKey).filter(Boolean));
  const discoveredIds = new Set([...(discoveryPeriod?.scannedAssetIds ?? [])].filter((assetId) => inventoryIds.has(assetId)));
  const vulnerabilityScanIds = new Set((scanCoverage?.assetIds ?? []).filter((assetId) => inventoryIds.has(assetId)));
  const confirmedByBoth = intersectionSize(discoveredIds, vulnerabilityScanIds);
  const confirmedByBothIds = intersection(discoveredIds, vulnerabilityScanIds);
  const inventoryNotDiscoveredIds = difference(inventoryIds, discoveredIds);
  const discoveredNotInVulnerabilityScanIds = difference(discoveredIds, vulnerabilityScanIds);
  const vulnerabilityScanNotInDiscoveryIds = difference(vulnerabilityScanIds, discoveredIds);
  const discoveryPeriodKey = String(discoveryPeriod?.period ?? "");
  const vulnerabilityPeriodKey = normalizedCoveragePeriod(scanCoverage?.reportPeriod);
  return {
    scanAvailable: Boolean(scanCoverage?.available),
    inventoryAssets: inventoryIds.size,
    hostDiscoveredAssets: discoveredIds.size,
    vulnerabilityScanAssets: vulnerabilityScanIds.size,
    confirmedByBoth,
    inventoryNotDiscovered: differenceSize(inventoryIds, discoveredIds),
    discoveredNotInVulnerabilityScan: differenceSize(discoveredIds, vulnerabilityScanIds),
    vulnerabilityScanNotInDiscovery: differenceSize(vulnerabilityScanIds, discoveredIds),
    discoveryCoveragePercentage: percentage(discoveredIds.size, inventoryIds.size),
    vulnerabilityScanCoveragePercentage: percentage(vulnerabilityScanIds.size, inventoryIds.size),
    discoveredAssetScanPercentage: percentage(confirmedByBoth, discoveredIds.size),
    scanResultIdentities: Number(scanCoverage?.observedScanIdentities ?? 0),
    unmatchedScanIdentities: Number(scanCoverage?.unmatchedScanIdentities ?? 0),
    ambiguousScanIdentities: Number(scanCoverage?.ambiguousScanIdentities ?? 0),
    discoveryPeriod: discoveryPeriodKey,
    vulnerabilityScanPeriod: vulnerabilityPeriodKey,
    periodsAligned: discoveryPeriodKey && vulnerabilityPeriodKey ? discoveryPeriodKey === vulnerabilityPeriodKey : null,
    assetIds: {
      inventory: sortedIds(inventoryIds),
      discovered: sortedIds(discoveredIds),
      vulnerabilityScan: sortedIds(vulnerabilityScanIds),
      confirmedByBoth: sortedIds(confirmedByBothIds),
      inventoryNotDiscovered: sortedIds(inventoryNotDiscoveredIds),
      discoveredNotInVulnerabilityScan: sortedIds(discoveredNotInVulnerabilityScanIds),
      vulnerabilityScanNotInDiscovery: sortedIds(vulnerabilityScanNotInDiscoveryIds),
    },
  };
}

export function hostDiscoveryCoverageCsv(analysis) {
  const periodHeaders = analysis.periods.map((period) => period.periodLabel);
  const rows = [[
    "Asset Name",
    "IP Address",
    "DNS Name",
    "Host Name",
    "External ID",
    "Asset Type",
    "Responsible Team",
    "Criticality",
    ...periodHeaders,
    "Months Discovered",
    "Months Not Discovered",
    "Coverage Percentage",
    "Consecutive Missed Months",
    "Last Discovered Month",
  ]];
  for (const asset of analysis.assetCoverage) {
    rows.push([
      asset.displayName,
      asset.ipAddress,
      asset.dnsName,
      asset.hostName,
      asset.externalId,
      asset.assetType,
      asset.teamName || "Unassigned",
      asset.criticality,
      ...analysis.periods.map((period) => asset.statuses[period.period] ? "Discovered" : "Not Discovered"),
      asset.monthsScanned,
      asset.monthsMissed,
      asset.coveragePercentage / 100,
      asset.consecutiveMissed,
      asset.lastScannedPeriod ? formatDiscoveryPeriod(asset.lastScannedPeriod) : "Never discovered",
    ]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export function hostDiscoveryExceptionsCsv(analysis) {
  const rows = [["Month", "Classification", "Discovered Identity", "All Observed Identities", "Candidate Assets"]];
  for (const period of analysis.periods) {
    for (const host of period.unmatchedHosts) rows.push([period.periodLabel, "Not in inventory", host.displayIdentity, host.identities.join(" | "), 0]);
    for (const host of period.ambiguousHosts) rows.push([period.periodLabel, "Ambiguous inventory match", host.displayIdentity, host.identities.join(" | "), host.candidateCount]);
    for (const host of period.outOfScopeHosts) rows.push([period.periodLabel, "Matched out-of-scope asset", host.displayIdentity, host.identities.join(" | "), 1]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export function hostDiscoveryAssetListCsv(analysis, { period = analysis?.latestPeriod, category = "all" } = {}) {
  const selected = analysis?.periods?.find((item) => item.period === period) ?? analysis?.latest;
  if (!selected) throw new Error("Analyze host discovery before exporting an asset list.");
  const allowed = new Set(["all", "discovered", "not-discovered", "never-discovered"]);
  if (!allowed.has(category)) throw new Error(`Unsupported host-discovery export category: ${category}.`);
  const labels = {
    all: "All in-scope inventory",
    discovered: "Discovered",
    "not-discovered": "Not discovered",
    "never-discovered": "Never discovered in submitted periods",
  };
  const assets = analysis.assetCoverage.filter((asset) => {
    if (category === "discovered") return Boolean(asset.statuses[selected.period]);
    if (category === "not-discovered") return !asset.statuses[selected.period];
    if (category === "never-discovered") return asset.monthsScanned === 0;
    return true;
  });
  const rows = [[
    "Classification",
    "Reporting Month",
    "Asset Name",
    "IP Address",
    "DNS Name",
    "Host Name",
    "Asset Type",
    "Responsible Team",
    "Discovered This Month",
    "Months Discovered",
    "Months Not Discovered",
    "Last Discovered Month",
  ]];
  for (const asset of assets) {
    rows.push([
      labels[category],
      selected.periodLabel,
      asset.displayName,
      asset.ipAddress,
      asset.dnsName,
      asset.hostName,
      asset.assetType,
      asset.teamName || "Unassigned",
      asset.statuses[selected.period] ? "Yes" : "No",
      asset.monthsScanned,
      asset.monthsMissed,
      asset.lastScannedPeriod ? formatDiscoveryPeriod(asset.lastScannedPeriod) : "Never discovered",
    ]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export function threeLayerCoverageCsv({ inventory = [], data, category = "confirmedByBoth" } = {}) {
  const categories = {
    inventory: "All in-scope inventory",
    discovered: "Host discovered",
    vulnerabilityScan: "In vulnerability result",
    confirmedByBoth: "Confirmed in host discovery and vulnerability result",
    inventoryNotDiscovered: "In inventory but not host discovered",
    discoveredNotInVulnerabilityScan: "Host discovered but absent from vulnerability result",
    vulnerabilityScanNotInDiscovery: "In vulnerability result but absent from host discovery",
  };
  if (!data?.assetIds || !Object.hasOwn(categories, category)) throw new Error(`Unsupported three-layer export category: ${category}.`);
  const selectedIds = new Set(data.assetIds[category] ?? []);
  const rows = [[
    "Classification",
    "Asset Name",
    "IP Address",
    "DNS Name",
    "Host Name",
    "Asset Type",
    "Responsible Team",
    "Host Discovery Month",
    "Vulnerability Result Month",
  ]];
  for (const asset of inventory) {
    const id = asset.id || asset.assetKey;
    if (!selectedIds.has(id)) continue;
    rows.push([
      categories[category],
      asset.dnsName || asset.hostName || asset.ipAddress || asset.assetKey,
      asset.ipAddress,
      asset.dnsName,
      asset.hostName,
      asset.assetType,
      asset.teamName || asset.responsibleTeam || "Unassigned",
      data.discoveryPeriod ? formatDiscoveryPeriod(data.discoveryPeriod) : "Not supplied",
      data.vulnerabilityScanPeriod ? formatDiscoveryPeriod(data.vulnerabilityScanPeriod) : "Not supplied",
    ]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export function downloadDiscoveryCsv(csv, filename) {
  const blob = new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function matrixToHosts(matrix, fileName) {
  const headerIndex = findHeaderRow(matrix);
  const rows = [];
  let headers;
  if (headerIndex >= 0) {
    headers = matrix[headerIndex].map(normalizeHeader);
    for (const values of matrix.slice(headerIndex + 1)) {
      const row = Object.fromEntries(headers.map((header, index) => [header, clean(values[index])]).filter(([header]) => header));
      if (Object.values(row).some(Boolean)) rows.push(row);
    }
  } else if (matrix.every((row) => row.filter((value) => clean(value)).length <= 1)) {
    headers = ["ip address"];
    for (const values of matrix) if (clean(values[0])) rows.push({ "ip address": clean(values[0]) });
  } else {
    throw new Error(`${fileName} has no recognizable IP, DNS, host name, or asset ID header in its first 30 rows.`);
  }

  const hostsByPrimaryIdentity = new Map();
  let excludedOfflineRows = 0;
  let identityRows = 0;
  let rowsWithIpAddress = 0;
  let rowsWithDnsName = 0;
  let rowsWithIpAndDns = 0;
  for (const row of rows) {
    const status = STATUS_FIELDS.map((header) => row[header]).find((value) => clean(value));
    if (status && NEGATIVE_STATUS.test(clean(status))) {
      excludedOfflineRows += 1;
      continue;
    }
    const typedIdentities = Object.fromEntries(Object.entries(IDENTITY_FIELDS).map(([type, aliases]) => [
      type,
      aliases.flatMap((alias) => splitIdentityCell(row[alias])),
    ]));
    const identities = Object.values(typedIdentities).flat();
    const normalized = [...new Set(identities.map(normalizeIdentity).filter(Boolean))];
    if (!normalized.length) continue;
    identityRows += 1;
    const ipAddresses = [...new Set(typedIdentities.ipAddress.map(normalizeIdentity).filter(Boolean))];
    const dnsNames = [...new Set(typedIdentities.dnsName.map(normalizeIdentity).filter(Boolean))];
    if (ipAddresses.length) rowsWithIpAddress += 1;
    if (dnsNames.length) rowsWithDnsName += 1;
    if (ipAddresses.length && dnsNames.length) rowsWithIpAndDns += 1;
    const primary = normalized[0];
    const current = hostsByPrimaryIdentity.get(primary);
    if (current) {
      current.identities = [...new Set([...current.identities, ...normalized])];
      current.ipAddresses = [...new Set([...current.ipAddresses, ...ipAddresses])];
      current.dnsNames = [...new Set([...current.dnsNames, ...dnsNames])];
    } else {
      hostsByPrimaryIdentity.set(primary, {
        displayIdentity: identities.find((value) => clean(value)) || primary,
        identities: normalized,
        ipAddresses,
        dnsNames,
      });
    }
  }
  return {
    fileName,
    hosts: [...hostsByPrimaryIdentity.values()],
    sourceRows: rows.length,
    excludedOfflineRows,
    duplicateRowsRemoved: Math.max(0, identityRows - hostsByPrimaryIdentity.size),
    rowsWithIpAddress,
    rowsWithDnsName,
    rowsWithIpAndDns,
  };
}

function classifyMatchEvidence(host, asset) {
  if (!asset) return "other";
  const inventoryIp = normalizeIdentity(asset.ipAddress);
  const inventoryDns = normalizeIdentity(asset.dnsName);
  const shortDns = inventoryDns.includes(".") ? inventoryDns.split(".")[0] : inventoryDns;
  const ipMatched = Boolean(inventoryIp && host.ipAddresses?.includes(inventoryIp));
  const dnsMatched = Boolean(inventoryDns && host.dnsNames?.some((value) => value === inventoryDns || value === shortDns));
  if (ipMatched && dnsMatched) return "ipAndDns";
  if (ipMatched) return "ipOnly";
  if (dnsMatched) return "dnsOnly";
  return "other";
}

function csvMatrix(text, fileName) {
  const result = Papa.parse(String(text ?? ""), { header: false, skipEmptyLines: "greedy" });
  if (!result.data.length) throw new Error(`${fileName} is empty.`);
  const nonFatalCodes = new Set(["TooFewFields", "TooManyFields", "UndetectableDelimiter"]);
  const fatal = result.errors.filter((error) => !nonFatalCodes.has(error.code));
  if (fatal.length) throw new Error(`${fileName} could not be parsed: ${fatal[0].message}`);
  return result.data;
}

async function xlsxMatrix(file) {
  if (typeof file?.arrayBuffer !== "function") throw new Error(`${file?.name ?? "The XLSX file"} cannot be read.`);
  const { default: ExcelJS } = await import("exceljs");
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(await file.arrayBuffer());
  for (const sheet of workbook.worksheets) {
    const matrix = [];
    sheet.eachRow({ includeEmpty: false }, (row) => {
      const values = Array.from({ length: row.cellCount }, (_, index) => excelCellText(row.getCell(index + 1)));
      if (values.some(Boolean)) matrix.push(values);
    });
    if (findHeaderRow(matrix) >= 0 || matrix.every((row) => row.filter(Boolean).length <= 1)) return matrix;
  }
  throw new Error(`${file.name} has no worksheet containing recognizable host discovery data.`);
}

function findHeaderRow(matrix) {
  const limit = Math.min(matrix.length, 30);
  for (let index = 0; index < limit; index += 1) {
    const headers = matrix[index].map(normalizeHeader);
    if (headers.some((header) => ALL_IDENTITY_HEADERS.has(header))) return index;
  }
  return -1;
}

function buildInventoryIndex(assets) {
  const aliases = new Map();
  const shortDnsOwners = new Map();
  for (const asset of assets) {
    const assetId = asset.id || asset.assetKey;
    for (const [method, value] of [
      ["asset-key", asset.assetKey],
      ["ip-address", asset.ipAddress],
      ["dns-name", asset.dnsName],
      ["host-name", asset.hostName],
      ["external-id", asset.externalId],
    ]) addAlias(aliases, normalizeIdentity(value), assetId, method);
    const dns = normalizeIdentity(asset.dnsName);
    if (dns?.includes(".")) {
      const shortName = dns.split(".")[0];
      const owners = shortDnsOwners.get(shortName) ?? new Set();
      owners.add(assetId);
      shortDnsOwners.set(shortName, owners);
    }
  }
  for (const [shortName, owners] of shortDnsOwners) {
    if (owners.size === 1) addAlias(aliases, shortName, [...owners][0], "unique-short-dns");
  }
  return aliases;
}

function addAlias(index, alias, assetId, method) {
  if (!alias) return;
  const candidates = index.get(alias) ?? new Map();
  if (!candidates.has(assetId)) candidates.set(assetId, method);
  index.set(alias, candidates);
}

function matchHost(host, index) {
  const candidates = new Map();
  for (const identity of host.identities) {
    for (const [assetId, method] of index.get(identity) ?? []) {
      if (!candidates.has(assetId) || method !== "unique-short-dns") candidates.set(assetId, { method, identity });
    }
  }
  const assetIds = [...candidates.keys()];
  if (assetIds.length === 1) {
    const selected = candidates.get(assetIds[0]);
    return { status: "matched", assetId: assetIds[0], matchMethod: selected.method, matchedIdentity: selected.identity };
  }
  return assetIds.length > 1 ? { status: "ambiguous", assetIds } : { status: "unmatched", assetIds: [] };
}

function coverageBreakdown(assets, scannedIds, groupBy) {
  const groups = new Map();
  for (const asset of assets) {
    const label = groupBy(asset) || "Unassigned";
    const group = groups.get(label) ?? { label, inventoryAssets: 0, scannedAssets: 0, notScannedAssets: 0, coveragePercentage: 0 };
    group.inventoryAssets += 1;
    if (scannedIds.has(asset.id || asset.assetKey)) group.scannedAssets += 1;
    groups.set(label, group);
  }
  return [...groups.values()].map((group) => ({
    ...group,
    notScannedAssets: group.inventoryAssets - group.scannedAssets,
    coveragePercentage: percentage(group.scannedAssets, group.inventoryAssets),
  })).sort((left, right) => left.coveragePercentage - right.coveragePercentage || right.inventoryAssets - left.inventoryAssets || left.label.localeCompare(right.label));
}

function splitIdentityCell(value) {
  const source = clean(value);
  if (!source) return [];
  if (/^\[.*\]$/.test(source)) {
    try {
      const parsed = JSON.parse(source);
      if (Array.isArray(parsed)) return parsed.flatMap(splitIdentityCell);
    } catch {
      // Fall through to delimiter parsing for non-JSON scanner values.
    }
  }
  return source.split(/[;,|\n]+/).map(clean).filter(Boolean);
}

function normalizeIdentity(value) {
  let identity = clean(value).toLowerCase();
  if (!identity || ["n/a", "na", "none", "null", "unknown", "-"].includes(identity)) return "";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(identity)) {
    try { identity = new URL(identity).hostname.toLowerCase(); } catch { /* Keep original scanner value. */ }
  }
  identity = identity.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (/^[^:]+:\d+$/.test(identity)) identity = identity.replace(/:\d+$/, "");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(identity)) {
    const octets = identity.split(".").map(Number);
    if (octets.every((octet) => octet >= 0 && octet <= 255)) return octets.join(".");
  }
  return identity;
}

function normalizeHeader(value) {
  return clean(value).toLowerCase().replace(/[._-]+/g, " ").replace(/\s+/g, " ");
}

function excelCellText(cell) {
  if (cell?.value == null) return "";
  if (cell.value instanceof Date) return cell.value.toISOString().slice(0, 10);
  return clean(cell.text ?? cell.value);
}

function percentage(numerator, denominator) {
  return denominator ? Math.round((numerator / denominator) * 10_000) / 100 : 0;
}

function firstDuplicate(values) {
  const seen = new Set();
  return values.find((value) => seen.has(value) || !seen.add(value));
}

function intersectionSize(left, right) {
  let count = 0;
  for (const value of left) if (right.has(value)) count += 1;
  return count;
}

function intersection(left, right) {
  return new Set([...left].filter((value) => right.has(value)));
}

function differenceSize(left, right) {
  let count = 0;
  for (const value of left) if (!right.has(value)) count += 1;
  return count;
}

function difference(left, right) {
  return new Set([...left].filter((value) => !right.has(value)));
}

function sortedIds(values) {
  return [...values].sort((left, right) => String(left).localeCompare(String(right)));
}

function normalizedCoveragePeriod(value) {
  const text = String(value ?? "").trim();
  const iso = text.match(/^(20\d{2})-(0[1-9]|1[0-2])/);
  if (iso) return `${iso[1]}-${iso[2]}`;
  const named = text.match(new RegExp(`(${MONTHS.join("|")})\\s+(20\\d{2})`, "i"));
  if (!named) return "";
  const month = MONTHS.findIndex((item) => item.toLowerCase() === named[1].toLowerCase()) + 1;
  return `${named[2]}-${String(month).padStart(2, "0")}`;
}

function csvCell(value) {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function clean(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object" && "text" in value) return String(value.text ?? "").trim();
  if (typeof value === "object" && "result" in value) return String(value.result ?? "").trim();
  return String(value).trim();
}
