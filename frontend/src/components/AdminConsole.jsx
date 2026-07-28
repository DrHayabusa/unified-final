import { useDeferredValue, useEffect, useState } from "react";
import { AlertTriangle, Boxes, Building2, ChevronDown, ChevronLeft, ChevronRight, ClipboardPaste, Download, FileSpreadsheet, Pencil, Plus, Save, Search, Shield, Trash2, UserPlus, Users, UsersRound, X } from "lucide-react";

import { usePlatform } from "../context/PlatformContext.jsx";
import { ASSET_ONBOARDING_TOOLS, ASSET_TYPES, assetInventoryTemplateCsv, normalizeAssetRow, normalizeAssetType, onboardingToolLabel, parseAssetInventory, parsePastedAssetInventory } from "../lib/assetInventory.jsx";
import {
  createCustomer,
  createCustomerTeam,
  createUser,
  deleteCustomer,
  deleteCustomerAssets,
  fetchCustomerAssets,
  fetchCustomerScanAssetCoverage,
  fetchCustomerTeams,
  fetchUsers,
  importCustomerAssets,
  updateCustomerAsset,
  updateCustomer,
  updateCustomerTeam,
} from "../lib/platformApi.jsx";

const tabs = [
  { id: "customers", label: "Tenants", icon: Building2 },
  { id: "teams", label: "Teams & ownership", icon: UsersRound },
  { id: "assets", label: "Asset scope", icon: Boxes },
  { id: "users", label: "Users & access", icon: Users },
];

export function AdminConsole({ onNavigate }) {
  const platform = usePlatform();
  const [tab, setTab] = useState("customers");

  if (platform.user?.globalRole !== "system_admin") {
    return (
      <section className="cyber-panel rounded-[2rem] p-10 text-center">
        <Shield className="mx-auto h-10 w-10 text-red-300" />
        <h2 className="mt-4 text-2xl font-black text-white">Administrator access required</h2>
        <p className="mt-2 text-sm font-semibold text-slate-400">Tenant administration is limited to platform administrators.</p>
        <button type="button" onClick={() => onNavigate?.("portfolio")} className="ghost-button mt-6">Return to Dashboards</button>
      </section>
    );
  }

  return (
    <div className="space-y-5">
      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div><p className="mini-label">Platform Administration</p><h2 className="mt-2 text-3xl font-black tracking-tight text-white">Tenants, assets, and access</h2><p className="mt-2 text-sm font-semibold text-slate-400">Define each tenant boundary before saving scanner evidence into it.</p></div>
          <div className="flex flex-wrap gap-2 rounded-2xl border border-white/[0.08] bg-black/25 p-1.5">
            {tabs.map(({ id, label, icon: Icon }) => <button key={id} type="button" data-testid={`admin-tab-${id}`} onClick={() => setTab(id)} className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-black transition ${tab === id ? "bg-red-600 text-white shadow-glow" : "text-slate-500 hover:bg-white/5 hover:text-white"}`}><Icon className="h-4 w-4" />{label}</button>)}
          </div>
        </div>
      </section>

      {tab === "customers" && <CustomersTab platform={platform} onOpenAssets={() => setTab("assets")} onOpenDashboard={() => onNavigate?.("portfolio")} />}
      {tab === "teams" && <TeamsTab platform={platform} onOpenAssets={() => setTab("assets")} />}
      {tab === "assets" && <AssetInventoryWorkspace platform={platform} />}
      {tab === "users" && <UsersTab platform={platform} />}
    </div>
  );
}

function CustomersTab({ platform, onOpenAssets, onOpenDashboard }) {
  const emptyForm = { name: "", slug: "", assetScopeMode: "observed", status: "active", notes: "" };
  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState("");
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [state, setState] = useState({ busy: false, error: "", message: "" });
  const update = (field) => (event) => setForm((current) => ({ ...current, [field]: event.target.value }));

  const beginEdit = (customer) => {
    setEditingId(customer.id);
    setForm({ name: customer.name, slug: customer.slug, assetScopeMode: customer.assetScopeMode, status: customer.status, notes: customer.notes ?? "" });
    setState({ busy: false, error: "", message: "" });
  };

  const cancelEdit = () => {
    setEditingId("");
    setForm(emptyForm);
    setState({ busy: false, error: "", message: "" });
  };

  const submit = async (event) => {
    event.preventDefault();
    setState({ busy: true, error: "", message: "" });
    try {
      const payload = editingId
        ? await updateCustomer(editingId, form, platform.csrfToken)
        : await createCustomer(form, platform.csrfToken);
      await platform.refreshCustomers({ selectCustomerId: payload.customer.id });
      setEditingId("");
      setForm(emptyForm);
      setState({ busy: false, error: "", message: editingId ? `${payload.customer.name} was updated.` : `${payload.customer.name} is ready.` });
    } catch (error) {
      setState({ busy: false, error: error.message, message: "" });
    }
  };

  const removeTenant = async () => {
    if (!deleteTarget || deleteConfirmation !== deleteTarget.name) return;
    setState({ busy: true, error: "", message: "" });
    try {
      const payload = await deleteCustomer(deleteTarget.id, deleteConfirmation, platform.csrfToken);
      setDeleteTarget(null);
      setDeleteConfirmation("");
      await platform.refreshCustomers();
      setState({ busy: false, error: "", message: `${payload.deleted.name} and its tenant data were deleted.` });
    } catch (error) {
      setState({ busy: false, error: error.message, message: "" });
    }
  };

  return (
    <div className="grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <p className="mini-label">{editingId ? "Tenant Settings" : "New Tenant"}</p><h3 className="mt-1 text-2xl font-black text-white">{editingId ? "Edit tenant" : "Create tenant"}</h3>
        <p className="mt-2 text-sm font-semibold leading-6 text-slate-400">{editingId ? "Update the tenant identity and scanner scope policy." : "Every tenant receives an isolated dashboard, inventory, teams, and saved analysis history."}</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <AdminField label="Tenant name" required value={form.name} onChange={update("name")} placeholder="Example Industries" />
          <AdminField label="Tenant ID / slug" value={form.slug} onChange={update("slug")} placeholder="Auto-generated from name" />
          <label className="block"><span className="admin-label">Asset scope policy</span><select aria-label="Asset scope policy" value={form.assetScopeMode} onChange={update("assetScopeMode")} className="admin-input"><option value="observed">Combined known assets</option><option value="inventory">Approved inventory only</option></select></label>
          {editingId && <label className="block"><span className="admin-label">Tenant status</span><select aria-label="Tenant status" value={form.status} onChange={update("status")} className="admin-input"><option value="active">Active</option><option value="inactive">Inactive</option></select></label>}
          <label className="block"><span className="admin-label">Internal notes</span><textarea aria-label="Internal notes" value={form.notes} onChange={update("notes")} rows={4} className="admin-input resize-none" placeholder="Tenant context or operational notes" /></label>
          {state.error && <Notice error>{state.error}</Notice>}{state.message && <Notice>{state.message}</Notice>}
          <div className="flex gap-2">
            {editingId && <button type="button" onClick={cancelEdit} className="ghost-button flex flex-1 items-center justify-center gap-2"><X className="h-4 w-4" />Cancel</button>}
            <button disabled={state.busy} className="neon-button flex flex-1 items-center justify-center gap-2 disabled:opacity-50">{editingId ? <Save className="h-4 w-4" /> : <Building2 className="h-4 w-4" />}{state.busy ? "Saving..." : editingId ? "Save changes" : "Create tenant"}</button>
          </div>
        </form>
      </section>

      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <div className="flex items-baseline justify-between gap-3"><div><p className="mini-label">Tenant Directory</p><h3 className="mt-1 text-2xl font-black text-white">Managed tenants</h3></div><span className="font-mono text-xs font-bold text-slate-500">{platform.customers.length} total</span></div>
        <div className="mt-6 grid gap-3 lg:grid-cols-2">
          {platform.customers.map((customer) => (
            <article key={customer.id} className={`rounded-2xl border p-5 transition ${customer.id === platform.selectedCustomerId ? "border-red-400/35 bg-red-500/[0.06]" : "border-white/[0.08] bg-white/[0.025]"}`}>
              <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate text-lg font-black text-white">{customer.name}</p><p className="mt-1 truncate font-mono text-[0.65rem] font-semibold text-slate-600">{customer.slug}</p></div><span className={`rounded-full border px-2.5 py-1 text-[0.62rem] font-black uppercase ${customer.status === "active" ? "border-emerald-300/20 bg-emerald-400/10 text-emerald-300" : "border-slate-400/20 bg-slate-400/10 text-slate-400"}`}>{customer.status}</span></div>
              <div className="mt-5 grid grid-cols-2 gap-2"><SmallStat label="In-scope assets" value={customer.assetCount} /><SmallStat label="Reports" value={customer.scanCount} /></div>
              <p className="mt-3 text-xs font-semibold text-slate-500">Scope: <span className="font-black text-slate-300">{customer.assetScopeMode === "inventory" ? "Approved inventory only" : "Combined known assets"}</span></p>
              <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4"><button type="button" disabled={customer.status !== "active"} onClick={() => { platform.setSelectedCustomerId(customer.id); onOpenDashboard(); }} className="ghost-button px-3 py-2 text-xs disabled:cursor-not-allowed disabled:opacity-40">Dashboard</button><button type="button" onClick={() => { platform.setSelectedCustomerId(customer.id); onOpenAssets(); }} className="ghost-button px-3 py-2 text-xs">Assets</button><button type="button" onClick={() => beginEdit(customer)} className="ghost-button flex items-center justify-center gap-1 px-3 py-2 text-xs"><Pencil className="h-3.5 w-3.5" />Edit</button><button type="button" onClick={() => { setDeleteTarget(customer); setDeleteConfirmation(""); setState({ busy: false, error: "", message: "" }); }} className="ghost-button flex items-center justify-center gap-1 border-red-400/15 px-3 py-2 text-xs text-red-300 hover:border-red-400/30 hover:bg-red-500/[0.08]"><Trash2 className="h-3.5 w-3.5" />Delete</button></div>
            </article>
          ))}
          {!platform.customers.length && <div className="lg:col-span-2 rounded-2xl border border-dashed border-white/10 p-10 text-center text-sm font-semibold text-slate-600">No tenants yet. Create the first isolated workspace.</div>}
        </div>
      </section>
      {deleteTarget && <div className="fixed inset-0 z-[100] grid place-items-center bg-black/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="delete-tenant-title"><section className="w-full max-w-lg rounded-2xl border border-red-400/25 bg-[#111113] p-6 shadow-2xl"><div className="flex items-start gap-4"><span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-red-400/20 bg-red-500/[0.08]"><AlertTriangle className="h-5 w-5 text-red-300" /></span><div><p className="mini-label">Irreversible action</p><h3 id="delete-tenant-title" className="mt-1 text-xl font-extrabold text-white">Delete {deleteTarget.name}</h3><p className="mt-2 text-sm font-medium leading-6 text-slate-400">This permanently removes the tenant boundary, saved reports, findings, teams, memberships, and asset inventory. User accounts are retained but lose this tenant assignment.</p></div></div><label className="mt-5 block"><span className="admin-label">Type the exact tenant name to confirm</span><input autoFocus value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} placeholder={deleteTarget.name} className="admin-input" /></label>{state.error && <div className="mt-4"><Notice error>{state.error}</Notice></div>}<div className="mt-5 grid grid-cols-2 gap-3"><button type="button" disabled={state.busy} onClick={() => { setDeleteTarget(null); setDeleteConfirmation(""); setState({ busy: false, error: "", message: "" }); }} className="ghost-button">Cancel</button><button type="button" disabled={state.busy || deleteConfirmation !== deleteTarget.name} onClick={removeTenant} className="primary-button bg-red-700 disabled:cursor-not-allowed disabled:opacity-35">{state.busy ? "Deleting tenant..." : "Permanently delete"}</button></div></section></div>}
    </div>
  );
}

function TeamsTab({ platform, onOpenAssets }) {
  const customer = platform.selectedCustomer;
  const emptyForm = { name: "", code: "", description: "" };
  const [teams, setTeams] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState("");
  const [state, setState] = useState({ busy: false, error: "", message: "" });
  const update = (field) => (event) => setForm((current) => ({ ...current, [field]: event.target.value }));

  const load = async () => {
    if (!customer) return setTeams([]);
    try {
      const payload = await fetchCustomerTeams(customer.id);
      setTeams(payload.teams ?? []);
    } catch (error) {
      setState((current) => ({ ...current, error: error.message }));
    }
  };

  useEffect(() => {
    setEditingId("");
    setForm(emptyForm);
    setState({ busy: false, error: "", message: "" });
    load();
  }, [customer?.id]);

  const submit = async (event) => {
    event.preventDefault();
    if (!customer) return;
    setState({ busy: true, error: "", message: "" });
    try {
      const payload = editingId
        ? await updateCustomerTeam(customer.id, editingId, form, platform.csrfToken)
        : await createCustomerTeam(customer.id, form, platform.csrfToken);
      setEditingId("");
      setForm(emptyForm);
      await load();
      setState({ busy: false, error: "", message: `${payload.team.name} was ${editingId ? "updated" : "created"}.` });
    } catch (error) {
      setState({ busy: false, error: error.message, message: "" });
    }
  };

  const beginEdit = (team) => {
    setEditingId(team.id);
    setForm({ name: team.name, code: team.code, description: team.description ?? "" });
    setState({ busy: false, error: "", message: "" });
  };

  if (!customer) return <EmptyAdmin label="Create or select a tenant before defining operational teams." />;

  return (
    <div className="grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <p className="mini-label">{customer.name}</p>
        <h3 className="mt-1 text-2xl font-black text-white">{editingId ? "Edit operational team" : "Create operational team"}</h3>
        <p className="mt-2 text-sm font-semibold leading-6 text-slate-400">Teams are ownership groups such as Linux Operations or Network Engineering. Assign assets to them without creating another login.</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <AdminField label="Team name" required value={form.name} onChange={update("name")} placeholder="Linux Operations" />
          <AdminField label="Team code" value={form.code} onChange={update("code")} placeholder="Auto-generated from name" />
          <label className="block"><span className="admin-label">Responsibility</span><textarea aria-label="Team responsibility" value={form.description} onChange={update("description")} rows={4} className="admin-input resize-none" placeholder="Owns Linux servers and associated remediation." /></label>
          {state.error && <Notice error>{state.error}</Notice>}{state.message && <Notice>{state.message}</Notice>}
          <div className="flex gap-2">
            {editingId && <button type="button" onClick={() => { setEditingId(""); setForm(emptyForm); }} className="ghost-button flex flex-1 items-center justify-center gap-2"><X className="h-4 w-4" />Cancel</button>}
            <button disabled={state.busy} className="neon-button flex flex-1 items-center justify-center gap-2 disabled:opacity-50"><UsersRound className="h-4 w-4" />{state.busy ? "Saving..." : editingId ? "Save team" : "Create team"}</button>
          </div>
        </form>
      </section>

      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <div className="flex flex-wrap items-end justify-between gap-3"><div><p className="mini-label">Ownership Directory</p><h3 className="mt-1 text-2xl font-black text-white">Responsible teams</h3></div><button type="button" onClick={onOpenAssets} className="ghost-button px-4 py-2.5 text-sm">Assign assets</button></div>
        <div className="mt-6 grid gap-3 lg:grid-cols-2">
          {teams.map((team) => <article key={team.id} className="rounded-2xl border border-white/[0.08] bg-white/[0.025] p-5"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate text-base font-black text-white">{team.name}</p><p className="mt-1 font-mono text-[0.65rem] font-bold uppercase text-red-300">{team.code}</p></div><button type="button" aria-label={`Edit ${team.name}`} onClick={() => beginEdit(team)} className="grid h-9 w-9 place-items-center rounded-xl border border-white/10 text-slate-500 transition hover:border-red-400/30 hover:text-white"><Pencil className="h-4 w-4" /></button></div><p className="mt-3 min-h-10 text-xs font-semibold leading-5 text-slate-500">{team.description || "No responsibility note provided."}</p><div className="mt-4 grid grid-cols-2 gap-2"><SmallStat label="Assigned assets" value={team.assetCount} /><SmallStat label="In scope" value={team.inScopeAssetCount} /></div></article>)}
          {!teams.length && <div className="lg:col-span-2"><EmptyAdmin label="No operational teams yet. Create a team, then assign tenant assets to it." /></div>}
        </div>
      </section>
    </div>
  );
}

export function AssetInventoryWorkspace({ platform, onOpenValidation }) {
  const customer = platform.selectedCustomer;
  const [assets, setAssets] = useState([]);
  const [teams, setTeams] = useState([]);
  const [scanCoverage, setScanCoverage] = useState(null);
  const [defaultOnboardingTool, setDefaultOnboardingTool] = useState("");
  const [defaultAssetType, setDefaultAssetType] = useState("");
  const [defaultOs, setDefaultOs] = useState("");
  const [singleAsset, setSingleAsset] = useState({ ipAddress: "", dnsName: "", hostName: "" });
  const [pasteText, setPasteText] = useState("");
  const [teamName, setTeamName] = useState("");
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [selectedAssetIds, setSelectedAssetIds] = useState(() => new Set());
  const [deleteTargetIds, setDeleteTargetIds] = useState([]);
  const [editTarget, setEditTarget] = useState(null);
  const [editForm, setEditForm] = useState({ ipAddress: "", dnsName: "", hostName: "", onboardingTool: "manual", assetType: "Other", teamId: "", platform: "" });
  const [page, setPage] = useState(1);
  const [state, setState] = useState({ loading: false, error: "", message: "" });
  const canManageAssets = platform.user?.globalRole === "system_admin" || ["owner", "analyst"].includes(customer?.membershipRole);

  const load = async () => {
    if (!customer) {
      setAssets([]);
      setTeams([]);
      setScanCoverage(null);
      return;
    }
    setState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const [assetPayload, teamPayload, coveragePayload] = await Promise.all([
        fetchCustomerAssets(customer.id, { limit: 100_000, timeoutMs: 60_000 }),
        fetchCustomerTeams(customer.id),
        fetchCustomerScanAssetCoverage(customer.id),
      ]);
      const nextAssets = assetPayload.assets ?? [];
      setAssets(nextAssets);
      setTeams(teamPayload.teams ?? []);
      setScanCoverage(coveragePayload.coverage ?? null);
      setSelectedAssetIds((current) => new Set([...current].filter((id) => nextAssets.some((asset) => asset.id === id))));
      setState((current) => ({ ...current, loading: false }));
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  useEffect(() => {
    setDefaultOnboardingTool("");
    setDefaultAssetType("");
    setDefaultOs("");
    setSingleAsset({ ipAddress: "", dnsName: "", hostName: "" });
    setPasteText("");
    setTeamName("");
    setShowOnboarding(false);
    setDragActive(false);
    setSearch("");
    setSelectedAssetIds(new Set());
    setDeleteTargetIds([]);
    setEditTarget(null);
    setPage(1);
    load();
  }, [customer?.id]);

  useEffect(() => setPage(1), [deferredSearch]);

  const ensureOwners = async (parsed) => {
    let availableTeams = [...teams];
    const knownNames = new Map(availableTeams.map((team) => [team.name.trim().toLowerCase(), team]));
    const missingNames = [...new Set(parsed.map((asset) => asset.responsibleTeam?.trim()).filter(Boolean))]
      .filter((name) => !knownNames.has(name.toLowerCase()));
    for (const name of missingNames) {
      const payload = await createCustomerTeam(customer.id, { name, description: "Team created during asset onboarding." }, platform.csrfToken);
      availableTeams.push(payload.team);
      knownNames.set(name.toLowerCase(), payload.team);
    }
    setTeams(availableTeams);
    return knownNames;
  };

  const saveAssets = async (parsed, sourceLabel) => {
    if (!customer || !canManageAssets) return;
    setState({ loading: true, error: "", message: `Validating ${sourceLabel}...` });
    try {
      const prepared = parsed.map((asset) => ({ ...asset, responsibleTeam: asset.responsibleTeam || teamName.trim() }));
      const knownOwners = await ensureOwners(prepared);
      const assetsWithOwnership = prepared.map(({ responsibleTeam, ...asset }) => ({
        ...asset,
        teamId: responsibleTeam ? knownOwners.get(responsibleTeam.trim().toLowerCase())?.id ?? null : null,
      }));
      const result = await importCustomerAssets(customer.id, assetsWithOwnership, platform.csrfToken);
      await platform.refreshCustomers({ selectCustomerId: customer.id });
      await load();
      setState({ loading: false, error: "", message: `${result.count.toLocaleString()} asset${result.count === 1 ? "" : "s"} added or updated from ${sourceLabel}.` });
      return true;
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
      return false;
    }
  };

  const importInventoryFile = async (file) => {
    if (!file || !customer) return;
    try {
      if (!/\.(csv|xlsx)$/i.test(file.name)) throw new Error("Upload a CSV or XLSX asset inventory.");
      if (!defaultOnboardingTool) throw new Error("Select the Platform / Tool before importing assets.");
      const parsed = await parseAssetInventory(file, { defaultAssetType, defaultOnboardingTool, defaultPlatform: defaultOs });
      await saveAssets(parsed, file.name);
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  const importFile = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    await importInventoryFile(file);
  };

  const dropInventory = async (event) => {
    event.preventDefault();
    setDragActive(false);
    await importInventoryFile(event.dataTransfer.files?.[0]);
  };

  const importPasted = async () => {
    try {
      if (!defaultOnboardingTool) throw new Error("Select the Platform / Tool before adding assets.");
      const parsed = parsePastedAssetInventory(pasteText, { defaultAssetType, defaultOnboardingTool, defaultPlatform: defaultOs });
      if (await saveAssets(parsed, "the pasted list")) setPasteText("");
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  const addSingleAsset = async () => {
    try {
      if (!defaultOnboardingTool) throw new Error("Select the Platform / Tool before adding an asset.");
      const asset = normalizeAssetRow({
        "IP Address": singleAsset.ipAddress,
        "DNS Name": singleAsset.dnsName,
        "Host Name": singleAsset.hostName,
        "Responsible Team": teamName,
      }, { defaultAssetType, defaultOnboardingTool, defaultPlatform: defaultOs });
      if (!asset) throw new Error("Enter an IP address, DNS name, or host name.");
      if (await saveAssets([asset], "manual entry")) setSingleAsset({ ipAddress: "", dnsName: "", hostName: "" });
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  const beginEdit = (asset) => {
    setEditTarget(asset);
    setEditForm({
      ipAddress: asset.ipAddress ?? "",
      dnsName: asset.dnsName ?? "",
      hostName: asset.hostName ?? "",
      onboardingTool: asset.onboardingTool ?? "manual",
      assetType: asset.assetType ?? "Other",
      teamId: asset.teamId ?? "",
      platform: asset.platform ?? "",
    });
    setState((current) => ({ ...current, error: "", message: "" }));
  };

  const saveEdit = async () => {
    if (!editTarget) return;
    setState({ loading: true, error: "", message: "Saving asset..." });
    try {
      const payload = await updateCustomerAsset(customer.id, editTarget.id, {
        ...editForm,
        assetType: normalizeAssetType(editForm.assetType, editForm.platform),
        teamId: editForm.teamId || null,
      }, platform.csrfToken);
      setAssets((current) => current.map((item) => item.id === editTarget.id ? payload.asset : item));
      setEditTarget(null);
      setState({ loading: false, error: "", message: "Asset details updated." });
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  const toggleSelected = (assetId) => setSelectedAssetIds((current) => {
    const next = new Set(current);
    if (next.has(assetId)) next.delete(assetId);
    else next.add(assetId);
    return next;
  });

  const confirmDelete = (assetIds) => {
    setDeleteTargetIds(assetIds);
    setState((current) => ({ ...current, error: "", message: "" }));
  };

  const removeAssets = async () => {
    if (!deleteTargetIds.length) return;
    setState({ loading: true, error: "", message: "Deleting selected assets..." });
    try {
      const result = await deleteCustomerAssets(customer.id, deleteTargetIds, platform.csrfToken);
      const deleted = new Set(deleteTargetIds);
      setAssets((current) => current.filter((asset) => !deleted.has(asset.id)));
      setSelectedAssetIds((current) => new Set([...current].filter((id) => !deleted.has(id))));
      setDeleteTargetIds([]);
      await platform.refreshCustomers({ selectCustomerId: customer.id });
      await load();
      setState({ loading: false, error: "", message: `${result.count.toLocaleString()} asset${result.count === 1 ? "" : "s"} deleted from the database.` });
    } catch (error) {
      setState({ loading: false, error: error.message, message: "" });
    }
  };

  const downloadTemplate = () => {
    const url = URL.createObjectURL(new Blob([assetInventoryTemplateCsv()], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "MVA_Customer_Asset_Inventory_Template.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const searchTerms = deferredSearch.toLowerCase().split(/[,;\n]+/).map((term) => term.trim()).filter(Boolean);
  const visibleAssets = searchTerms.length
    ? assets.filter((asset) => {
      const searchable = [asset.assetKey, asset.ipAddress, asset.dnsName, asset.hostName, onboardingToolLabel(asset.onboardingTool), asset.assetType, asset.teamName, asset.platform]
        .map((value) => String(value ?? "").toLowerCase()).join(" ");
      return searchTerms.some((term) => searchable.includes(term));
    })
    : assets;
  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(visibleAssets.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageAssets = visibleAssets.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const allPageSelected = pageAssets.length > 0 && pageAssets.every((asset) => selectedAssetIds.has(asset.id));

  const togglePage = () => setSelectedAssetIds((current) => {
    const next = new Set(current);
    if (allPageSelected) pageAssets.forEach((asset) => next.delete(asset.id));
    else pageAssets.forEach((asset) => next.add(asset.id));
    return next;
  });

  if (!customer) return <EmptyAdmin label="Create or select a tenant before importing assets." />;
  if (!canManageAssets) return <EmptyAdmin label="Analyst or owner access is required to manage tenant assets." />;

  return (
    <div className="space-y-4">
      <section className="enterprise-panel p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="mini-label">{customer.name}</p>
            <h2 className="mt-2 text-2xl font-extrabold tracking-tight text-white">Asset Inventory</h2>
            <p className="mt-2 max-w-3xl text-sm font-medium text-slate-400">Manage the tenant's IPs, names, vulnerability tools, responsible teams, and operating systems.</p>
          </div>
          <button type="button" onClick={() => setShowOnboarding((current) => !current)} aria-expanded={showOnboarding} className="primary-button flex items-center gap-2"><Plus className="h-4 w-4" />Add assets<ChevronDown className={`h-4 w-4 transition ${showOnboarding ? "rotate-180" : ""}`} /></button>
        </div>
        {showOnboarding && <div className="mt-6 border-t border-white/[0.08] pt-6">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label><span className="admin-label">Platform / Tool</span><select aria-label="Asset platform or tool" value={defaultOnboardingTool} onChange={(event) => setDefaultOnboardingTool(event.target.value)} className="admin-input"><option value="">Select vulnerability tool</option>{ASSET_ONBOARDING_TOOLS.filter((tool) => tool.id !== "multi-tool").map((tool) => <option key={tool.id} value={tool.id}>{tool.label}</option>)}</select></label>
            <label><span className="admin-label">Responsible team</span><input aria-label="Responsible team" list="mva-team-options" value={teamName} onChange={(event) => setTeamName(event.target.value)} placeholder="Type or select a team" className="admin-input" /><datalist id="mva-team-options">{teams.map((team) => <option key={team.id} value={team.name} />)}</datalist></label>
            <label><span className="admin-label">Asset type</span><input aria-label="Default asset type" list="mva-asset-type-options" value={defaultAssetType} onChange={(event) => setDefaultAssetType(event.target.value)} placeholder="Linux Server, Network Device..." className="admin-input" /><datalist id="mva-asset-type-options">{ASSET_TYPES.map((assetType) => <option key={assetType} value={assetType} />)}</datalist></label>
            <label><span className="admin-label">Operating system (optional)</span><input aria-label="Default operating system" value={defaultOs} onChange={(event) => setDefaultOs(event.target.value)} placeholder="Ubuntu 24.04 or Windows Server 2022" className="admin-input" /></label>
          </div>
          <p className="mt-3 text-xs font-medium text-slate-500">Typed Team and Asset Type values are applied to rows that do not provide their own values. A new team is created automatically when the upload is saved.</p>

          <div className="mt-5 grid gap-4 xl:grid-cols-2">
            <div className="rounded-2xl border border-white/[0.08] bg-black/20 p-4">
              <p className="text-sm font-extrabold text-white">Add one asset</p><p className="mt-1 text-xs font-medium text-slate-500">Enter an IP, DNS name, or host name. All imported tenant assets are active inventory.</p>
              <div className="mt-4 grid gap-2 sm:grid-cols-3"><input aria-label="Asset IP address" value={singleAsset.ipAddress} onChange={(event) => setSingleAsset((current) => ({ ...current, ipAddress: event.target.value }))} placeholder="IP address" className="admin-input" /><input aria-label="Asset DNS name" value={singleAsset.dnsName} onChange={(event) => setSingleAsset((current) => ({ ...current, dnsName: event.target.value }))} placeholder="DNS name" className="admin-input" /><input aria-label="Asset host name" value={singleAsset.hostName} onChange={(event) => setSingleAsset((current) => ({ ...current, hostName: event.target.value }))} placeholder="Host name" className="admin-input" /></div>
              <button type="button" disabled={state.loading || !Object.values(singleAsset).some((value) => value.trim())} onClick={addSingleAsset} className="primary-button mt-3 flex items-center gap-2 disabled:opacity-40"><Plus className="h-4 w-4" />Add asset</button>
            </div>
            <div className="rounded-2xl border border-white/[0.08] bg-black/20 p-4">
              <div className="flex items-start justify-between gap-3"><div><p className="text-sm font-extrabold text-white">Upload asset inventory</p><p className="mt-1 text-xs font-medium text-slate-500">CSV or XLSX: Tool, Asset Type, IP, DNS, Host Name, Team, and OS.</p></div><FileSpreadsheet className="h-5 w-5 text-red-300" /></div>
              <label onDragEnter={(event) => { event.preventDefault(); setDragActive(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setDragActive(false); }} onDrop={dropInventory} className={`mt-4 flex min-h-28 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-4 py-5 text-center transition ${dragActive ? "border-red-400/60 bg-red-500/[0.10]" : "border-white/[0.14] bg-white/[0.025] hover:border-red-400/35 hover:bg-red-500/[0.04]"}`}><FileSpreadsheet className="h-6 w-6 text-red-300" /><span className="mt-2 text-sm font-extrabold text-white">Drop CSV/XLSX here or browse</span><span className="mt-1 text-xs font-medium text-slate-500">One inventory file at a time</span><input type="file" accept=".csv,.xlsx" onChange={importFile} className="sr-only" /></label>
              <button type="button" onClick={downloadTemplate} className="secondary-button mt-3 flex items-center gap-2"><Download className="h-4 w-4" />Download template</button>
            </div>
          </div>
          <details className="mt-4 rounded-2xl border border-white/[0.08] bg-black/15 p-4"><summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-extrabold text-slate-300"><ClipboardPaste className="h-4 w-4 text-red-300" />Paste multiple assets</summary><p className="mt-3 text-xs font-medium text-slate-500">One line each: IP, Host Name, Team Name, OS Name. Unknown teams are created automatically.</p><textarea aria-label="Paste multiple assets" value={pasteText} onChange={(event) => setPasteText(event.target.value)} rows={5} placeholder={"10.20.1.10, web-prod-01, Linux Operations, Ubuntu 24.04\n10.20.1.11, db-prod-01, Database Operations, RHEL 9"} className="admin-input mt-3 resize-y font-mono text-xs leading-6" /><button type="button" disabled={!pasteText.trim() || state.loading} onClick={importPasted} className="primary-button mt-3 flex items-center gap-2 disabled:opacity-40"><Plus className="h-4 w-4" />Add pasted assets</button></details>
        </div>}
        {state.error && <div className="mt-4"><Notice error>{state.error}</Notice></div>}{state.message && <div className="mt-4"><Notice>{state.message}</Notice></div>}
      </section>

      <AssetValidationSummary
        inventoryCount={assets.length}
        coverage={scanCoverage}
        onOpenValidation={onOpenValidation}
      />

      <section className="enterprise-panel p-5 sm:p-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div><p className="mini-label">Inventory records</p><h3 className="mt-2 text-xl font-extrabold text-white">{assets.length.toLocaleString()} asset{assets.length === 1 ? "" : "s"}</h3><p className="mt-1 text-xs font-medium text-slate-500">{visibleAssets.length.toLocaleString()} shown{selectedAssetIds.size ? ` / ${selectedAssetIds.size.toLocaleString()} selected` : ""}</p></div>
          <div className="flex flex-wrap items-end gap-2">{selectedAssetIds.size > 0 && <button type="button" onClick={() => confirmDelete([...selectedAssetIds])} className="secondary-button flex items-center gap-2 border-red-400/25 text-red-200"><Trash2 className="h-4 w-4" />Delete selected ({selectedAssetIds.size})</button>}<label className="relative block min-w-72"><span className="sr-only">Search one or multiple assets</span><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search multiple IPs or names, separated by commas" className="admin-input pl-10" /></label></div>
        </div>
        <div className="mt-5 overflow-x-auto"><table className="enterprise-table min-w-[1080px]"><thead><tr><th className="w-12"><input type="checkbox" aria-label="Select all assets on this page" checked={allPageSelected} onChange={togglePage} className="h-4 w-4 accent-red-500" /></th><th>IP address</th><th>DNS / Host name</th><th>Platform / Tool</th><th>Asset type</th><th>Responsible team</th><th>Operating system</th><th className="w-28 text-right">Actions</th></tr></thead><tbody>{pageAssets.map((asset) => <tr key={asset.id} className={selectedAssetIds.has(asset.id) ? "bg-red-500/[0.035]" : ""}><td><input type="checkbox" aria-label={`Select ${asset.dnsName || asset.hostName || asset.ipAddress || asset.assetKey}`} checked={selectedAssetIds.has(asset.id)} onChange={() => toggleSelected(asset.id)} className="h-4 w-4 accent-red-500" /></td><td className="font-mono text-xs font-bold text-slate-300">{asset.ipAddress || "-"}</td><td><p className="font-bold text-white">{asset.dnsName || asset.hostName || "-"}</p>{asset.dnsName && asset.hostName && asset.dnsName !== asset.hostName && <p className="mt-1 text-[0.66rem] text-slate-600">{asset.hostName}</p>}</td><td><span className="rounded-lg border border-red-400/15 bg-red-500/[0.06] px-2.5 py-1 text-xs font-bold text-red-100">{onboardingToolLabel(asset.onboardingTool)}</span></td><td className="font-semibold text-slate-300">{asset.assetType || "Other"}</td><td className="font-semibold text-slate-300">{asset.teamName || "Unassigned"}</td><td>{asset.platform || "-"}</td><td><div className="flex justify-end gap-1"><button type="button" aria-label={`Edit ${asset.dnsName || asset.hostName || asset.ipAddress}`} onClick={() => beginEdit(asset)} className="grid h-9 w-9 place-items-center rounded-lg border border-white/10 text-slate-400 transition hover:border-red-400/25 hover:text-white"><Pencil className="h-4 w-4" /></button><button type="button" aria-label={`Delete ${asset.dnsName || asset.hostName || asset.ipAddress}`} onClick={() => confirmDelete([asset.id])} className="grid h-9 w-9 place-items-center rounded-lg border border-red-400/15 text-red-300 transition hover:border-red-400/35 hover:bg-red-500/[0.08]"><Trash2 className="h-4 w-4" /></button></div></td></tr>)}</tbody></table>{!visibleAssets.length && !state.loading && <EmptyAdmin label={assets.length ? "No assets match this search." : "No assets yet. Select Add assets to begin."} />}</div>
        {visibleAssets.length > 0 && <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.07] pt-4"><p className="text-xs font-semibold text-slate-500">Showing {((currentPage - 1) * pageSize + 1).toLocaleString()}-{Math.min(currentPage * pageSize, visibleAssets.length).toLocaleString()} of {visibleAssets.length.toLocaleString()}</p><div className="flex items-center gap-2"><button type="button" aria-label="Previous asset page" disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))} className="secondary-button px-3 disabled:opacity-30"><ChevronLeft className="h-4 w-4" /></button><span className="min-w-24 text-center text-xs font-bold text-slate-400">Page {currentPage} of {pageCount}</span><button type="button" aria-label="Next asset page" disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))} className="secondary-button px-3 disabled:opacity-30"><ChevronRight className="h-4 w-4" /></button></div></div>}
      </section>

      {editTarget && <div className="fixed inset-0 z-[100] grid place-items-center bg-black/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="edit-asset-title"><section className="w-full max-w-2xl rounded-2xl border border-white/10 bg-[#111113] p-6 shadow-2xl"><div className="flex items-start justify-between gap-4"><div><p className="mini-label">Asset Inventory</p><h3 id="edit-asset-title" className="mt-1 text-xl font-extrabold text-white">Edit asset</h3><p className="mt-2 text-sm font-medium text-slate-500">Only the core inventory fields are required.</p></div><button type="button" aria-label="Close asset editor" onClick={() => setEditTarget(null)} className="grid h-9 w-9 place-items-center rounded-lg border border-white/10 text-slate-400"><X className="h-4 w-4" /></button></div><div className="mt-5 grid gap-3 sm:grid-cols-2"><AdminField label="IP address" value={editForm.ipAddress} onChange={(event) => setEditForm((current) => ({ ...current, ipAddress: event.target.value }))} /><AdminField label="DNS name" value={editForm.dnsName} onChange={(event) => setEditForm((current) => ({ ...current, dnsName: event.target.value }))} /><AdminField label="Host name" value={editForm.hostName} onChange={(event) => setEditForm((current) => ({ ...current, hostName: event.target.value }))} /><label><span className="admin-label">Platform / Tool</span><select aria-label="Edit asset platform or tool" value={editForm.onboardingTool} onChange={(event) => setEditForm((current) => ({ ...current, onboardingTool: event.target.value }))} className="admin-input">{ASSET_ONBOARDING_TOOLS.map((tool) => <option key={tool.id} value={tool.id}>{tool.label}</option>)}</select></label><label><span className="admin-label">Asset type</span><input aria-label="Edit asset type" list="mva-asset-type-options" value={editForm.assetType} onChange={(event) => setEditForm((current) => ({ ...current, assetType: event.target.value }))} className="admin-input" /></label><label><span className="admin-label">Responsible team</span><select aria-label="Edit responsible team" value={editForm.teamId} onChange={(event) => setEditForm((current) => ({ ...current, teamId: event.target.value }))} className="admin-input"><option value="">Unassigned</option>{teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}</select></label><AdminField label="Operating system (optional)" value={editForm.platform} onChange={(event) => setEditForm((current) => ({ ...current, platform: event.target.value }))} /></div>{state.error && <div className="mt-4"><Notice error>{state.error}</Notice></div>}<div className="mt-6 grid grid-cols-2 gap-3"><button type="button" disabled={state.loading} onClick={() => setEditTarget(null)} className="secondary-button">Cancel</button><button type="button" disabled={state.loading || ![editForm.ipAddress, editForm.dnsName, editForm.hostName].some((value) => value.trim())} onClick={saveEdit} className="primary-button flex items-center justify-center gap-2 disabled:opacity-35"><Save className="h-4 w-4" />{state.loading ? "Saving..." : "Save asset"}</button></div></section></div>}

      {deleteTargetIds.length > 0 && <div className="fixed inset-0 z-[100] grid place-items-center bg-black/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="delete-assets-title"><section className="w-full max-w-lg rounded-2xl border border-red-400/25 bg-[#111113] p-6 shadow-2xl"><div className="flex items-start gap-4"><span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-red-400/20 bg-red-500/[0.08]"><AlertTriangle className="h-5 w-5 text-red-300" /></span><div><p className="mini-label">Confirm deletion</p><h3 id="delete-assets-title" className="mt-1 text-xl font-extrabold text-white">Delete {deleteTargetIds.length.toLocaleString()} asset{deleteTargetIds.length === 1 ? "" : "s"}?</h3><p className="mt-2 text-sm font-medium leading-6 text-slate-400">The selected inventory records will be permanently removed. Their vulnerabilities will immediately leave active dashboards and exports; historical scan evidence remains available for audit.</p></div></div>{state.error && <div className="mt-4"><Notice error>{state.error}</Notice></div>}<div className="mt-6 grid grid-cols-2 gap-3"><button type="button" disabled={state.loading} onClick={() => setDeleteTargetIds([])} className="secondary-button">Cancel</button><button type="button" disabled={state.loading} onClick={removeAssets} className="primary-button flex items-center justify-center gap-2 bg-red-700"><Trash2 className="h-4 w-4" />{state.loading ? "Deleting..." : "Delete assets"}</button></div></section></div>}
    </div>
  );
}

function AssetValidationSummary({ inventoryCount, coverage, onOpenValidation }) {
  const matched = Number(coverage?.matchedInventoryAssets ?? 0);
  const notObserved = Math.max(0, inventoryCount - matched);
  const hasScan = Boolean(coverage?.available);
  return (
    <section className="enterprise-panel p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">Asset validation</p>
          <h3 className="mt-2 text-xl font-extrabold text-white">Inventory and latest scan alignment</h3>
          <p className="mt-2 max-w-3xl text-xs font-medium leading-5 text-slate-500">Saved scanner evidence is matched to this tenant’s inventory by unambiguous IP or DNS identity. Add host-discovery exports in the full validation workspace to separate unreachable assets from scanner coverage gaps.</p>
        </div>
        {onOpenValidation && <button type="button" onClick={onOpenValidation} className="secondary-button">Open three-layer validation</button>}
      </div>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <ValidationMetric label="Inventory assets" value={inventoryCount} tone="text-white" />
        <ValidationMetric label="Scan identities" value={hasScan ? coverage.observedScanIdentities : 0} tone="text-sky-300" />
        <ValidationMetric label="Matched inventory" value={matched} tone="text-emerald-300" />
        <ValidationMetric label="Not in latest scan" value={notObserved} tone={notObserved ? "text-amber-200" : "text-emerald-300"} />
        <ValidationMetric label="Unmanaged scan identities" value={hasScan ? coverage.unmatchedScanIdentities : 0} tone="text-red-300" />
      </div>
      <p className="mt-4 rounded-xl border border-white/[0.07] bg-black/20 px-4 py-3 text-xs font-semibold text-slate-500">
        {hasScan
          ? `Latest saved evidence: ${coverage.sourceLabel || coverage.sourceTool || "Scanner data"} · ${coverage.reportPeriod || "Current period"}. Ambiguous identities: ${Number(coverage.ambiguousScanIdentities ?? 0).toLocaleString()}.`
          : "No finalized scanner analysis is saved for this tenant yet. Analyze and save a report to populate scan validation."}
      </p>
    </section>
  );
}

function ValidationMetric({ label, value, tone }) {
  return <article className="rounded-2xl border border-white/[0.07] bg-black/20 p-4"><p className="font-mono text-[0.58rem] font-bold uppercase tracking-[0.1em] text-slate-600">{label}</p><p className={`mt-2 text-2xl font-extrabold ${tone}`}>{Number(value ?? 0).toLocaleString()}</p></article>;
}

function UsersTab({ platform }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ fullName: "", email: "", password: "", globalRole: "customer_user", customerId: platform.selectedCustomerId, membershipRole: "analyst", assetTypes: [] });
  const [state, setState] = useState({ busy: false, error: "", message: "" });

  const load = async () => {
    try { setUsers((await fetchUsers()).users ?? []); } catch (error) { setState((current) => ({ ...current, error: error.message })); }
  };
  useEffect(() => { load(); }, []);
  useEffect(() => { if (!form.customerId && platform.selectedCustomerId) setForm((current) => ({ ...current, customerId: platform.selectedCustomerId })); }, [platform.selectedCustomerId]);
  const update = (field) => (event) => setForm((current) => ({ ...current, [field]: event.target.value }));
  const toggleAssetType = (assetType) => setForm((current) => ({ ...current, assetTypes: current.assetTypes.includes(assetType) ? current.assetTypes.filter((item) => item !== assetType) : [...current.assetTypes, assetType] }));

  const submit = async (event) => {
    event.preventDefault();
    setState({ busy: true, error: "", message: "" });
    try {
      const memberships = form.globalRole === "system_admin" ? [] : [{ customerId: form.customerId, role: form.membershipRole, assetTypes: form.assetTypes }];
      await createUser({ fullName: form.fullName, email: form.email, password: form.password, globalRole: form.globalRole, memberships }, platform.csrfToken);
      setForm((current) => ({ ...current, fullName: "", email: "", password: "", membershipRole: "analyst", assetTypes: [] }));
      await load();
      setState({ busy: false, error: "", message: "User account created." });
    } catch (error) { setState({ busy: false, error: error.message, message: "" }); }
  };

  return (
    <div className="grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6">
        <p className="mini-label">Controlled Provisioning</p><h3 className="mt-1 text-2xl font-black text-white">Create user</h3><p className="mt-2 text-sm font-semibold text-slate-400">New tenant accounts default to Analyst so they can onboard assets, assign owners, analyze scanner data, and export scoped findings.</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <AdminField label="Full name" required value={form.fullName} onChange={update("fullName")} /><AdminField label="Work email" type="email" required value={form.email} onChange={update("email")} /><AdminField label="Temporary password" type="password" required minLength={12} value={form.password} onChange={update("password")} />
          <label className="block"><span className="admin-label">Platform role</span><select aria-label="Platform role" className="admin-input" value={form.globalRole} onChange={update("globalRole")}><option value="customer_user">Tenant user</option><option value="system_admin">System administrator</option></select></label>
          {form.globalRole === "customer_user" && <><div className="grid grid-cols-[1fr_130px] gap-2"><label><span className="admin-label">Tenant</span><select aria-label="Tenant assignment" required className="admin-input" value={form.customerId} onChange={update("customerId")}><option value="">Select</option>{platform.customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}</select></label><label><span className="admin-label">Access</span><select aria-label="Tenant access role" className="admin-input" value={form.membershipRole} onChange={update("membershipRole")}><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="owner">Owner</option></select></label></div><fieldset><legend className="admin-label">Asset category scope</legend><p className="mb-2 text-[0.68rem] font-semibold leading-5 text-slate-600">Leave all unselected for complete tenant access, or choose one or more asset categories.</p><div className="flex flex-wrap gap-1.5">{ASSET_TYPES.map((assetType) => <button key={assetType} type="button" aria-pressed={form.assetTypes.includes(assetType)} onClick={() => toggleAssetType(assetType)} className={`rounded-lg border px-2.5 py-2 text-[0.68rem] font-black transition ${form.assetTypes.includes(assetType) ? "border-cyan-300/30 bg-cyan-400/10 text-cyan-200" : "border-white/[0.08] bg-white/[0.025] text-slate-600 hover:text-white"}`}>{assetType}</button>)}</div><p className="mt-2 text-xs font-bold text-slate-400">{form.assetTypes.length ? `Limited to: ${form.assetTypes.join(", ")}` : "All asset types"}</p></fieldset></>}
          {state.error && <Notice error>{state.error}</Notice>}{state.message && <Notice>{state.message}</Notice>}<button disabled={state.busy} className="neon-button flex w-full items-center justify-center gap-2 disabled:opacity-50"><UserPlus className="h-4 w-4" />{state.busy ? "Creating..." : "Create user"}</button>
        </form>
      </section>
      <section className="cyber-panel rounded-[1.75rem] p-5 sm:p-6"><div className="flex items-baseline justify-between"><div><p className="mini-label">Access Directory</p><h3 className="mt-1 text-2xl font-black text-white">Platform users</h3></div><span className="font-mono text-xs font-bold text-slate-500">{users.length} accounts</span></div><div className="mt-6 space-y-2">{users.map((user) => <article key={user.id} className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/[0.08] bg-white/[0.025] p-4"><div><p className="text-sm font-black text-white">{user.fullName}</p><p className="mt-1 text-xs font-semibold text-slate-500">{user.email}</p>{user.memberships?.flatMap((membership) => membership.assetTypes ?? []).length > 0 && <p className="mt-2 text-[0.68rem] font-bold text-cyan-300">{user.memberships.flatMap((membership) => membership.assetTypes ?? []).join(", ")}</p>}</div><div className="text-right"><p className="text-xs font-black uppercase text-red-300">{user.globalRole.replace("_", " ")}</p><p className="mt-1 text-[0.68rem] font-semibold text-slate-600">{user.memberships?.length ? `${user.memberships.length} tenant assignment(s)` : "Platform-wide"}</p></div></article>)}</div></section>
    </div>
  );
}

function AdminField({ label, ...props }) { return <label className="block"><span className="admin-label">{label}</span><input {...props} className="admin-input" /></label>; }
function Notice({ error = false, children }) { return <p role={error ? "alert" : undefined} className={`rounded-xl border px-4 py-3 text-xs font-bold ${error ? "border-red-400/25 bg-red-500/10 text-red-100" : "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200"}`}>{children}</p>; }
function SmallStat({ label, value = 0 }) { return <div className="rounded-xl border border-white/[0.07] bg-black/20 p-3"><p className="font-mono text-[0.58rem] font-bold uppercase text-slate-600">{label}</p><p className="mt-1 text-xl font-black text-white">{Number(value).toLocaleString()}</p></div>; }
function EmptyAdmin({ label }) { return <div className="rounded-2xl border border-dashed border-white/10 p-10 text-center text-sm font-semibold text-slate-600">{label}</div>; }
