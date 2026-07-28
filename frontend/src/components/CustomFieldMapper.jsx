import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, ChevronDown, FileCog, TriangleAlert } from "lucide-react";

import {
  autoMapCustomHeaders,
  CUSTOM_FIELD_DEFINITIONS,
  parseExportFile,
  validateCustomFieldMapping,
} from "../lib/vulnerabilityEngine.jsx";

const INITIAL_CONFIG = {
  mapping: {},
  severityScale: "auto",
  exploitMode: "boolean",
  fileName: "",
  fields: [],
};

export function CustomFieldMapper({ files = [], value = INITIAL_CONFIG, onChange }) {
  const [inspection, setInspection] = useState({ state: "idle", message: "Add a custom CSV or XLSX file to inspect its headers." });
  const config = { ...INITIAL_CONFIG, ...value };
  const validation = useMemo(() => validateCustomFieldMapping(config.mapping), [config.mapping]);

  useEffect(() => {
    let active = true;
    const inspect = async () => {
      if (!files.length) {
        setInspection({ state: "idle", message: "Add a custom CSV or XLSX file to inspect its headers." });
        onChange?.(INITIAL_CONFIG);
        return;
      }
      setInspection({ state: "loading", message: "Inspecting headers and preparing suggested mappings..." });
      try {
        const parsedFiles = await Promise.all(files.map((file) => parseExportFile(file, { allowUnknown: true }).then((parsed) => ({ file, parsed }))));
        const target = parsedFiles.find(({ parsed }) => parsed.sourceTool === "custom-csv") ?? parsedFiles[0];
        if (!active) return;
        const fields = target.parsed.fields ?? Object.keys(target.parsed.rows?.[0] ?? {});
        const sameFile = config.fileName === target.file.name && config.fields.join("\u001f") === fields.join("\u001f");
        const next = sameFile
          ? config
          : { ...INITIAL_CONFIG, mapping: autoMapCustomHeaders(fields), fileName: target.file.name, fields };
        onChange?.(next);
        setInspection({ state: "ready", message: `${fields.length} headers detected in ${target.file.name}. Review the suggested mapping before analysis.` });
      } catch (error) {
        if (!active) return;
        setInspection({ state: "error", message: error.message || "Custom header inspection failed." });
      }
    };
    inspect();
    return () => { active = false; };
  }, [files]);

  const updateMapping = (key, header) => {
    onChange?.({ ...config, mapping: { ...config.mapping, [key]: header } });
  };

  return (
    <section className="mt-4 overflow-hidden rounded-2xl border border-sky-300/15 bg-sky-400/[0.035]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
        <div className="flex items-start gap-3">
          <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-sky-300/20 bg-sky-400/[0.08]"><FileCog className="h-5 w-5 text-sky-300" /></span>
          <div>
            <p className="mini-label text-sky-300">Universal scanner mapping</p>
            <h3 className="mt-1 text-lg font-extrabold text-white">Map source headers to the MVA finding model</h3>
            <p className="mt-1 text-xs font-medium leading-5 text-slate-500">Suggestions are based on common scanner field names. Required identity and severity fields must be confirmed.</p>
          </div>
        </div>
        <span className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-extrabold ${validation.valid ? "border-emerald-300/20 bg-emerald-400/[0.06] text-emerald-200" : "border-amber-300/20 bg-amber-400/[0.06] text-amber-100"}`}>
          {validation.valid ? <CheckCircle2 className="h-4 w-4" /> : <TriangleAlert className="h-4 w-4" />}
          {validation.valid ? "Required mapping complete" : `${validation.missing.length} requirement(s) pending`}
        </span>
      </div>

      <div className="grid gap-3 p-5 sm:grid-cols-2 xl:grid-cols-3">
        {CUSTOM_FIELD_DEFINITIONS.map((definition) => (
          <label key={definition.key} className="block">
            <span className="admin-label">
              {definition.label}
              {(definition.required || definition.requiredGroup) && <span className="ml-1 text-red-300">*</span>}
            </span>
            <span className="relative block">
              <select
                value={config.mapping[definition.key] ?? ""}
                onChange={(event) => updateMapping(definition.key, event.target.value)}
                className="admin-input appearance-none pr-9 text-xs"
              >
                <option value="">Not mapped</option>
                {config.fields.map((field) => <option key={field} value={field}>{field}</option>)}
              </select>
              <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
            </span>
          </label>
        ))}
      </div>

      <div className="grid gap-3 border-t border-white/[0.07] p-5 md:grid-cols-2">
        <label>
          <span className="admin-label">Severity scale</span>
          <select value={config.severityScale} onChange={(event) => onChange?.({ ...config, severityScale: event.target.value })} className="admin-input text-xs">
            <option value="auto">Text / standard 0-4</option>
            <option value="qualys-standard">Qualys standard 1-5</option>
            <option value="qualys-custom">Custom Qualys 1-5</option>
          </select>
        </label>
        <label>
          <span className="admin-label">Exploit interpretation</span>
          <select value={config.exploitMode} onChange={(event) => onChange?.({ ...config, exploitMode: event.target.value })} className="admin-input text-xs">
            <option value="boolean">Interpret yes/no and exploit labels</option>
            <option value="non-empty">Any evidence text means available</option>
          </select>
        </label>
      </div>

      <div aria-live="polite" className={`border-t border-white/[0.07] px-5 py-3 text-xs font-bold ${inspection.state === "error" ? "text-red-200" : validation.valid ? "text-emerald-200" : "text-slate-500"}`}>
        {inspection.message}{!validation.valid && config.fields.length ? ` Missing: ${validation.missing.join("; ")}.` : ""}
      </div>
    </section>
  );
}
