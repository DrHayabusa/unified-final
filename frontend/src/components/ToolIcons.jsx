const accentMap = {
  emerald: "text-emerald-400",
  sky: "text-sky-400",
  violet: "text-violet-400",
  red: "text-red-500",
  amber: "text-amber-400",
  slate: "text-slate-300",
};

export function SourceToolIcon({ id, accent = "emerald" }) {
  const color = accentMap[accent] ?? accentMap.emerald;
  const common = `h-16 w-16 ${color} drop-shadow-[0_0_18px_currentColor]`;

  if (id === "tenable-sc") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M32 7 53 19v26L32 57 11 45V19L32 7Z" fill="none" stroke="currentColor" strokeWidth="3" />
        <path d="M32 17 44 24v15l-12 8-12-8V24l12-7Z" fill="currentColor" opacity="0.12" />
        <path d="M22 32h20M32 20v24M24 25l16 14M40 25 24 39" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      </svg>
    );
  }

  if (id === "tenable-io") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M32 6 55 19v26L32 58 9 45V19L32 6Z" fill="none" stroke="currentColor" strokeWidth="3" />
        <path d="M21 26 32 20l11 6-11 7-11-7Z" fill="currentColor" opacity="0.22" />
        <path d="M21 26v13l11 7 11-7V26M32 33v13" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinejoin="round" />
      </svg>
    );
  }

  if (id === "mdvm") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M32 7 53 17v16c0 13-8 21-21 27C19 54 11 46 11 33V17L32 7Z" fill="currentColor" opacity="0.12" />
        <path d="M32 7 53 17v16c0 13-8 21-21 27C19 54 11 46 11 33V17L32 7Z" fill="none" stroke="currentColor" strokeWidth="3" />
        <path d="M20 43V23l12 14 12-14v20" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (id === "crowdstrike") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M6 18c16 7 30 8 52 3-11 5-20 8-30 8 8 3 17 4 28 2-12 7-26 8-41 2 8 8 20 14 34 18C27 50 13 39 6 18Z" fill="currentColor" />
        <path d="M15 16c9 7 20 10 34 11" fill="none" stroke="#020617" strokeWidth="2" opacity="0.35" />
      </svg>
    );
  }

  if (id === "qualys" || id === "custom-qualys") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M32 5C20 9 12 19 12 32c0 14 8 24 20 29 12-5 20-15 20-29C52 19 44 9 32 5Z" fill="currentColor" />
        <circle cx="32" cy="32" r="13" fill="#ffffff" opacity="0.95" />
        <path d="M36 36 45 45" stroke="currentColor" strokeWidth="7" strokeLinecap="round" />
      </svg>
    );
  }

  if (id === "openshift") {
    return (
      <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
        <path d="M15 18 32 8l17 10v20L32 48 15 38V18Z" fill="none" stroke="currentColor" strokeWidth="3" strokeLinejoin="round" />
        <path d="M8 29 15 25v13l17 10v8L8 42V29ZM56 22l-7-4v20L32 48v8l24-14V22Z" fill="currentColor" opacity="0.25" />
        <path d="M22 25 32 19l10 6v12l-10 6-10-6V25Z" fill="currentColor" opacity="0.16" />
        <path d="m26 30 6-4 6 4v7l-6 4-6-4v-7Z" fill="currentColor" />
      </svg>
    );
  }

  return (
    <svg className={common} viewBox="0 0 64 64" aria-hidden="true">
      <path d="M18 6h22l10 10v42H18V6Z" fill="currentColor" opacity="0.15" />
      <path d="M18 6h22l10 10v42H18V6Z" fill="none" stroke="currentColor" strokeWidth="3" />
      <path d="M40 6v12h10M25 30h18M25 39h18M25 48h11" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function MvaLogo({ className = "h-20 w-20" }) {
  return (
    <svg viewBox="0 0 80 88" className={className} role="img" aria-label="MVA shield mark">
      <path d="M40 4 70 15v23c0 20-11 35-30 46C21 73 10 58 10 38V15L40 4Z" fill="#0a0a0b" stroke="#3f3f46" strokeWidth="1.5" />
      <path d="M40 9 65 18v20c0 16-8 28-25 39C23 66 15 54 15 38V18L40 9Z" fill="#121214" />
      <path d="M40 4 70 15v23M40 84C21 73 10 58 10 38V15L40 4" fill="none" stroke="#ef4444" strokeWidth="3.5" strokeLinejoin="miter" />
      <path d="M18 22h10M62 22H52M40 13v7" stroke="#7f1d1d" strokeWidth="2" />
      <text x="40" y="47" fill="#f4f4f5" fontFamily="Manrope, sans-serif" fontSize="17" fontWeight="800" letterSpacing="0.8" textAnchor="middle">MVA</text>
      <path d="M24 55h32" stroke="#ef4444" strokeWidth="3" strokeLinecap="square" />
      <path d="M34 63h12" stroke="#7f1d1d" strokeWidth="2" />
    </svg>
  );
}
