export function HelpAgLogo({ className = "" }) {
  return (
    <img
      src={`${import.meta.env.BASE_URL}brand/helpag-logo-white.png`}
      alt="Help AG"
      className={`h-auto object-contain ${className}`}
    />
  );
}
