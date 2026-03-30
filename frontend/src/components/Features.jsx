import "./Features.css";

const ShieldIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);

const ScanIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.3-4.3" />
    <path d="M11 8v6" />
    <path d="M8 11h6" />
  </svg>
);

const ReportIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="16" y1="13" x2="8" y2="13" />
    <line x1="16" y1="17" x2="8" y2="17" />
    <polyline points="10 9 9 9 8 9" />
  </svg>
);

const FEATURES = [
  {
    icon: <ShieldIcon />,
    title: "Security Headers Check",
    description:
      "Verifies HTTPS, CSP, HSTS, and other security headers are properly configured.",
  },
  {
    icon: <ScanIcon />,
    title: "Vulnerability Scanning",
    description:
      "Uses OWASP ZAP to detect common web vulnerabilities like XSS and SQL injection.",
  },
  {
    icon: <ReportIcon />,
    title: "QA-Friendly Reports",
    description:
      "Clear explanations and actionable recommendations, no security jargon.",
  },
];

function Features() {
  return (
    <section className="features">
      {FEATURES.map((f) => (
        <div key={f.title} className="feature-card">
          <div className="feature-icon">{f.icon}</div>
          <h3 className="feature-title">{f.title}</h3>
          <p className="feature-desc">{f.description}</p>
        </div>
      ))}
    </section>
  );
}

export default Features;
