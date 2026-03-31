import "./Hero.css";

function Hero({ scanners = {} }) {
  const scannerStatuses = Object.entries(scanners)
    .filter(([_, available]) => available)
    .map(([name]) => name.charAt(0).toUpperCase() + name.slice(1));

  return (
    <section className="hero">
      <span className="hero-badge">SECURITY MADE SIMPLE</span>
      <h1 className="hero-title">
        Scan Your Web Application
        <br />
        <span className="hero-highlight">Get Clear Security Reports</span>
      </h1>
      <p className="hero-description">
        A security scanning tool designed for QA engineers. Enter a URL and get
        human-readable security findings without the complexity.
      </p>
      {scannerStatuses.length > 0 && (
        <div className="scanner-status">
          Available scanners: {scannerStatuses.join(", ")}
        </div>
      )}
    </section>
  );
}

export default Hero;
