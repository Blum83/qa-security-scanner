import { useState } from "react";
import "./ScanForm.css";

function ScanForm({ onScan }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);

  const normalizeUrl = (raw) => {
    const trimmed = raw.trim();
    if (!/^https?:\/\//i.test(trimmed)) {
      return `https://${trimmed}`;
    }
    return trimmed;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    await onScan(normalizeUrl(url));
    setLoading(false);
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <label className="form-label" htmlFor="url-input">
        Website URL to Scan
      </label>
      <input
        id="url-input"
        type="text"
        className="url-input"
        placeholder="https://example.com"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        required
        disabled={loading}
      />
      <button
        type="submit"
        className="scan-btn"
        disabled={loading || !url.trim()}
      >
        {loading ? (
          <>
            <span className="btn-spinner" />
            Starting Scan...
          </>
        ) : (
          <>
            <span className="btn-icon">&#x23F1;</span>
            Start Security Scan
          </>
        )}
      </button>
      <p className="hint">
        The scan checks security headers and performs automated vulnerability
        testing. This may take a few minutes depending on the website size.
      </p>
    </form>
  );
}

export default ScanForm;
