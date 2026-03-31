import { useState, useEffect } from "react";
import { listScans, getScan } from "../api";
import "./ScanDashboard.css";

const STATUS_ORDER = ["running", "pending", "completed", "failed", "cancelled"];

function ScanDashboard({ onViewReport, onBack }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [loadingId, setLoadingId] = useState(null);

  useEffect(() => {
    fetchScans();
  }, []);

  async function fetchScans() {
    try {
      const data = await listScans();
      data.sort((a, b) => {
        const si = STATUS_ORDER.indexOf(a.status);
        const sj = STATUS_ORDER.indexOf(b.status);
        if (si !== sj) return si - sj;
        return (b.created_at || "").localeCompare(a.created_at || "");
      });
      setScans(data);
    } catch {
      setError("Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }

  async function handleOpen(scan) {
    if (scan.status !== "completed" && scan.status !== "failed") return;
    setLoadingId(scan.scan_id);
    try {
      const full = await getScan(scan.scan_id);
      onViewReport(full, scan.scan_id);
    } catch {
      setError("Failed to load scan report.");
    } finally {
      setLoadingId(null);
    }
  }

  const completed = scans.filter((s) => s.status === "completed");
  const totalIssues = completed.reduce((acc, s) => {
    if (!s.summary) return acc;
    return acc + s.summary.critical + s.summary.high + s.summary.medium + s.summary.low;
  }, 0);
  const totalCritical = completed.reduce((acc, s) => acc + (s.summary?.critical || 0), 0);
  const totalHigh = completed.reduce((acc, s) => acc + (s.summary?.high || 0), 0);

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div>
          <h2>Scan History</h2>
          <p className="dashboard-subtitle">All scans, most recent first. Click a completed scan to view the full report.</p>
        </div>
        <button className="btn-outline" onClick={onBack}>Back</button>
      </div>

      {error && <div className="dashboard-error">{error}</div>}

      {!loading && scans.length > 0 && (
        <div className="dashboard-stats">
          <StatCard label="Total scans" value={scans.length} />
          <StatCard label="Completed" value={completed.length} accent="success" />
          <StatCard label="Issues found" value={totalIssues} accent="medium" />
          <StatCard label="Critical" value={totalCritical} accent="critical" />
          <StatCard label="High" value={totalHigh} accent="high" />
        </div>
      )}

      {loading ? (
        <div className="dashboard-empty">Loading history...</div>
      ) : scans.length === 0 ? (
        <div className="dashboard-empty">
          <p>No scans yet.</p>
          <p>Run your first scan to see results here.</p>
        </div>
      ) : (
        <div className="dashboard-list">
          {scans.map((scan) => (
            <ScanRow
              key={scan.scan_id}
              scan={scan}
              loading={loadingId === scan.scan_id}
              onClick={() => handleOpen(scan)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className={`stat-card ${accent ? `stat-card--${accent}` : ""}`}>
      <span className={`stat-value ${accent ? `risk-${accent}` : ""}`}>{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function ScanRow({ scan, loading, onClick }) {
  const isClickable = scan.status === "completed" || scan.status === "failed";

  function formatDate(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  const { summary } = scan;

  return (
    <div
      className={`scan-row ${isClickable ? "scan-row--clickable" : ""} ${loading ? "scan-row--loading" : ""}`}
      onClick={isClickable ? onClick : undefined}
      title={isClickable ? "Click to view report" : undefined}
    >
      <div className="scan-row-main">
        <div className="scan-row-url">{scan.target_url}</div>
        <div className="scan-row-meta">
          <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
          <span className="scan-row-date">{formatDate(scan.created_at)}</span>
          <span className="scan-row-id">{scan.scan_id.slice(0, 8)}…</span>
        </div>
      </div>

      {summary && (
        <div className="scan-row-summary">
          {summary.critical > 0 && (
            <span className="issue-pill pill-critical">{summary.critical} critical</span>
          )}
          {summary.high > 0 && (
            <span className="issue-pill pill-high">{summary.high} high</span>
          )}
          {summary.medium > 0 && (
            <span className="issue-pill pill-medium">{summary.medium} med</span>
          )}
          {summary.low > 0 && (
            <span className="issue-pill pill-low">{summary.low} low</span>
          )}
          {summary.critical === 0 && summary.high === 0 && summary.medium === 0 && summary.low === 0 && (
            <span className="issue-pill pill-clean">clean</span>
          )}
        </div>
      )}

      {isClickable && (
        <div className="scan-row-arrow">{loading ? "…" : "›"}</div>
      )}
    </div>
  );
}

export default ScanDashboard;
