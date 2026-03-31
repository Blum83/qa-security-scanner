import { getScanPdfUrl } from "../api";
import "./ScanReport.css";

const RISK_ORDER = ["critical", "high", "medium", "low", "info"];

function ScanReport({ data, onReset, scanId }) {
  if (!data) return null;

  const { status, target_url, summary, issues, error } = data;

  if (status === "failed") {
    return (
      <div className="report">
        <div className="report-error">
          <h2>Scan Failed</h2>
          <p>{error || "An unexpected error occurred."}</p>
          <button className="btn-primary" onClick={onReset}>
            Try Again
          </button>
        </div>
      </div>
    );
  }

  const sortedIssues = [...issues].sort(
    (a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk)
  );

  const grouped = {};
  for (const risk of RISK_ORDER) {
    const matching = sortedIssues.filter((i) => i.risk === risk);
    if (matching.length > 0) grouped[risk] = matching;
  }

  const totalIssues = issues.length;

  return (
    <div className="report">
      <div className="report-header">
        <div className="report-header-top">
          <div>
            <h2>Scan Results</h2>
            <p className="target-url">{target_url}</p>
          </div>
          <div className="report-actions">
            {scanId && (
              <a
                href={getScanPdfUrl(scanId)}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-outline btn-pdf"
              >
                Download PDF
              </a>
            )}
            <button className="btn-outline" onClick={onReset}>
              New Scan
            </button>
          </div>
        </div>

        {summary && (
          <div className="summary-grid">
            <SummaryCard
              label="Critical"
              count={summary.critical}
              level="critical"
            />
            <SummaryCard label="High" count={summary.high} level="high" />
            <SummaryCard
              label="Medium"
              count={summary.medium}
              level="medium"
            />
            <SummaryCard label="Low" count={summary.low} level="low" />
          </div>
        )}

        <p className="total-issues">
          {totalIssues} {totalIssues === 1 ? "issue" : "issues"} found
        </p>
      </div>

      {totalIssues === 0 && (
        <div className="no-issues">
          No security issues were found. The site looks good!
        </div>
      )}

      {Object.entries(grouped).map(([risk, items]) => (
        <div key={risk} className="issue-group">
          <h3 className={`group-title risk-${risk}`}>
            {risk.charAt(0).toUpperCase() + risk.slice(1)}{" "}
            <span className="group-count">({items.length})</span>
          </h3>
          {items.map((issue, i) => (
            <IssueCard key={i} issue={issue} />
          ))}
        </div>
      ))}
    </div>
  );
}

function SummaryCard({ label, count, level }) {
  return (
    <div className={`summary-card risk/bg-${level}`}>
      <span className={`summary-count risk-${level}`}>{count}</span>
      <span className="summary-label">{label}</span>
    </div>
  );
}

function IssueCard({ issue }) {
  return (
    <div className="issue-card">
      <div className="issue-top-row">
        <span className={`risk-badge risk-${issue.risk}`}>{issue.risk}</span>
        <span className="issue-type-badge">{issue.type}</span>
      </div>
      <h4 className="issue-name">{issue.name}</h4>
      <p className="issue-message">{issue.message}</p>
      <div className="issue-recommendation">
        <span className="rec-label">Recommendation</span>
        {issue.recommendation}
      </div>
    </div>
  );
}

export default ScanReport;
