import { useState, useEffect } from "react";
import "./ScanProgress.css";

const PHASES = [
  { key: "headers", label: "Checking security headers", minProgress: 0 },
  { key: "spider", label: "Crawling the website", minProgress: 10 },
  { key: "active", label: "Testing for vulnerabilities", minProgress: 40 },
  { key: "results", label: "Collecting results", minProgress: 90 },
  { key: "report", label: "Building report", minProgress: 98 },
];

function getActivePhaseIndex(progress) {
  let idx = 0;
  for (let i = PHASES.length - 1; i >= 0; i--) {
    if (progress >= PHASES[i].minProgress) {
      idx = i;
      break;
    }
  }
  return idx;
}

function formatElapsed(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m === 0) return `${s}s`;
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

function ScanProgress({ data, onStop }) {
  const progress = data?.progress || 0;
  const phaseText = data?.phase || "Initializing...";
  const targetUrl = data?.target_url || "";
  const phaseDetails = data?.phase_details || [];
  const activeIdx = getActivePhaseIndex(progress);

  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  const isActiveScan = activeIdx === 2;

  return (
    <div className="scan-progress">
      <div className="spinner" />
      <h2>Scanning in progress...</h2>
      {targetUrl && <p className="scan-target">{targetUrl}</p>}

      {phaseText && <p className="current-phase">{phaseText}</p>}

      <div className="progress-bar-container">
        <div className="progress-bar" style={{ width: `${progress}%` }} />
      </div>
      <p className="progress-text">
        {progress}% complete &middot; {formatElapsed(elapsed)}
      </p>

      {isActiveScan && phaseDetails.length === 0 && (
        <p className="phase-hint">
          Active vulnerability testing can take 10-20 minutes for large sites.
          The scanner is working — progress may appear slow at first.
        </p>
      )}

      <div className="phase-list">
        {PHASES.map((phase, i) => {
          let status = "pending";
          if (i < activeIdx) status = "done";
          else if (i === activeIdx) status = "active";

          return (
            <div key={phase.key} className={`phase-item phase-${status}`}>
              <span className="phase-icon">
                {status === "done" && "\u2713"}
                {status === "active" && "\u25CF"}
                {status === "pending" && ""}
              </span>
              <span className="phase-label">{phase.label}</span>
            </div>
          );
        })}
      </div>

      {phaseDetails.length > 0 && (
        <div className="phase-details">
          <p className="phase-details-title">Current operations:</p>
          <ul className="phase-details-list">
            {phaseDetails.map((detail, i) => (
              <li key={i}>{detail}</li>
            ))}
          </ul>
        </div>
      )}

      <button className="stop-btn" onClick={onStop} type="button">
        Stop Scan
      </button>
    </div>
  );
}

export default ScanProgress;
