import { useState, useRef, useEffect, useCallback } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import ScanForm from "./components/ScanForm";
import Features from "./components/Features";
import ScanProgress from "./components/ScanProgress";
import ScanReport from "./components/ScanReport";
import ScheduleManager from "./components/ScheduleManager";
import ScanDashboard from "./components/ScanDashboard";
import { startScan, getScan, stopScan, getHealth } from "./api";
import "./App.css";

const POLL_INTERVAL = 5000;
const MAX_POLL_ATTEMPTS = 360;
const MAX_RETRIES = 3;
const RETRY_DELAY = 2000;

function App() {
  const navigate = useNavigate();
  const [view, setView] = useState("form"); // "form" | "scanning" | "report"
  const [scanData, setScanData] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState(null);
  const [scanners, setScanners] = useState({ zap: false, nuclei: false });
  const intervalRef = useRef(null);
  const pollAttemptsRef = useRef(0);
  const retryCountRef = useRef(0);

  // Recover in-progress scan from localStorage on mount
  useEffect(() => {
    const savedScanId = localStorage.getItem("currentScanId");
    if (savedScanId) {
      setScanId(savedScanId);
      setView("scanning");
      navigate("/", { replace: true });
      pollScan(savedScanId, true);
    }
  }, []);

  useEffect(() => {
    getHealth()
      .then((data) => setScanners(data.scanners || {}))
      .catch(() => {});
  }, []);

  const handleScan = async (url) => {
    setError(null);
    try {
      const { scan_id } = await startScan(url);
      setScanId(scan_id);
      localStorage.setItem("currentScanId", scan_id);
      setView("scanning");
      pollAttemptsRef.current = 0;
      retryCountRef.current = 0;
      pollScan(scan_id);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Failed to start scan. Is the backend running?"
      );
    }
  };

  const pollScan = useCallback((id, isRecovery = false) => {
    if (intervalRef.current) clearInterval(intervalRef.current);

    if (!isRecovery) {
      pollAttemptsRef.current = 0;
      retryCountRef.current = 0;
    }

    intervalRef.current = setInterval(async () => {
      try {
        const data = await getScan(id);
        retryCountRef.current = 0;
        setScanData(data);

        if (
          data.status === "completed" ||
          data.status === "failed" ||
          data.status === "cancelled"
        ) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          localStorage.removeItem("currentScanId");
          setView(data.status === "cancelled" ? "form" : "report");
        }

        pollAttemptsRef.current += 1;
        if (pollAttemptsRef.current >= MAX_POLL_ATTEMPTS) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          localStorage.removeItem("currentScanId");
          setError("Scan timed out after 30 minutes.");
          setView("form");
        }
      } catch {
        retryCountRef.current += 1;
        if (retryCountRef.current >= MAX_RETRIES) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          localStorage.removeItem("currentScanId");
          setError("Lost connection to the scanner. Please try again.");
          setView("form");
        } else {
          setTimeout(() => {
            if (intervalRef.current) {
              getScan(id)
                .then((data) => {
                  retryCountRef.current = 0;
                  setScanData(data);
                  if (
                    data.status === "completed" ||
                    data.status === "failed" ||
                    data.status === "cancelled"
                  ) {
                    clearInterval(intervalRef.current);
                    intervalRef.current = null;
                    localStorage.removeItem("currentScanId");
                    setView(data.status === "cancelled" ? "form" : "report");
                  }
                })
                .catch(() => {});
            }
          }, RETRY_DELAY);
        }
      }
    }, POLL_INTERVAL);
  }, []);

  const handleStop = async () => {
    if (!scanId) return;
    try {
      await stopScan(scanId);
    } catch {
      // ignore
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    localStorage.removeItem("currentScanId");
    setView("form");
    setScanData(null);
    setScanId(null);
  };

  const handleReset = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    localStorage.removeItem("currentScanId");
    setView("form");
    setScanData(null);
    setScanId(null);
    setError(null);
  };

  return (
    <div className="app">
      <Navbar />
      <main className="main">
        {error && <div className="error-banner">{error}</div>}

        <Routes>
          <Route
            path="/"
            element={
              <>
                {view === "form" && (
                  <>
                    <Hero scanners={scanners} />
                    <ScanForm onScan={handleScan} />
                    <Features />
                  </>
                )}
                {view === "scanning" && (
                  <ScanProgress data={scanData} onStop={handleStop} />
                )}
                {view === "report" && (
                  <ScanReport data={scanData} onReset={handleReset} scanId={scanId} />
                )}
              </>
            }
          />
          <Route
            path="/schedules"
            element={<ScheduleManager onBack={() => navigate("/")} />}
          />
          <Route
            path="/history"
            element={
              <ScanDashboard
                onViewReport={(data, id) => {
                  setScanData(data);
                  setScanId(id);
                  setView("report");
                  navigate("/");
                }}
                onBack={() => navigate("/")}
              />
            }
          />
        </Routes>
      </main>
    </div>
  );
}

export default App;
