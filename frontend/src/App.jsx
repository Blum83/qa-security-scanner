import { useState, useRef, useEffect } from "react";
import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import ScanForm from "./components/ScanForm";
import Features from "./components/Features";
import ScanProgress from "./components/ScanProgress";
import ScanReport from "./components/ScanReport";
import { startScan, getScan, stopScan } from "./api";
import "./App.css";

const POLL_INTERVAL = 5000; // 5 seconds instead of 3
const MAX_POLL_TIME = 30 * 60 * 1000; // 30 minutes max polling

function App() {
  const [view, setView] = useState("form");
  const [scanData, setScanData] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState(null);
  const intervalRef = useRef(null);

  const handleScan = async (url) => {
    setError(null);
    try {
      const { scan_id } = await startScan(url);
      setScanId(scan_id);
      setView("scanning");
      pollScan(scan_id);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Failed to start scan. Is the backend running?"
      );
    }
  };

  const pollScan = (id) => {
    intervalRef.current = setInterval(async () => {
      try {
        const data = await getScan(id);
        setScanData(data);

        if (
          data.status === "completed" ||
          data.status === "failed" ||
          data.status === "cancelled"
        ) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          setView(data.status === "cancelled" ? "form" : "report");
        }
      } catch {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        setError("Lost connection to the scanner.");
        setView("form");
      }
    }, POLL_INTERVAL);
  };

  const handleStop = async () => {
    if (!scanId) return;
    try {
      await stopScan(scanId);
    } catch {
      // Stop failed — just go back
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setView("form");
    setScanData(null);
    setScanId(null);
  };

  const handleReset = () => {
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

        {view === "form" && (
          <>
            <Hero />
            <ScanForm onScan={handleScan} />
            <Features />
          </>
        )}
        {view === "scanning" && (
          <ScanProgress data={scanData} onStop={handleStop} />
        )}
        {view === "report" && (
          <ScanReport data={scanData} onReset={handleReset} />
        )}
      </main>
    </div>
  );
}

export default App;
