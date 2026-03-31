import { useState, useEffect } from "react";
import {
  listSchedules,
  createSchedule,
  deleteSchedule,
  pauseSchedule,
  resumeSchedule,
} from "../api";
import "./ScheduleManager.css";

const CRON_EXAMPLES = [
  { label: "Every day at 9am", value: "0 9 * * *" },
  { label: "Every Monday at 9am", value: "0 9 * * 1" },
  { label: "Every hour", value: "0 * * * *" },
  { label: "Every Sunday at midnight", value: "0 0 * * 0" },
];

function ScheduleManager({ onBack }) {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    fetchSchedules();
  }, []);

  async function fetchSchedules() {
    try {
      const data = await listSchedules();
      setSchedules(data);
    } catch {
      setError("Failed to load schedules.");
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(formData) {
    try {
      const created = await createSchedule(formData);
      setSchedules((prev) => [created, ...prev]);
      setShowForm(false);
    } catch (err) {
      const msg = err.response?.data?.detail || "Failed to create schedule.";
      throw new Error(msg);
    }
  }

  async function handleDelete(scheduleId) {
    if (!confirm("Delete this schedule? This cannot be undone.")) return;
    try {
      await deleteSchedule(scheduleId);
      setSchedules((prev) => prev.filter((s) => s.schedule_id !== scheduleId));
    } catch {
      setError("Failed to delete schedule.");
    }
  }

  async function handleToggle(schedule) {
    try {
      const updated =
        schedule.status === "active"
          ? await pauseSchedule(schedule.schedule_id)
          : await resumeSchedule(schedule.schedule_id);
      setSchedules((prev) =>
        prev.map((s) => (s.schedule_id === updated.schedule_id ? updated : s))
      );
    } catch {
      setError("Failed to update schedule status.");
    }
  }

  return (
    <div className="schedule-manager">
      <div className="schedule-header">
        <div>
          <h2>Scheduled Scans</h2>
          <p className="schedule-subtitle">
            Automatically scan URLs on a recurring schedule and receive
            notifications when scans complete.
          </p>
        </div>
        <div className="schedule-header-actions">
          <button
            className="btn-primary"
            onClick={() => setShowForm((v) => !v)}
          >
            {showForm ? "Cancel" : "+ New Schedule"}
          </button>
          <button className="btn-outline" onClick={onBack}>
            Back
          </button>
        </div>
      </div>

      {error && <div className="schedule-error">{error}</div>}

      {showForm && (
        <CreateScheduleForm onSubmit={handleCreate} onCancel={() => setShowForm(false)} />
      )}

      {loading ? (
        <div className="schedule-loading">Loading schedules...</div>
      ) : schedules.length === 0 ? (
        <div className="schedule-empty">
          <p>No schedules yet.</p>
          <p>Create one to automatically scan a URL on a recurring basis.</p>
        </div>
      ) : (
        <div className="schedule-list">
          {schedules.map((s) => (
            <ScheduleCard
              key={s.schedule_id}
              schedule={s}
              onDelete={handleDelete}
              onToggle={handleToggle}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function CreateScheduleForm({ onSubmit, onCancel }) {
  const [url, setUrl] = useState("https://");
  const [cron, setCron] = useState("0 9 * * 1");
  const [label, setLabel] = useState("");
  const [webhooks, setWebhooks] = useState([]);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  function addWebhook() {
    setWebhooks((prev) => [...prev, { type: "slack", target: "" }]);
  }

  function removeWebhook(i) {
    setWebhooks((prev) => prev.filter((_, idx) => idx !== i));
  }

  function updateWebhook(i, field, value) {
    setWebhooks((prev) =>
      prev.map((wh, idx) => (idx === i ? { ...wh, [field]: value } : wh))
    );
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    const targetUrl = url.trim().startsWith("http") ? url.trim() : `https://${url.trim()}`;
    const validWebhooks = webhooks.filter((w) => w.target.trim());

    setSubmitting(true);
    try {
      await onSubmit({ url: targetUrl, cron, label: label || null, webhooks: validWebhooks });
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="schedule-form" onSubmit={handleSubmit}>
      <h3>New Schedule</h3>

      {error && <div className="schedule-form-error">{error}</div>}

      <div className="form-group">
        <label>Target URL</label>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          required
        />
      </div>

      <div className="form-group">
        <label>Label (optional)</label>
        <input
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Production site"
          maxLength={80}
        />
      </div>

      <div className="form-group">
        <label>Cron Schedule</label>
        <input
          type="text"
          value={cron}
          onChange={(e) => setCron(e.target.value)}
          placeholder="0 9 * * 1"
          required
        />
        <div className="cron-examples">
          {CRON_EXAMPLES.map((ex) => (
            <button
              key={ex.value}
              type="button"
              className="cron-chip"
              onClick={() => setCron(ex.value)}
            >
              {ex.label}
            </button>
          ))}
        </div>
        <span className="form-hint">
          5-field cron: minute hour day month weekday (UTC)
        </span>
      </div>

      <div className="form-group">
        <label>Notifications</label>
        {webhooks.map((wh, i) => (
          <div key={i} className="webhook-row">
            <select
              value={wh.type}
              onChange={(e) => updateWebhook(i, "type", e.target.value)}
            >
              <option value="slack">Slack</option>
              <option value="email">Email</option>
            </select>
            <input
              type={wh.type === "email" ? "email" : "url"}
              value={wh.target}
              onChange={(e) => updateWebhook(i, "target", e.target.value)}
              placeholder={
                wh.type === "slack"
                  ? "https://hooks.slack.com/services/..."
                  : "user@example.com"
              }
            />
            <button
              type="button"
              className="webhook-remove"
              onClick={() => removeWebhook(i)}
              title="Remove"
            >
              ×
            </button>
          </div>
        ))}
        <button type="button" className="btn-add-webhook" onClick={addWebhook}>
          + Add notification
        </button>
      </div>

      <div className="form-actions">
        <button type="submit" className="btn-primary" disabled={submitting}>
          {submitting ? "Creating..." : "Create Schedule"}
        </button>
        <button type="button" className="btn-outline" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function ScheduleCard({ schedule, onDelete, onToggle }) {
  const isPaused = schedule.status === "paused";

  function formatNextRun(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  return (
    <div className={`schedule-card ${isPaused ? "schedule-card--paused" : ""}`}>
      <div className="schedule-card-top">
        <div className="schedule-card-info">
          {schedule.label && <p className="schedule-label">{schedule.label}</p>}
          <p className="schedule-url">{schedule.url}</p>
          <div className="schedule-meta">
            <span className="schedule-cron">{schedule.cron}</span>
            <span className={`schedule-status-badge status-${schedule.status}`}>
              {schedule.status}
            </span>
          </div>
        </div>
        <div className="schedule-card-actions">
          <button
            className={isPaused ? "btn-outline btn-sm" : "btn-outline btn-sm btn-pause"}
            onClick={() => onToggle(schedule)}
          >
            {isPaused ? "Resume" : "Pause"}
          </button>
          <button
            className="btn-outline btn-sm btn-danger"
            onClick={() => onDelete(schedule.schedule_id)}
          >
            Delete
          </button>
        </div>
      </div>

      <div className="schedule-card-footer">
        <span>Next run: {formatNextRun(schedule.next_run_at)}</span>
        {schedule.last_scan_id && (
          <span>Last scan: {schedule.last_scan_id.slice(0, 8)}…</span>
        )}
        {schedule.webhooks?.length > 0 && (
          <span>{schedule.webhooks.length} notification(s)</span>
        )}
      </div>
    </div>
  );
}

export default ScheduleManager;
