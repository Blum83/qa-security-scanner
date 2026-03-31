import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

const client = axios.create({ baseURL: API_BASE });

export async function startScan(url) {
  const { data } = await client.post("/scan", { url });
  return data;
}

export async function getScan(scanId) {
  const { data } = await client.get(`/scan/${scanId}`);
  return data;
}

export async function stopScan(scanId) {
  const { data } = await client.post(`/scan/${scanId}/stop`);
  return data;
}

export async function getHealth() {
  const { data } = await client.get("/health");
  return data;
}

export function getScanPdfUrl(scanId) {
  return `${API_BASE}/scan/${scanId}/pdf`;
}

export async function listSchedules() {
  const { data } = await client.get("/schedules");
  return data;
}

export async function createSchedule(payload) {
  const { data } = await client.post("/schedules", payload);
  return data;
}

export async function updateSchedule(scheduleId, payload) {
  const { data } = await client.put(`/schedules/${scheduleId}`, payload);
  return data;
}

export async function deleteSchedule(scheduleId) {
  await client.delete(`/schedules/${scheduleId}`);
}

export async function pauseSchedule(scheduleId) {
  const { data } = await client.post(`/schedules/${scheduleId}/pause`);
  return data;
}

export async function resumeSchedule(scheduleId) {
  const { data } = await client.post(`/schedules/${scheduleId}/resume`);
  return data;
}
