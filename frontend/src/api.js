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
