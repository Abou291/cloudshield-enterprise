import type { Finding, ScanResult } from "./types";

const API_URL = import.meta.env.VITE_API_URL ?? "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, init);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail ?? `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const listFindings = () => request<Finding[]>("/findings");

export const runDemoScan = () =>
  request<ScanResult>("/scans/demo", { method: "POST" });
