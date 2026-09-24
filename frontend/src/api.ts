import type { AssistantResponse, AuditEvent, AwsConnectionInput, AwsConnectionView, Finding, ScanHistory, ScanResult, Session } from "./types";

const API_URL = import.meta.env.VITE_API_URL ?? "/api/v1";
// Intentionally memory-only: reload/logout forgets the token.
let apiToken = "";
export function setApiToken(token: string) { apiToken = token; }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (apiToken) headers.set("Authorization", `Bearer ${apiToken}`);
  const response = await fetch(`${API_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new ApiError(response.status, typeof payload.detail === "string"
      ? payload.detail : `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const listFindings = (source: string, offset = 0) =>
  request<Finding[]>(`/findings?source=${encodeURIComponent(source)}&limit=100&offset=${offset}`);
export const getSession = () => request<Session>("/session");
export const listScans = () => request<ScanHistory[]>("/scans");
export const listAudit = () => request<AuditEvent[]>("/audit");
export const runAwsScan = () => request<ScanResult>("/scans/aws", { method: "POST" });

export const runDemoScan = () =>
  request<ScanResult>("/scans/demo", { method: "POST" });

export const testAwsConnection = (connection: AwsConnectionInput) => request<AwsConnectionView>(
  "/connections/aws/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(connection) },
);
export const saveAwsConnection = (connection: AwsConnectionInput) => request<AwsConnectionView>(
  "/connections/aws", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(connection) },
);

export const askAssistant = (question: string, source: string) => request<AssistantResponse>("/assistant", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, source }) });
