import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

import App from "./App";
import { setApiToken } from "./api";

const session = {
  tenant_id: "demo",
  subject: "local-demo",
  role: "operator",
  demo: true,
  desktop: false,
  aws_enabled: false,
};
const response = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
const emptySummary = { findings: 0, critical: 0, high: 0, medium: 0, low: 0, highest_risk: null, accounts_affected: 0, regions_affected: 0, internet_exposed: 0, privileged: 0, sensitive_data: 0, attack_path_candidates: 0, top_risks: [] };
const fetchMock = vi.fn();

beforeEach(() => {
  setApiToken(""); fetchMock.mockReset(); vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockImplementation(async (url: string) => {
    if (url.endsWith("/session")) return response(session);
    if (url.includes("/executive-summary")) return response(emptySummary);
    return response([]);
  });
});
afterEach(() => { cleanup(); setApiToken(""); });

test("renders the empty dashboard", async () => {
  render(<App />);
  expect(screen.getByText("AegisShield")).toBeInTheDocument();
  expect(await screen.findByText("No findings loaded")).toBeInTheDocument();
  expect(screen.getByText("No data")).toBeInTheDocument();
  expect(screen.queryByText("Security score")).not.toBeInTheDocument();
  expect(screen.getByText(/Synthetic data/)).toBeInTheDocument();
});

test("requires a token and clears it on sign-out", async () => {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/session")) {
      return new Headers(init?.headers).get("Authorization") === "Bearer test-token"
        ? response({ ...session, demo: false, tenant_id: "alpha" })
        : response({ detail: "Valid API token required" }, 401);
    }
    return response([]);
  });
  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Connect" })).toBeEnabled());
  fireEvent.change(screen.getByLabelText("API token"), { target: { value: "test-token" } });
  fireEvent.click(screen.getByRole("button", { name: "Connect" }));
  expect(await screen.findByText("alpha")).toBeInTheDocument();
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
  fireEvent.click(screen.getByText("Sign out"));
  expect(await screen.findByLabelText("API token")).toHaveValue("");
  expect(screen.queryByText("alpha")).not.toBeInTheDocument();
});

test("viewer cannot trigger scans", async () => {
  fetchMock.mockImplementation(async (url: string) => response(
    url.endsWith("/session") ? { ...session, role: "viewer" } : []));
  render(<App />);
  expect(await screen.findByRole("button", { name: "Run demo scan" })).toBeDisabled();
});

test("scan failure remains visible after history refresh", async () => {
  fetchMock.mockImplementation(async (url: string) => {
    if (url.endsWith("/session")) return response(session);
    if (url.endsWith("/scans/demo")) return response({ detail: "Scan failed; previous findings were preserved" }, 503);
    return response([]);
  });
  render(<App />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Run demo scan" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Run demo scan" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("previous findings were preserved");
  await waitFor(() => expect(screen.getByRole("button", { name: "Run demo scan" })).toBeEnabled());
  expect(screen.getByRole("alert")).toHaveTextContent("previous findings were preserved");
});

test("shows failed scans without zero-findings success claims", async () => {
  fetchMock.mockImplementation(async (url: string) => {
    if (url.endsWith("/session")) return response(session);
    if (url.endsWith("/scans")) return response([{
      scan_id: "scan-1", source: "demo-fixture", status: "failed", started_at: "2026-09-20T10:00:00Z",
      completed_at: "2026-09-20T10:01:00Z", assets_scanned: 0, findings_count: 0, error_code: "SCAN_FAILED",
    }]);
    return response([]);
  });
  render(<App />);
  expect(await screen.findByText(/Displayed findings may be stale/)).toBeInTheDocument();
  expect(screen.getByText("failed · SCAN_FAILED")).toBeInTheDocument();
});


test("renders risk intelligence without overstating attack reachability", async () => {
  fetchMock.mockImplementation(async (url: string) => {
    if (url.endsWith("/session")) return response(session);
    if (url.includes("/executive-summary")) return response({
      ...emptySummary,
      findings: 3,
      accounts_affected: 1,
      regions_affected: 2,
      internet_exposed: 1,
      privileged: 1,
      attack_path_candidates: 1,
    });
    if (url.includes("/attack-paths")) return response([{
      path_id: "candidate-1",
      kind: "exposure-to-privilege",
      title: "Internet exposure combined with privileged identity risk",
      account_id: "111122223333",
      severity: "high",
      score: 88,
      confidence: "candidate",
      rationale: "Correlated risk signals.",
      caveat: "Correlated posture signals only; this does not prove reachability.",
      steps: [],
      remediation: "Reduce public exposure and privilege.",
    }]);
    return response([]);
  });
  render(<App />);
  expect(await screen.findByText("Risk intelligence")).toBeInTheDocument();
  expect(await screen.findByText("Internet exposure combined with privileged identity risk")).toBeInTheDocument();
  expect(screen.getByText(/not proof that an exploit chain is reachable/i)).toBeInTheDocument();
});
