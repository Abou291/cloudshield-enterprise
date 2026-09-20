import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

import App from "./App";
import { setApiToken } from "./api";

const session = { tenant_id: "demo", subject: "local-demo", role: "operator", demo: true, aws_enabled: false };
const response = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
const fetchMock = vi.fn();

beforeEach(() => {
  setApiToken(""); fetchMock.mockReset(); vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockImplementation(async (url: string) =>
    response(url.endsWith("/session") ? session : []));
});
afterEach(() => { cleanup(); setApiToken(""); });

test("renders the empty dashboard", async () => {
  render(<App />);
  expect(screen.getByText("CloudShield")).toBeInTheDocument();
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
