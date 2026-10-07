import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
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
const total = {
  active: 0,
  severities: { critical: 0, high: 0, medium: 0, low: 0 },
  states: { open: 0, acknowledged: 0, resolved: 0 },
  highest_risk: null,
  coverage_gaps: 0,
  latest_scan: null,
};
const response = (body: unknown, status = 200) => ({
  ok: status < 400,
  status,
  json: async () => body,
});
const fetchMock = vi.fn();
const base = (url: string) =>
  url.endsWith("/session")
    ? session
    : url.includes("/posture-summary")
      ? total
      : [];
beforeEach(() => {
  window.location.hash = "";
  setApiToken("");
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockImplementation(async (url: string) => response(base(url)));
});
afterEach(() => {
  cleanup();
  setApiToken("");
  vi.unstubAllGlobals();
});

test("empty demo is explicitly synthetic and does not claim a safe score", async () => {
  render(<App />);
  expect(
    await screen.findByText("Votre premier audit commence ici"),
  ).toBeInTheDocument();
  expect(screen.getByText(/Données fictives/)).toBeInTheDocument();
  expect(screen.queryByText(/100%/)).not.toBeInTheDocument();
});
test("navigation renders only the selected view", async () => {
  render(<App />);
  await screen.findByText("Commencez par ce qui compte.");
  fireEvent.click(
    screen.getByRole("button", { name: "Historique des audits" }),
  );
  expect(
    await screen.findByRole("heading", {
      level: 1,
      name: "Historique des audits",
    }),
  ).toHaveFocus();
  expect(
    screen.queryByText("Commencez par ce qui compte."),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText("Journal des actions · toutes sources"),
  ).toBeInTheDocument();
});
test("viewer cannot run audits", async () => {
  fetchMock.mockImplementation(async (url: string) =>
    response(
      url.endsWith("/session") ? { ...session, role: "viewer" } : base(url),
    ),
  );
  render(<App />);
  expect(
    await screen.findByRole("button", { name: "Auditer la démo" }),
  ).toBeDisabled();
});
test("scan failure remains visible after refresh and existing results stay available", async () => {
  fetchMock.mockImplementation(async (url: string) =>
    url.endsWith("/scans/demo")
      ? response(
          { detail: "Scan failed; previous findings were preserved" },
          503,
        )
      : response(base(url)),
  );
  render(<App />);
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Auditer la démo" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Auditer la démo" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "previous findings were preserved",
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Auditer la démo" }),
    ).toBeEnabled(),
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "previous findings were preserved",
  );
});
test("summary uses source totals even when displayed page is empty", async () => {
  fetchMock.mockImplementation(async (url: string) =>
    response(
      url.includes("/posture-summary")
        ? {
            ...total,
            active: 603,
            highest_risk: 96,
            severities: { ...total.severities, high: 603 },
          }
        : base(url),
    ),
  );
  render(<App />);
  expect(await screen.findByText("96")).toBeInTheDocument();
  expect(screen.getAllByText("603").length).toBeGreaterThan(0);
});
test("AWS desktop opens on real AWS and can reach onboarding", async () => {
  fetchMock.mockImplementation(async (url: string) =>
    response(
      url.endsWith("/session")
        ? { ...session, demo: false, desktop: true }
        : base(url),
    ),
  );
  render(<App />);
  const source = await screen.findByRole("combobox", {
    name: "Source des résultats",
  });
  expect(source).toHaveValue("aws");
  expect(screen.queryByText(/Données fictives/)).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Connexion AWS" }));
  expect(
    await screen.findByLabelText("ARN du rôle en lecture seule"),
  ).toBeInTheDocument();
});
test("failed role validation never saves the connection", async () => {
  fetchMock.mockImplementation(async (url: string) =>
    url.endsWith("/connections/aws/test")
      ? response({ detail: "Role access denied" }, 422)
      : response(
          url.endsWith("/session")
            ? { ...session, demo: false, desktop: true }
            : base(url),
        ),
  );
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Connexion AWS" }));
  fireEvent.change(screen.getByLabelText("Identifiant du compte"), {
    target: { value: "123456789012" },
  });
  fireEvent.change(screen.getByLabelText("ARN du rôle en lecture seule"), {
    target: { value: "arn:aws:iam::123456789012:role/test" },
  });
  fireEvent.change(screen.getByLabelText("External ID"), {
    target: { value: "external-value-123456" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Valider et enregistrer" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Role access denied",
  );
  expect(
    fetchMock.mock.calls.some(
      ([url, init]) =>
        String(url).endsWith("/connections/aws") && init?.method === "PUT",
    ),
  ).toBe(false);
});
test("API authentication stays memory-only and clears on logout", async () => {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/session"))
      return new Headers(init?.headers).get("Authorization") ===
        "Bearer test-token"
        ? response({ ...session, demo: false, tenant_id: "alpha" })
        : response({ detail: "Valid API token required" }, 401);
    return response(base(url));
  });
  render(<App />);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Se connecter" })).toBeEnabled(),
  );
  fireEvent.change(screen.getByLabelText("Jeton API"), {
    target: { value: "test-token" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Se connecter" }));
  expect(await screen.findByText("alpha")).toBeInTheDocument();
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
  fireEvent.click(screen.getByText("Se déconnecter"));
  expect(await screen.findByLabelText("Jeton API")).toHaveValue("");
});
