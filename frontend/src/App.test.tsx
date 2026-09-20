import { render, screen } from "@testing-library/react";
import { vi } from "vitest";

import App from "./App";

vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => [] }));

test("renders the empty dashboard", async () => {
  render(<App />);
  expect(screen.getByText("CloudShield")).toBeInTheDocument();
  expect(await screen.findByText("No findings loaded")).toBeInTheDocument();
});

