const { app, BrowserWindow, dialog } = require("electron");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

let backend;
const PORT = 8765;

function backendPath() {
  const executable = process.platform === "win32" ? "aegisshield-api.exe" : "aegisshield-api";
  return app.isPackaged
    ? path.join(process.resourcesPath, "backend", executable)
    : path.join(__dirname, "../../../backend/dist", executable);
}

function startBackend() {
  const dataDir = path.join(app.getPath("userData"), "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const environment = {
    ...process.env,
    AEGISSHIELD_PORT: String(PORT),
    CLOUDSHIELD_DESKTOP_MODE: "true",
    CLOUDSHIELD_DESKTOP_CONFIG_PATH: path.join(dataDir, "aws-connection.json"),
    CLOUDSHIELD_DEMO_MODE: "true",
    CLOUDSHIELD_DATABASE_URL: `sqlite:///${path.join(dataDir, "aegisshield.db").replaceAll("\\", "/")}`,
    CLOUDSHIELD_CORS_ORIGINS: "null,http://127.0.0.1:5173,http://localhost:5173",
  };
  backend = spawn(backendPath(), [], { env: environment, windowsHide: true });
  backend.on("error", (error) => dialog.showErrorBox("AegisShield", `Unable to start the local security service: ${error.message}`));
}

async function waitForBackend(remaining = 24) {
  try {
    const response = await fetch(`http://127.0.0.1:${PORT}/api/v1/health`);
    if (response.ok) return;
  } catch (_) { /* The child process is still starting. */ }
  if (remaining === 0) throw new Error("The local security service did not become ready");
  await new Promise((resolve) => setTimeout(resolve, 500));
  return waitForBackend(remaining - 1);
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440, height: 940, minWidth: 1080, minHeight: 720, title: "AegisShield",
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  window.removeMenu();
  const uiDirectory = app.isPackaged ? path.join(process.resourcesPath, "ui") : path.join(__dirname, "../../../frontend/dist");
  window.loadFile(path.join(uiDirectory, "index.html"));
}

app.whenReady().then(async () => {
  startBackend();
  try { await waitForBackend(); createWindow(); }
  catch (error) { dialog.showErrorBox("AegisShield", error.message); app.quit(); }
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", () => { if (backend && !backend.killed) backend.kill(); });
