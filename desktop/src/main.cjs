const { app, BrowserWindow, dialog, session } = require("electron");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

let backend;
let apiToken;
let instanceNonce;
const PORT = 8765;
const API_PATTERN = `http://127.0.0.1:${PORT}/api/v1/*`;

function backendPath() {
  const executable =
    process.platform === "win32" ? "aegisshield-api.exe" : "aegisshield-api";
  return app.isPackaged
    ? path.join(process.resourcesPath, "backend", executable)
    : path.join(__dirname, "../../backend/dist", executable);
}

function startBackend() {
  const dataDir = path.join(app.getPath("userData"), "data");
  fs.mkdirSync(dataDir, { recursive: true });

  apiToken = crypto.randomBytes(32).toString("base64url");
  instanceNonce = crypto.randomBytes(24).toString("base64url");
  const tokenHash = crypto.createHash("sha256").update(apiToken).digest("hex");
  const principal = [
    {
      key_sha256: tokenHash,
      tenant_id: "desktop",
      subject: "local-desktop",
      role: "operator",
    },
  ];

  const environment = {
    ...process.env,
    AEGISSHIELD_PORT: String(PORT),
    CLOUDSHIELD_ENV: "production",
    CLOUDSHIELD_DESKTOP_MODE: "true",
    CLOUDSHIELD_INSTANCE_NONCE: instanceNonce,
    CLOUDSHIELD_DESKTOP_CONFIG_PATH: path.join(
      dataDir,
      "aws-connection.json",
    ),
    CLOUDSHIELD_DEMO_MODE: "false",
    CLOUDSHIELD_API_KEYS: JSON.stringify(principal),
    CLOUDSHIELD_DATABASE_URL: `sqlite:///${path
      .join(dataDir, "aegisshield.db")
      .replaceAll("\\", "/")}`,
    CLOUDSHIELD_CORS_ORIGINS: JSON.stringify(["null"]),
    CLOUDSHIELD_RATE_LIMIT_PER_MINUTE: "240",
  };

  backend = spawn(backendPath(), [], {
    env: environment,
    windowsHide: true,
    stdio: "ignore",
  });
  backend.on("error", (error) => {
    dialog.showErrorBox(
      "AegisShield",
      `Unable to start the local security service: ${error.message}`,
    );
  });
}

function configureSession() {
  session.defaultSession.webRequest.onBeforeSendHeaders(
    { urls: [API_PATTERN] },
    (details, callback) => {
      details.requestHeaders.Authorization = `Bearer ${apiToken}`;
      callback({ requestHeaders: details.requestHeaders });
    },
  );
  session.defaultSession.setPermissionRequestHandler(
    (_webContents, _permission, callback) => callback(false),
  );
}

async function waitForBackend(remaining = 30) {
  try {
    const response = await fetch(`http://127.0.0.1:${PORT}/api/v1/health`);
    if (response.ok) {
      const health = await response.json();
      if (health.status === "ok" && health.instance === instanceNonce) return;
    }
  } catch (_) {
    // The child process is still starting.
  }
  if (remaining === 0) {
    throw new Error("The local security service did not become ready");
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  return waitForBackend(remaining - 1);
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 940,
    minWidth: 1080,
    minHeight: 720,
    title: "AegisShield",
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: !app.isPackaged,
    },
  });

  window.removeMenu();
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith("file://")) event.preventDefault();
  });

  const uiDirectory = app.isPackaged
    ? path.join(process.resourcesPath, "ui")
    : path.join(__dirname, "../../frontend/dist");
  window.loadFile(path.join(uiDirectory, "index.html"));
  window.once("ready-to-show", () => window.show());
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.whenReady().then(async () => {
    startBackend();
    configureSession();
    try {
      await waitForBackend();
      createWindow();
    } catch (error) {
      dialog.showErrorBox("AegisShield", error.message);
      app.quit();
    }
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
app.on("before-quit", () => {
  apiToken = undefined;
  instanceNonce = undefined;
  if (backend && !backend.killed) backend.kill();
});
