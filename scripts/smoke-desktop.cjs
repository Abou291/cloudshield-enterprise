/* Exercise the actual packaged renderer and secured backend on Windows. */
const { _electron: electron } = require("../desktop/node_modules/playwright");
const path = require("node:path");
const fs = require("node:fs");
(async () => {
  const errors = [];
  const desktop = await electron.launch({
    executablePath: path.resolve("desktop/dist/win-unpacked/AegisShield.exe"),
    timeout: 90000,
  });
  try {
    const page = await desktop.firstWindow({ timeout: 90000 });
    page.on("pageerror", (error) => errors.push(error.message));
    await page
      .getByRole("heading", { name: "Vue d’ensemble", exact: true })
      .waitFor();
    const background = await page
      .locator(".sidebar")
      .evaluate((el) => getComputedStyle(el).backgroundColor);
    if (background !== "rgb(255, 255, 255)")
      throw Error("Light desktop styles did not load");
    await page
      .getByRole("combobox", { name: "Source des résultats" })
      .selectOption("demo-fixture");
    await page
      .getByRole("button", { name: "Auditer la démo", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Audit terminé" })
      .waitFor();
    fs.mkdirSync("desktop/dist/screenshots", { recursive: true });
    await page.screenshot({
      path: "desktop/dist/screenshots/overview.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: /Plan de correction/ }).click();
    await page
      .getByRole("button", { name: /^Ouvrir / })
      .first()
      .click();
    await page.getByRole("dialog").waitFor();
    await page
      .getByRole("button", { name: "Prendre en charge", exact: true })
      .click();
    await page.getByText(/· En cours/).waitFor();
    await page.screenshot({
      path: "desktop/dist/screenshots/finding.png",
      fullPage: true,
    });
    await page.keyboard.press("Escape");
    await page.getByRole("dialog").waitFor({ state: "detached" });
    await page
      .getByRole("button", { name: "Historique des audits", exact: true })
      .click();
    await page.getByText("Terminé", { exact: true }).first().waitFor();
    if (errors.length) throw Error(errors.join("\n"));
    console.log(
      "Packaged Windows renderer: CSS, scan, navigation, details, acknowledgement, Escape and history passed.",
    );
  } finally {
    await desktop.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
