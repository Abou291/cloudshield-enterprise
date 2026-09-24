import { useEffect, useState } from "react";

import {
  createBackup,
  getDiagnostics,
  getSecurityReport,
  restoreLatestBackup,
  runAwsDiagnostics,
} from "./api";
import type { AwsDiagnostics, Diagnostics, Session } from "./types";

export default function DiagnosticsPanel({
  session,
  source,
}: {
  session: Session;
  source: string;
}) {
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const [aws, setAws] = useState<AwsDiagnostics | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () =>
    getDiagnostics()
      .then(setDiagnostics)
      .catch((caught) =>
        setMessage(caught instanceof Error ? caught.message : "Diagnostics failed"),
      );

  useEffect(() => {
    void refresh();
  }, []);

  const runAws = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await runAwsDiagnostics();
      setAws(result);
      setMessage(result.message);
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "AWS diagnostics failed");
    } finally {
      setBusy(false);
    }
  };

  const backup = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await createBackup();
      setMessage(`Backup created: ${result.file_name} · SHA-256 ${result.sha256.slice(0, 16)}…`);
      await refresh();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Backup failed");
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!window.confirm("Restore the latest AegisShield database backup? Current local data will be replaced.")) {
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const result = await restoreLatestBackup();
      setMessage(`Restored backup: ${result.file_name}. Reloading local state…`);
      window.setTimeout(() => window.location.reload(), 600);
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Restore failed");
      setBusy(false);
    }
  };

  const exportReport = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const report = await getSecurityReport(source);
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `aegisshield-${source}-report-${new Date()
        .toISOString()
        .slice(0, 10)}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setMessage("Security report exported.");
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Report export failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel diagnostics-panel" id="diagnostics">
      <div className="panel-title">
        <div>
          <h2>Diagnostics & recovery</h2>
          <p>Local health, AWS access validation, backup and evidence export.</p>
        </div>
        <button disabled={busy} onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      {diagnostics && (
        <div className="diagnostic-grid">
          <article>
            <small>Version</small>
            <strong>{diagnostics.version}</strong>
          </article>
          <article>
            <small>Backend</small>
            <strong>{diagnostics.backend}</strong>
          </article>
          <article>
            <small>Database</small>
            <strong>
              {diagnostics.database} · {diagnostics.database_engine}
            </strong>
          </article>
          <article>
            <small>AWS connection</small>
            <strong>{diagnostics.aws_configured ? "configured" : "not configured"}</strong>
          </article>
          <article>
            <small>Local backups</small>
            <strong>{diagnostics.backup_count}</strong>
          </article>
        </div>
      )}

      {aws && (
        <p className={aws.status === "ok" ? "notice" : "error"}>
          {aws.code} · {aws.message}
        </p>
      )}
      {message && !aws && <p className="notice">{message}</p>}

      <div className="diagnostic-actions">
        {!session.demo && (
          <button disabled={busy || !diagnostics?.aws_configured} onClick={() => void runAws()}>
            Test AWS access
          </button>
        )}
        {session.desktop && (
          <>
            <button disabled={busy} onClick={() => void backup()}>
              Create backup
            </button>
            <button disabled={busy || (diagnostics?.backup_count ?? 0) === 0} onClick={() => void restore()}>
              Restore latest
            </button>
          </>
        )}
        <button disabled={busy} onClick={() => void exportReport()}>
          Export security report
        </button>
      </div>

      {diagnostics?.data_directory && (
        <p className="diagnostic-path">
          Local data: <code>{diagnostics.data_directory}</code>
        </p>
      )}
    </section>
  );
}
