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
        setMessage(caught instanceof Error ? caught.message : "Échec du diagnostic"),
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
      setMessage(caught instanceof Error ? caught.message : "Échec du diagnostic AWS");
    } finally {
      setBusy(false);
    }
  };

  const backup = async () => {
    setAws(null);
    setBusy(true);
    setMessage(null);
    try {
      const result = await createBackup();
      setMessage(`Sauvegarde créée : ${result.file_name} · SHA-256 ${result.sha256.slice(0, 16)}…`);
      await refresh();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Échec de la sauvegarde");
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!window.confirm("Restaurer la dernière sauvegarde AegisShield ? Les données locales actuelles seront remplacées.")) {
      return;
    }
    setBusy(true);
    setAws(null);
    setMessage(null);
    try {
      const result = await restoreLatestBackup();
      setMessage(`Sauvegarde restaurée : ${result.file_name}. Rechargement des données…`);
      window.setTimeout(() => window.location.reload(), 600);
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Échec de la restauration");
      setBusy(false);
    }
  };

  const exportReport = async () => {
    setAws(null);
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
      setMessage("Rapport exporté.");
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Échec de l’export");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel diagnostics-panel" id="diagnostics">
      <div className="panel-title">
        <div>
          <h2>Application et données</h2>
          <p>État du service local, accès AWS et sauvegardes.</p>
        </div>
        <button disabled={busy} onClick={() => void refresh()}>
          Actualiser
        </button>
      </div>

      {diagnostics && (
        <div className="diagnostic-grid">
          <article>
            <small>Version</small>
            <strong>{diagnostics.version}</strong>
          </article>
          <article>
            <small>Service local</small>
            <strong>{diagnostics.backend}</strong>
          </article>
          <article>
            <small>Base de données</small>
            <strong>
              {diagnostics.database} · {diagnostics.database_engine}
            </strong>
          </article>
          <article>
            <small>Connexion AWS</small>
            <strong>{diagnostics.aws_configured ? "configurée" : "non configurée"}</strong>
          </article>
          <article>
            <small>Sauvegardes locales</small>
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
          <button disabled={busy || session.role !== "operator" || !diagnostics?.aws_configured} onClick={() => void runAws()}>
            Tester l’accès AWS
          </button>
        )}
        {session.desktop && (
          <>
            <button disabled={busy || session.role !== "operator"} onClick={() => void backup()}>
              Créer une sauvegarde
            </button>
            <button disabled={busy || session.role !== "operator" || (diagnostics?.backup_count ?? 0) === 0} onClick={() => void restore()}>
              Restaurer la dernière
            </button>
          </>
        )}
        <button disabled={busy} onClick={() => void exportReport()}>
          Exporter le rapport JSON
        </button>
      </div>

      {diagnostics?.data_directory && (
        <p className="diagnostic-path">
          Données locales : <code>{diagnostics.data_directory}</code>
        </p>
      )}
    </section>
  );
}
