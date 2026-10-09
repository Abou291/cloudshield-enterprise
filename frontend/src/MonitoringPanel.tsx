import { useCallback, useEffect, useState } from "react";

import { acknowledgeAlert, getMonitorStatus, listMonitorAlerts, runMonitorCycle } from "./api";
import type { MonitorAlert, MonitorStatus, Session } from "./types";

const LABELS: Record<string, string> = {
  ok: "Running",
  partial: "Running with gaps",
  error: "Failing",
  stale: "Stopped (schedule missed)",
  never_run: "Never run",
};

export default function MonitoringPanel({ session }: { session: Session }) {
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [alerts, setAlerts] = useState<MonitorAlert[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextAlerts] = await Promise.all([getMonitorStatus(), listMonitorAlerts()]);
      setStatus(typeof nextStatus?.status === "string" ? nextStatus : null);
      setAlerts(Array.isArray(nextAlerts) ? nextAlerts : []);
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Monitoring unavailable");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await runMonitorCycle();
      setMessage(`Cycle ${result.status}: ${result.alerts_new} new alert(s).`);
      await refresh();
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : "Monitoring cycle failed");
    } finally {
      setBusy(false);
    }
  };

  const acknowledge = async (alertId: string) => {
    await acknowledgeAlert(alertId).catch(() => undefined);
    await refresh();
  };

  return (
    <section className="panel monitoring-panel" id="monitoring">
      <div className="panel-title">
        <div>
          <h2>Continuous monitoring</h2>
          <p>
            Behaviour alerts from CloudTrail and GuardDuty. CloudTrail events appear with a delay
            of up to about 15 minutes.
          </p>
        </div>
        <div>
          <button disabled={busy} onClick={() => void refresh()}>Refresh</button>
          {session.role === "operator" && (
            <button disabled={busy} onClick={() => void run()}>Run now</button>
          )}
        </div>
      </div>
      {message && <p role="status">{message}</p>}
      {status && (
        <div className="diagnostic-grid">
          <article><small>Monitor</small><strong>{LABELS[status.status] ?? status.status}</strong></article>
          <article><small>Last run</small>
            <strong>{status.last_run_at ? new Date(status.last_run_at).toLocaleString() : "never"}</strong></article>
          <article><small>Open alerts</small><strong>{status.open_alerts ?? 0}</strong></article>
          <article><small>Webhook</small><strong>{status.webhook_configured ? "configured" : "not configured"}</strong></article>
        </div>
      )}
      {status && status.errors.length > 0 && (
        <p>Collection gaps: {status.errors.join(", ")}</p>
      )}
      {alerts.length === 0 ? (
        <p>No open alerts.</p>
      ) : (
        <div className="table-wrap"><table>
          <thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Who</th><th>From</th><th></th></tr></thead>
          <tbody>{alerts.map((alert) => (
            <tr key={alert.alert_id}>
              <td>{new Date(alert.occurred_at).toLocaleString()}</td>
              <td>{alert.severity}</td>
              <td title={alert.summary}>{alert.rule_id} · {alert.title}</td>
              <td className="resource">{alert.principal}</td>
              <td>{alert.source_ip || "-"}</td>
              <td>{session.role === "operator" && (
                <button onClick={() => void acknowledge(alert.alert_id)}>Acknowledge</button>
              )}</td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
    </section>
  );
}
