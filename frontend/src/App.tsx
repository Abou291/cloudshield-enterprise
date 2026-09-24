import { useEffect, useMemo, useState } from "react";
import { Activity, Cloud, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";

import { ApiError, listAudit, listFindings, listScans, runAwsScan, runDemoScan, saveAwsConnection, testAwsConnection } from "./api";
import AccessGate from "./AccessGate";
import DiagnosticsPanel from "./DiagnosticsPanel";
import SecurityCopilot from "./SecurityCopilot";
import type { AuditEvent, AwsConnectionInput, Finding, ScanHistory, Session, Severity } from "./types";
import "./styles.css";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

function AwsConnectionSetup({ onDone }: { onDone: () => void }) {
  const [connection, setConnection] = useState<AwsConnectionInput>({
    role_arn: "",
    external_id: "",
    account_id: "",
    region: "eu-west-3",
    profile_name: "default",
  });
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const update = (field: keyof AwsConnectionInput, value: string) => setConnection((current) => ({ ...current, [field]: value }));
  const validate = async () => {
    setBusy(true); setMessage(null);
    try { await testAwsConnection(connection); setMessage("AWS role validated. You can save this connection."); }
    catch (caught) { setMessage(caught instanceof Error ? caught.message : "AWS role validation failed"); }
    finally { setBusy(false); }
  };
  const save = async () => {
    setBusy(true); setMessage(null);
    try { await saveAwsConnection(connection); setMessage("Connection saved locally. AWS credentials were not stored."); onDone(); }
    catch (caught) { setMessage(caught instanceof Error ? caught.message : "Could not save connection"); }
    finally { setBusy(false); }
  };
  return <section className="panel connection-panel" id="connection">
    <div className="panel-title"><div><h2>Connect an AWS account</h2><p>Uses your local AWS SSO/profile to assume a read-only role. No access key is stored.</p></div></div>
    <form onSubmit={(event) => { event.preventDefault(); void validate(); }}>
      <label>Role ARN<input required value={connection.role_arn} onChange={(event) => update("role_arn", event.target.value)} placeholder="arn:aws:iam::123456789012:role/aegisshield-readonly" /></label>
      <label>Account ID<input required pattern="[0-9]{12}" value={connection.account_id} onChange={(event) => update("account_id", event.target.value)} placeholder="123456789012" /></label>
      <label>External ID<input required minLength={16} value={connection.external_id} onChange={(event) => update("external_id", event.target.value)} placeholder="A unique value from the AWS trust policy" /></label>
      <label>AWS profile<input value={connection.profile_name ?? ""} onChange={(event) => update("profile_name", event.target.value)} placeholder="default" /><small>Use the AWS CLI/SSO profile already configured on this PC.</small></label>
      <label>Default region<input required value={connection.region} onChange={(event) => update("region", event.target.value)} placeholder="eu-west-3" /></label>
      <div className="connection-actions"><button disabled={busy} type="submit">{busy ? "Validating…" : "Validate AWS role"}</button><button disabled={busy} type="button" onClick={() => void save()}>Save connection</button></div>
    </form>
    {message && <p className={message.startsWith("AWS role validated") || message.startsWith("Connection saved") ? "notice" : "error"}>{message}</p>}
  </section>;
}

function Dashboard({ session, logout }: { session: Session; logout: () => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [source, setSource] = useState(
    session.demo || !session.aws_enabled ? "demo-fixture" : "aws",
  );
  const [scans, setScans] = useState<ScanHistory[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [fetching, setFetching] = useState(true);
  const [showConnection, setShowConnection] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([listFindings(source, offset), listScans(), listAudit()])
      .then(([items, history, events]) => {
        if (active) {
          setFindings(items); setScans(history); setAudit(events); setError(null);
        }
      })
      .catch((caught: unknown) => {
        if (active) setError(caught instanceof Error ? caught.message : "Unable to load findings");
        if (active && caught instanceof ApiError && caught.status === 401) logout();
      }).finally(() => { if (active) setFetching(false); });
    return () => {
      active = false;
    };
  }, [source, offset, revision, logout]);

  const scan = async () => {
    setLoading(true);
    setScanError(null);
    try {
      if (source === "aws") await runAwsScan(); else await runDemoScan();
    } catch (caught) {
      setScanError(caught instanceof Error ? caught.message : "Scan failed");
    } finally {
      setLoading(false);
      setFetching(true);
      setRevision((value) => value + 1);
    }
  };

  const counts = useMemo(
    () =>
      severityOrder.reduce<Record<Severity, number>>(
        (accumulator, severity) => ({
          ...accumulator,
          [severity]: findings.filter((item) => item.severity === severity).length,
        }),
        { critical: 0, high: 0, medium: 0, low: 0 },
      ),
    [findings],
  );
  const highestRisk = findings.length ? Math.max(...findings.map((item) => item.risk.score)) : null;
  const latestScan = scans.find((item) => item.source === source);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><ShieldCheck size={28} /><span>AegisShield</span></div>
        <p className="edition">Desktop · Security foundation</p>
        <nav>
          <a className="active" href="#overview"><Activity size={18} /> Overview</a>
          <a href="#findings"><TriangleAlert size={18} /> Findings</a>
          <a href="#scans"><Cloud size={18} /> Scan history</a>
          <a href="#audit">Audit trail</a>
          <a href="#diagnostics">Diagnostics</a>
        </nav>
        <div className="scope">
          <span className="status-dot" /> {session.tenant_id}
          <small>{session.demo ? "Local demonstration" : `${session.subject} · ${session.role}`}</small>
          {!session.demo && !session.desktop && <button className="link" onClick={logout}>Sign out</button>}
        </div>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">SECURITY POSTURE</p>
            <h1>Overview</h1>
            <p>Prioritized, explainable risks across your AWS inventory.</p>
          </div>
          <button onClick={scan} disabled={loading || fetching || session.role !== "operator"
            || (source === "aws" && !session.aws_enabled)}>
            <RefreshCw className={loading ? "spin" : ""} size={18} />
            {loading ? "Scanning…" : source === "aws" ? "Run AWS scan" : "Run demo scan"}
          </button>
        </header>

        <div className="toolbar">
          <label htmlFor="source">Data source</label>
          <select id="source" value={source} disabled={loading} onChange={(event) => {
            setSource(event.target.value); setOffset(0); setFindings([]); setSelected(null);
            setFetching(true);
          }}>
            <option value="demo-fixture">Demonstration fixtures</option>
            {!session.demo && <option value="aws">AWS inventory</option>}
          </select>
          <button disabled={loading || fetching} onClick={() => {
            setFetching(true); setRevision((value) => value + 1);
          }}>Refresh</button>
        </div>
        {source === "demo-fixture" && <p className="notice">Synthetic data — not an assessment of your AWS environment.</p>}
        {!session.demo && source === "aws" && !session.aws_enabled &&
          <p className="notice">An administrator must configure your organization's AWS connection.</p>}
        {latestScan && <p className="notice">Latest scan: {latestScan.status} · {new Date(latestScan.started_at).toLocaleString()}.
          {latestScan.status !== "succeeded" && " Displayed findings may be stale."}</p>}
        {error && <div role="alert" className="error">{error}</div>}
        {scanError && <div role="alert" className="error">{scanError}</div>}
        {!session.aws_enabled && <button className="connect-aws" onClick={() => setShowConnection(true)}>Connect AWS account</button>}
        {showConnection && <AwsConnectionSetup onDone={() => { setShowConnection(false); window.location.reload(); }} />}

        <section className="score-grid" id="overview">
          <article className="score-card">
            <div className="score-ring" style={{ "--score": highestRisk ?? 0 } as React.CSSProperties}>
              <strong>{highestRisk ?? "—"}</strong><span>{highestRisk !== null ? "/100" : "No data"}</span>
            </div>
            <div><p>Highest displayed risk</p><small>Finding priority, not a compliance or security score.</small></div>
          </article>
          {severityOrder.map((severity) => (
            <article className="metric" key={severity}>
              <SeverityBadge severity={severity} />
              <strong>{counts[severity]}</strong>
              <small>on this page</small>
            </article>
          ))}
        </section>

        <section className="panel" id="findings">
          <div className="panel-title">
            <div><h2>Top risks</h2><p>Ordered by contextual risk, not severity alone.</p></div>
            <span>{fetching ? "Loading…" : `${findings.length} findings · page ${offset / 100 + 1}`}</span>
          </div>
          {findings.length === 0 ? (
            <div className="empty"><ShieldCheck size={36} /><h3>No findings loaded</h3><p>Absence of findings does not establish security. Check scan status and coverage.</p></div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Risk</th><th /></tr></thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.fingerprint}>
                      <td><SeverityBadge severity={finding.severity} /></td>
                      <td><strong>{finding.title}</strong><small>{finding.rule_id} · {finding.region}</small></td>
                      <td className="resource">{finding.resource_id}</td>
                      <td><span className="risk">{finding.risk.score}</span></td>
                      <td><button className="link" onClick={() => setSelected(finding)}>Investigate</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <div className="toolbar">
          <button disabled={offset === 0 || fetching || loading} onClick={() => {
            setFetching(true); setOffset((value) => Math.max(0, value - 100));
          }}>Previous page</button>
          <button disabled={findings.length < 100 || offset >= 100000 || fetching || loading}
            onClick={() => { setFetching(true); setOffset((value) => value + 100); }}>Next page</button>
        </div>
        <section className="panel" id="scans">
          <div className="panel-title"><h2>Scan history</h2><span>Latest 100 · all sources</span></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Started</th><th>Source</th><th>Status</th><th>Assets</th><th>Findings</th></tr></thead>
            <tbody>{scans.map((item) => <tr key={item.scan_id}>
              <td>{new Date(item.started_at).toLocaleString()}</td><td>{item.source}</td>
              <td>{item.status}{item.error_code && ` · ${item.error_code}`}</td>
              <td>{item.status === "succeeded" ? item.assets_scanned : "—"}</td>
              <td>{item.status === "succeeded" ? item.findings_count : "—"}</td>
            </tr>)}</tbody>
          </table></div>
          {!scans.length && <p className="notice">No scans recorded.</p>}
        </section>
        <section className="panel" id="audit">
          <div className="panel-title"><h2>Audit trail</h2><span>Latest 100 events</span></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Scan</th></tr></thead>
            <tbody>{audit.map((item) => <tr key={item.event_id}>
              <td>{new Date(item.timestamp).toLocaleString()}</td><td>{item.subject}</td>
              <td>{item.action}</td><td className="resource">{item.object_id}</td>
            </tr>)}</tbody>
          </table></div>
        </section>

        <DiagnosticsPanel session={session} source={source} />
      </main>

      <SecurityCopilot findings={findings} />

      {selected && (
        <div className="overlay" role="presentation" onClick={() => setSelected(null)}>
          <aside className="drawer" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <button className="close" onClick={() => setSelected(null)}>×</button>
            <SeverityBadge severity={selected.severity} />
            <h2>{selected.title}</h2>
            <p>{selected.description}</p>
            <h3>Risk {selected.risk.score}/100</h3>
            <ul>{selected.risk.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
            <h3>Evidence</h3>
            <pre>{JSON.stringify(selected.evidence, null, 2)}</pre>
            <h3>Remediation</h3>
            <p>{selected.recommendation}</p>
          </aside>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return <AccessGate>{(session, logout) => <Dashboard session={session} logout={logout} />}</AccessGate>;
}
