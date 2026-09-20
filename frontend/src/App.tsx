import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Cloud, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";

import { listFindings, runDemoScan } from "./api";
import type { Finding, Severity } from "./types";
import "./styles.css";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

function App() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setFindings(await listFindings());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load findings");
    }
  }, []);

  useEffect(() => {
    let active = true;
    listFindings()
      .then((items) => {
        if (active) setFindings(items);
      })
      .catch((caught: unknown) => {
        if (active) setError(caught instanceof Error ? caught.message : "Unable to load findings");
      });
    return () => {
      active = false;
    };
  }, []);

  const scan = async () => {
    setLoading(true);
    try {
      await runDemoScan();
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Scan failed");
    } finally {
      setLoading(false);
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
  const securityScore = findings.length
    ? Math.max(0, 100 - Math.round(findings.reduce((sum, item) => sum + item.risk.score, 0) / 8))
    : 100;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><ShieldCheck size={28} /><span>CloudShield</span></div>
        <p className="edition">Enterprise · AWS V1</p>
        <nav>
          <a className="active" href="#overview"><Activity size={18} /> Overview</a>
          <a href="#findings"><TriangleAlert size={18} /> Findings</a>
          <a href="#assets"><Cloud size={18} /> Assets</a>
        </nav>
        <div className="scope">
          <span className="status-dot" /> Local demonstration
          <small>No AWS credentials required</small>
        </div>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">SECURITY POSTURE</p>
            <h1>Overview</h1>
            <p>Prioritized, explainable risks across your AWS inventory.</p>
          </div>
          <button onClick={scan} disabled={loading}>
            <RefreshCw className={loading ? "spin" : ""} size={18} />
            {loading ? "Scanning…" : "Run demo scan"}
          </button>
        </header>

        {error && <div className="error">{error}</div>}

        <section className="score-grid" id="overview">
          <article className="score-card">
            <div className="score-ring" style={{ "--score": securityScore } as React.CSSProperties}>
              <strong>{securityScore}</strong><span>/100</span>
            </div>
            <div><p>Security score</p><small>Lower scores mean more contextual risk.</small></div>
          </article>
          {severityOrder.map((severity) => (
            <article className="metric" key={severity}>
              <SeverityBadge severity={severity} />
              <strong>{counts[severity]}</strong>
              <small>open findings</small>
            </article>
          ))}
        </section>

        <section className="panel" id="findings">
          <div className="panel-title">
            <div><h2>Top risks</h2><p>Ordered by contextual risk, not severity alone.</p></div>
            <span>{findings.length} findings</span>
          </div>
          {findings.length === 0 ? (
            <div className="empty"><ShieldCheck size={36} /><h3>No findings loaded</h3><p>Run the safe demo scan to populate the dashboard.</p></div>
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
      </main>

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

export default App;
