import { useEffect, useState } from "react";

import { getAttackPaths, getExecutiveSummary } from "./api";
import type { AttackPath, ExecutiveSummary } from "./types";

export default function RiskIntelligencePanel({
  source,
  revision,
}: {
  source: string;
  revision: number;
}) {
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([getExecutiveSummary(source), getAttackPaths(source)])
      .then(([nextSummary, nextPaths]) => {
        if (!active) return;
        setSummary(nextSummary);
        setPaths(nextPaths);
        setError(null);
      })
      .catch((caught: unknown) => {
        if (!active) return;
        setError(caught instanceof Error ? caught.message : "Risk intelligence unavailable");
      });
    return () => {
      active = false;
    };
  }, [source, revision]);

  return (
    <section className="panel" id="risk-intelligence">
      <div className="panel-title">
        <div>
          <h2>Risk intelligence</h2>
          <p>Executive posture summary and conservative attack-path candidates.</p>
        </div>
        <span>{summary ? `${summary.findings} active findings` : "Loading…"}</span>
      </div>
      {error && <div role="alert" className="error">{error}</div>}
      {summary && (
        <>
          <div className="score-grid">
            <article className="metric">
              <strong>{summary.internet_exposed}</strong>
              <small>internet-exposed risks</small>
            </article>
            <article className="metric">
              <strong>{summary.privileged}</strong>
              <small>privileged risks</small>
            </article>
            <article className="metric">
              <strong>{summary.sensitive_data}</strong>
              <small>sensitive-data risks</small>
            </article>
            <article className="metric">
              <strong>{summary.attack_path_candidates}</strong>
              <small>attack-path candidates</small>
            </article>
          </div>
          <p className="notice">
            {summary.accounts_affected} account(s) · {summary.regions_affected} region(s) represented.
            Candidates are prioritization signals, not proof that an exploit chain is reachable.
          </p>
        </>
      )}
      {paths.length === 0 ? (
        <div className="empty">
          <h3>No correlated attack-path candidate</h3>
          <p>Individual findings can still be important. Correlation requires multiple independent risk signals.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Priority</th><th>Candidate</th><th>Account</th><th>Signals</th></tr>
            </thead>
            <tbody>
              {paths.slice(0, 10).map((path) => (
                <tr key={path.path_id}>
                  <td><span className="risk">{path.score}</span></td>
                  <td>
                    <strong>{path.title}</strong>
                    <small>{path.rationale}</small>
                  </td>
                  <td className="resource">{path.account_id}</td>
                  <td>{path.steps.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {paths[0] && (
        <p className="notice">
          Priority action: {paths[0].remediation}
        </p>
      )}
    </section>
  );
}
