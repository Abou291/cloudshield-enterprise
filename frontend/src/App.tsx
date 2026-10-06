import { useEffect, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Cloud,
  FileClock,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import AccessGate from "./AccessGate";
import DiagnosticsPanel from "./DiagnosticsPanel";
import {
  ApiError,
  getAwsConnection,
  getFinding,
  getPostureSummary,
  getSecurityReport,
  getSession,
  listAudit,
  listFindings,
  listScans,
  runAwsScan,
  runDemoScan,
  saveAwsConnection,
  testAwsConnection,
  updateFindingStatus,
} from "./api";
import type {
  AuditEvent,
  AwsConnectionInput,
  Finding,
  PostureSummary,
  ScanHistory,
  Session,
  Severity,
} from "./types";
import "./styles.css";

const severityNames: Record<Severity, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};
const statusNames = {
  open: "À traiter",
  acknowledged: "En cours",
  resolved: "Fermée",
};
const scanNames = {
  succeeded: "Terminé",
  failed: "Échec",
  running: "En cours",
  interrupted: "Interrompu",
};
const pages = {
  overview: {
    title: "Vue d’ensemble",
    subtitle: "L’essentiel pour décider quoi corriger.",
    icon: LayoutDashboard,
  },
  findings: {
    title: "Plan de correction",
    subtitle: "Comprendre les risques. Agir dans le bon ordre.",
    icon: ListChecks,
  },
  history: {
    title: "Historique des audits",
    subtitle: "Retrouver les contrôles et leurs résultats.",
    icon: FileClock,
  },
  connection: {
    title: "Connexion AWS",
    subtitle: "Un accès limité à la lecture de vos configurations.",
    icon: Cloud,
  },
  settings: {
    title: "Paramètres",
    subtitle: "Santé de l’application et données locales.",
    icon: Settings2,
  },
};
type Page = keyof typeof pages;
const pageFromHash = (): Page => {
  const p = window.location.hash.slice(1);
  return p in pages ? (p as Page) : "overview";
};
const date = (value?: string | null) =>
  value
    ? new Date(
        value.endsWith("Z") || /[+-]\d\d:\d\d$/.test(value)
          ? value
          : value + "Z",
      ).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" })
    : "—";
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "L’opération a échoué. Réessayez.";
function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge-${severity}`}>
      <i />
      {severityNames[severity]}
    </span>
  );
}

function AwsSetup({
  session,
  onDone,
}: {
  session: Session;
  onDone: (session: Session) => void;
}) {
  const [connection, setConnection] = useState<AwsConnectionInput>({
    role_arn: "",
    account_id: "",
    external_id: "",
    profile_name: "default",
    region: "eu-west-3",
    scan_all_regions: false,
  });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    if (session.desktop && session.aws_enabled)
      getAwsConnection()
        .then((value) => {
          if (active) setConnection((current) => ({ ...current, ...value }));
        })
        .catch((error) => {
          if (active) {
            setFailed(true);
            setMessage(errorText(error));
          }
        });
    return () => {
      active = false;
    };
  }, [session.desktop, session.aws_enabled]);
  const update = (key: keyof AwsConnectionInput, value: string | boolean) => {
    setConnection((current) => ({ ...current, [key]: value }));
    setMessage("");
  };
  return (
    <div className="connection-layout">
      <section className="panel connection-panel">
        <div className="panel-title">
          <div>
            <h2>
              {session.aws_enabled
                ? "Votre compte AWS"
                : "Connecter votre premier compte"}
            </h2>
            <p>
              Les identifiants temporaires restent gérés par votre profil AWS.
            </p>
          </div>
          <LockKeyhole size={20} />
        </div>
        {!session.desktop ? (
          <div className="empty">
            <Cloud size={28} />
            <h3>
              {session.demo
                ? "Vous explorez la démonstration"
                : "Connexion gérée par votre administrateur"}
            </h3>
            <p>
              {session.demo
                ? "Ouvrez l’application Windows pour configurer votre accès AWS réel."
                : "La configuration de cette version serveur est administrée côté API."}
            </p>
          </div>
        ) : (
          <form
            onSubmit={async (event) => {
              event.preventDefault();
              setBusy(true);
              setFailed(false);
              setMessage("Validation du rôle AWS…");
              try {
                await testAwsConnection(connection);
                await saveAwsConnection(connection);
                onDone(await getSession());
                setMessage(
                  "Connexion validée et enregistrée. Vous pouvez lancer votre audit.",
                );
              } catch (error) {
                setFailed(true);
                setMessage(errorText(error));
              } finally {
                setBusy(false);
              }
            }}
          >
            <fieldset disabled={busy}>
              <label>
                Identifiant du compte
                <input
                  required
                  pattern="[0-9]{12}"
                  maxLength={12}
                  placeholder="123456789012"
                  value={connection.account_id}
                  onChange={(e) => update("account_id", e.target.value)}
                />
              </label>
              <label>
                ARN du rôle en lecture seule
                <input
                  required
                  pattern="arn:aws:iam::[0-9]{12}:role/.+"
                  placeholder="arn:aws:iam::123456789012:role/aegisshield-readonly"
                  value={connection.role_arn}
                  onChange={(e) => update("role_arn", e.target.value)}
                />
              </label>
              <label>
                External ID
                <input
                  required
                  minLength={16}
                  maxLength={1224}
                  autoComplete="off"
                  type="password"
                  placeholder={
                    session.aws_enabled
                      ? "Saisissez à nouveau la valeur du rôle"
                      : "La valeur définie dans votre rôle AWS"
                  }
                  value={connection.external_id}
                  onChange={(e) => update("external_id", e.target.value)}
                />
              </label>
              <div className="form-pair">
                <label>
                  Profil AWS local
                  <input
                    value={connection.profile_name ?? ""}
                    onChange={(e) => update("profile_name", e.target.value)}
                    required
                    pattern="[A-Za-z0-9_.-]{1,128}"
                  />
                </label>
                <label>
                  Région principale
                  <input
                    value={connection.region}
                    onChange={(e) => update("region", e.target.value)}
                    required
                    pattern="[a-z]{2}(-[a-z0-9]+)+-[0-9]"
                  />
                </label>
              </div>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={connection.scan_all_regions}
                  onChange={(e) => update("scan_all_regions", e.target.checked)}
                />
                Auditer toutes les régions activées
              </label>
              <button
                className="primary"
                type="submit"
                disabled={session.role !== "operator"}
              >
                {busy ? (
                  <RefreshCw className="spin" size={16} />
                ) : (
                  <ShieldCheck size={16} />
                )}
                {busy ? "Validation…" : "Valider et enregistrer"}
              </button>
            </fieldset>
          </form>
        )}
        {message && (
          <p
            role={failed ? "alert" : "status"}
            className={failed ? "error" : "notice"}
          >
            {message}
          </p>
        )}
      </section>
      <aside className="setup-guide">
        <p className="eyebrow">AVANT DE COMMENCER</p>
        <h2>Trois étapes, un accès maîtrisé.</h2>
        <ol>
          <li>
            <strong>Préparer votre profil</strong>
            <p>
              Configurez AWS CLI avec votre accès IAM Identity Center, puis
              ouvrez une session SSO.
            </p>
            <code>aws sso login --profile votre-profil</code>
          </li>
          <li>
            <strong>Créer le rôle de lecture</strong>
            <p>
              Utilisez le modèle CloudFormation fourni avec la livraison et
              conservez son External ID. Le profil doit être autorisé à assumer
              ce rôle.
            </p>
          </li>
          <li>
            <strong>Valider la connexion</strong>
            <p>
              Renseignez les valeurs du rôle. L’application vérifie l’identité
              du compte avant l’enregistrement.
            </p>
          </li>
        </ol>
        <div className="trust-note">
          <LockKeyhole size={18} />
          <p>
            AegisShield ne modifie pas vos ressources AWS. Les corrections
            restent sous votre contrôle.
          </p>
        </div>
      </aside>
    </div>
  );
}

function FindingDialog({
  finding,
  operator,
  busy,
  onClose,
  onStatus,
  onVerify,
  feedback,
}: {
  finding: Finding;
  operator: boolean;
  busy: boolean;
  onClose: () => void;
  onStatus: (status: Finding["status"]) => void;
  onVerify: () => void;
  feedback: { error: string; notice: string };
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="finding-dialog"
      onCancel={onClose}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      aria-labelledby="finding-title"
    >
      <div className="dialog-content">
        <div className="dialog-top">
          <Badge severity={finding.severity} />
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Fermer le détail"
          >
            <X size={20} />
          </button>
        </div>
        {feedback.error && <p className="error" role="alert">{feedback.error}</p>}
        {feedback.notice && <p className="notice" role="status">{feedback.notice}</p>}
        <p className="eyebrow">
          {finding.rule_id} · {statusNames[finding.status]}
        </p>
        <h2 id="finding-title">{finding.title}</h2>
        <p>{finding.description}</p>
        <dl className="resource-detail">
          <div>
            <dt>Ressource</dt>
            <dd>{finding.resource_id}</dd>
          </div>
          <div>
            <dt>Compte / région</dt>
            <dd>
              {finding.account_id} · {finding.region}
            </dd>
          </div>
          <div>
            <dt>Dernière observation</dt>
            <dd>{date(finding.last_seen_at)}</dd>
          </div>
        </dl>
        <section className="detail-section">
          <span className="step-number">1</span>
          <div>
            <h3>
              Comprendre la priorité{" "}
              <span className="priority-value">{finding.risk.score}/100</span>
            </h3>
            <p className="muted">
              Score de priorité, pas une probabilité de compromission.
            </p>
            <ul>
              {finding.risk.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </div>
        </section>
        <section className="detail-section">
          <span className="step-number">2</span>
          <div>
            <h3>Corriger dans AWS</h3>
            <p>{finding.recommendation}</p>
            <p className="muted">
              Vérifiez l’impact sur vos services avant d’appliquer le
              changement.
            </p>
          </div>
        </section>
        <section className="detail-section">
          <span className="step-number">3</span>
          <div>
            <h3>Vérifier avec un nouvel audit</h3>
            <p>
              La fermeture automatique exige une nouvelle observation de la
              ressource sans cette alerte. Un contrôle incomplet conserve les
              alertes existantes.
            </p>
          </div>
        </section>
        <details>
          <summary>Preuves techniques</summary>
          <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
        </details>
        {operator && (
          <div className="dialog-actions">
            <button
              disabled={busy}
              onClick={() =>
                onStatus(
                  finding.status === "acknowledged" ? "open" : "acknowledged",
                )
              }
            >
              {finding.status === "acknowledged"
                ? "Remettre à traiter"
                : finding.status === "resolved"
                  ? "Reprendre le suivi"
                  : "Prendre en charge"}
            </button>
            <button className="primary" disabled={busy} onClick={onVerify}>
              <RefreshCw size={16} className={busy ? "spin" : ""} />
              Vérifier la correction
            </button>
          </div>
        )}
      </div>
    </dialog>
  );
}

function Dashboard({
  session: initialSession,
  logout,
}: {
  session: Session;
  logout: () => void;
}) {
  const [session, setSession] = useState(initialSession);
  const [page, setPage] = useState<Page>(pageFromHash);
  const [source, setSource] = useState(
    initialSession.demo ? "demo-fixture" : "aws",
  );
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [scans, setScans] = useState<ScanHistory[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [offset, setOffset] = useState(0);
  const [showResolved, setShowResolved] = useState(false);
  const [revision, setRevision] = useState(0);
  const [fetching, setFetching] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const titleRef = useRef<HTMLHeadingElement>(null);
  const navigated = useRef(false);
  useEffect(() => {
    const onHash = () => {
      const next = window.location.hash.slice(1);
      if (next in pages) setPage(next as Page);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    if (navigated.current) titleRef.current?.focus();
    navigated.current = true;
  }, [page]);
  useEffect(() => {
    let active = true;
    Promise.all([
      listFindings(source, offset, showResolved),
      getPostureSummary(source),
      listScans(),
      listAudit(),
    ])
      .then(([items, total, history, events]) => {
        if (active) {
          setFindings(items);
          setSummary(total);
          setScans(history);
          setAudit(events);
        }
      })
      .catch((error) => {
        if (active) {
          setError(errorText(error));
          if (error instanceof ApiError && error.status === 401) logout();
        }
      })
      .finally(() => {
        if (active) setFetching(false);
      });
    return () => {
      active = false;
    };
  }, [source, offset, showResolved, revision, logout]);
  const refresh = () => {
    setFetching(true);
    setRevision((n) => n + 1);
  };
  const navigate = (next: Page) => {
    window.location.hash = next;
    setPage(next);
  };
  const scan = async () => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result =
        source === "aws" ? await runAwsScan() : await runDemoScan();
      const incomplete = result.findings.some((f) => f.rule_id === "COV-001");
      setNotice(
        incomplete
          ? "Audit terminé avec des contrôles incomplets. Les alertes précédentes sont conservées."
          : `Audit terminé : ${result.assets_scanned} ressources inventoriées, ${result.findings_count} alertes observées.`,
      );
      if (selected) {
        const updated = await getFinding(source, selected.fingerprint);
        setSelected(updated);
        if (
          !incomplete &&
          selected.status !== "resolved" &&
          updated.status === "resolved"
        )
          setNotice(
            "La nouvelle observation ne retrouve plus cette alerte. Elle a été fermée automatiquement.",
          );
        else if (updated.status !== "resolved")
          setNotice(
            "L’alerte reste ouverte : consultez les preuves et le périmètre du nouvel audit.",
          );
      }
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
      refresh();
    }
  };
  const changeStatus = async (status: Finding["status"]) => {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      setSelected(
        await updateFindingStatus(selected.fingerprint, source, status),
      );
      refresh();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  };
  const exportReport = async () => {
    setBusy(true);
    setError("");
    try {
      const report = await getSecurityReport(source);
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(report, null, 2)], {
          type: "application/json",
        }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `AegisShield-audit-${source}-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice(
        "Rapport JSON exporté avec les alertes actives et leur empreinte d’intégrité.",
      );
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  };
  const latest = summary?.latest_scan;
  const canScan =
    session.role === "operator" && (source !== "aws" || session.aws_enabled);
  const visible = findings.filter(
    (item) =>
      (severity === "all" || item.severity === severity) &&
      `${item.title} ${item.resource_id} ${item.rule_id} ${item.account_id}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const activeFindings = findings.filter((item) => item.status !== "resolved");
  const scopedScans = scans.filter((item) => item.source === source);
  const openFinding = (finding: Finding) => setSelected(finding);
  const riskTable = (items: Finding[]) => (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Priorité</th>
            <th>Constat / ressource</th>
            <th>Région</th>
            <th>Suivi</th>
            <th>
              <span className="sr-only">Détail</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr key={f.fingerprint}>
              <td>
                <Badge severity={f.severity} />
                <span className="table-score">
                  {f.risk.score}
                  <small>/100</small>
                </span>
              </td>
              <td>
                <button className="finding-link" onClick={() => openFinding(f)}>
                  {f.title}
                </button>
                <small className="resource" title={f.resource_id}>
                  {f.resource_id}
                </small>
              </td>
              <td className="nowrap">{f.region}</td>
              <td>
                <span className={`status status-${f.status}`}>
                  {statusNames[f.status]}
                </span>
              </td>
              <td>
                <button
                  className="icon-button"
                  onClick={() => openFinding(f)}
                  aria-label={`Ouvrir ${f.title}`}
                >
                  <ArrowRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
  const empty = (
    <div className="empty">
      <ShieldCheck size={32} />
      <h3>
        {fetching
          ? "Chargement des résultats…"
          : latest
            ? "Aucune alerte dans cette sélection"
            : "Votre premier audit commence ici"}
      </h3>
      <p>
        {latest
          ? "Consultez le périmètre et les contrôles incomplets avant de conclure."
          : source === "aws" && !session.aws_enabled
            ? "Connectez votre compte AWS pour obtenir des résultats sur votre environnement."
            : "Lancez un audit pour obtenir vos premières priorités."}
      </p>
      {!fetching && !latest && (
        <button
          className="primary"
          disabled={busy || (canScan ? false : !session.desktop)}
          onClick={() => (canScan ? void scan() : navigate("connection"))}
        >
          {canScan ? "Lancer le premier audit" : "Configurer AWS"}
          <ArrowRight size={16} />
        </button>
      )}
    </div>
  );
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Aller au contenu
      </a>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={23} />
          </span>
          AegisShield
        </div>
        <p className="edition">AUDIT DE SÉCURITÉ AWS</p>
        <nav aria-label="Navigation principale">
          {(Object.entries(pages) as [Page, (typeof pages)[Page]][]).map(
            ([key, item]) => (
              <button
                key={key}
                className={page === key ? "nav-item active" : "nav-item"}
                aria-current={page === key ? "page" : undefined}
                aria-label={item.title}
                onClick={() => navigate(key)}
              >
                <item.icon size={18} />
                <span>{item.title}</span>
                {key === "findings" && summary && summary.active > 0 && (
                  <span className="nav-count">{summary.active}</span>
                )}
              </button>
            ),
          )}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-label">
            <LockKeyhole size={15} />
            <span>
              {session.desktop
                ? "Espace local sur ce PC"
                : session.demo
                  ? "Espace de démonstration"
                  : "Espace de votre organisation"}
            </span>
          </div>
          <small>Lecture seule · Corrections guidées</small>
          <div className="profile">
            <span className="avatar">{session.desktop ? "PC" : "AS"}</span>
            <div>
              <strong>
                {session.desktop ? "Application Windows" : session.tenant_id}
              </strong>
              <small>
                {session.role === "operator"
                  ? "Accès opérateur"
                  : "Lecture seule"}
              </small>
            </div>
          </div>
          {!session.desktop && !session.demo && (
            <button className="text-button" onClick={logout}>
              Se déconnecter
            </button>
          )}
        </div>
      </aside>
      <div className="workspace">
        <div className="topbar">
          <div className="breadcrumb">
            Espace de travail <ChevronRight size={14} />
            <strong>{pages[page].title}</strong>
          </div>
          <label className="source-control">
            <span className={`source-dot ${source === "aws" ? "" : "demo"}`} />
            <span className="sr-only">Source des résultats</span>
            <select
              aria-label="Source des résultats"
              disabled={busy}
              value={source}
              onChange={(event) => {
                setSource(event.target.value);
                setOffset(0);
                setSelected(null);
                setFindings([]);
                setSummary(null);
                setQuery("");
                setSeverity("all");
                setError("");
                setNotice("");
                setFetching(true);
              }}
            >
              {!session.demo && (
                <option value="aws">Mon environnement AWS</option>
              )}
              <option value="demo-fixture">Démonstration</option>
            </select>
          </label>
        </div>
        <main id="main-content">
          <header className="page-header">
            <div>
              <p className="eyebrow">
                {page === "overview"
                  ? "VOTRE POSTURE AWS, EN CLAIR"
                  : "AEGISSHIELD / AUDIT AWS"}
              </p>
              <h1 ref={titleRef} tabIndex={-1}>
                {pages[page].title}
              </h1>
              <p>{pages[page].subtitle}</p>
            </div>
            <div className="header-actions">
              {page !== "connection" && page !== "settings" && (
                <>
                  <button
                    disabled={busy || fetching || !latest}
                    onClick={() => void exportReport()}
                    title="Exporter les alertes actives en JSON"
                  >
                    <ArrowDownToLine size={16} />
                    <span>Exporter</span>
                  </button>
                  <button
                    className="primary"
                    disabled={busy || fetching || !canScan}
                    onClick={() => void scan()}
                  >
                    <RefreshCw size={16} className={busy ? "spin" : ""} />
                    {busy
                      ? "Opération en cours…"
                      : source === "aws"
                        ? "Lancer un audit"
                        : "Auditer la démo"}
                  </button>
                </>
              )}
            </div>
          </header>
          {source === "demo-fixture" && (
            <div className="notice demo-notice">
              <CircleHelp size={17} />
              <span>
                <strong>Mode démonstration.</strong> Données fictives, séparées
                de votre environnement AWS.
              </span>
            </div>
          )}
          {error && !selected && (
            <div role="alert" className="error">
              {error}
              <button
                className="text-button"
                onClick={() => {
                  setError("");
                  refresh();
                }}
              >
                Réessayer
              </button>
            </div>
          )}
          {notice && !selected && (
            <div role="status" className="notice">
              <Check size={17} />
              {notice}
            </div>
          )}
          {latest && latest.status !== "succeeded" && (
            <div className="warning">
              Dernier audit : {scanNames[latest.status]}. Les résultats affichés
              peuvent être anciens.
            </div>
          )}
          {(summary?.coverage_gaps ?? 0) > 0 && (
            <div className="warning">
              {summary?.coverage_gaps} contrôle(s) incomplet(s). Certaines
              configurations n’ont pas pu être inspectées ; les alertes
              précédentes sont conservées.
            </div>
          )}
          <div className="page-view" key={page}>
            {page === "overview" && (
              <>
                <section className="overview-intro">
                  <div>
                    <div className="section-kicker">
                      <span className="source-dot" />
                      AUDITER · COMPRENDRE · CORRIGER
                    </div>
                    <h2>Commencez par ce qui compte.</h2>
                    <p>
                      Des constats expliqués, classés par priorité, et un nouvel
                      audit pour suivre vos corrections.
                    </p>
                    <button
                      className="text-button"
                      onClick={() => navigate("findings")}
                    >
                      Ouvrir le plan de correction <ArrowRight size={16} />
                    </button>
                  </div>
                  <div className="last-audit">
                    <FileClock size={22} />
                    <span>DERNIER AUDIT</span>
                    <strong>{date(latest?.started_at)}</strong>
                    <small>
                      {latest
                        ? `${scanNames[latest.status]} · ${latest.status === "succeeded" ? latest.assets_scanned + " ressources inventoriées" : "Résultats à vérifier"}`
                        : "Aucun audit enregistré"}
                    </small>
                  </div>
                </section>
                <section
                  className="metrics"
                  aria-label="Synthèse de toutes les alertes de la source"
                >
                  <article className="metric">
                    <span>Alertes actives</span>
                    <strong>{summary?.active ?? "—"}</strong>
                    <small>Tous les résultats de cette source</small>
                  </article>
                  <article className="metric">
                    <span>
                      <i className="metric-dot red" />
                      Priorités critiques / élevées
                    </span>
                    <strong>
                      {summary
                        ? summary.severities.critical + summary.severities.high
                        : "—"}
                    </strong>
                    <small>À examiner en premier</small>
                  </article>
                  <article className="metric">
                    <span>Prises en charge</span>
                    <strong>{summary?.states.acknowledged ?? "—"}</strong>
                    <small>Corrections en cours de suivi</small>
                  </article>
                  <article className="metric">
                    <span>Priorité maximale</span>
                    <strong>
                      {summary?.highest_risk ?? "—"}
                      {summary?.highest_risk != null && <small>/100</small>}
                    </strong>
                    <small>Un indicateur de priorité</small>
                  </article>
                </section>
                <section className="panel">
                  <div className="panel-title">
                    <div>
                      <h2>À examiner en premier</h2>
                      <p>
                        Les alertes actives de la page courante, par risque
                        décroissant.
                      </p>
                    </div>
                    <button
                      className="text-button"
                      onClick={() => navigate("findings")}
                    >
                      Voir les alertes
                      <ArrowRight size={16} />
                    </button>
                  </div>
                  {activeFindings.length
                    ? riskTable(activeFindings.slice(0, 5))
                    : empty}
                </section>
                <div className="overview-footer">
                  <LockKeyhole size={17} />
                  <p>
                    <strong>Vous gardez la main.</strong> Audit des
                    configurations en lecture seule. Aucune modification
                    automatique de vos ressources.
                  </p>
                </div>
              </>
            )}
            {page === "findings" && (
              <>
                <section className="panel">
                  <div className="panel-title">
                    <div>
                      <h2>Vos corrections, par priorité</h2>
                      <p>
                        Ouvrez une alerte pour consulter les preuves, la
                        recommandation et la vérification.
                      </p>
                    </div>
                    <span className="subtle-label">
                      {summary?.active ?? "—"} actives au total
                    </span>
                  </div>
                  <div className="filter-bar">
                    <label className="search-field">
                      <Search size={17} />
                      <input
                        aria-label="Rechercher dans la page"
                        placeholder="Rechercher dans cette page…"
                        value={query}
                        onChange={(event) => setQuery(event.target.value)}
                      />
                    </label>
                    <label className="filter-select">
                      <SlidersHorizontal size={16} />
                      <select
                        aria-label="Filtrer la priorité"
                        value={severity}
                        onChange={(event) => setSeverity(event.target.value)}
                      >
                        <option value="all">Toutes les priorités</option>
                        {Object.entries(severityNames).map(([key, value]) => (
                          <option key={key} value={key}>
                            {value}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={showResolved}
                        disabled={busy || fetching}
                        onChange={(event) => {
                          setShowResolved(event.target.checked);
                          setOffset(0);
                          setFetching(true);
                        }}
                      />
                      Inclure les fermées
                    </label>
                  </div>
                  {visible.length ? riskTable(visible) : empty}
                  <div className="pagination">
                    <span>
                      {visible.length} affichées · Page {offset / 100 + 1} ·
                      Filtres sur cette page
                    </span>
                    <div>
                      <button
                        aria-label="Page précédente"
                        disabled={!offset || busy || fetching}
                        onClick={() => {
                          setOffset((n) => n - 100);
                          setFetching(true);
                        }}
                      >
                        <ChevronLeft size={16} />
                      </button>
                      <button
                        aria-label="Page suivante"
                        disabled={
                          findings.length < 100 ||
                          offset >= 100000 ||
                          busy ||
                          fetching
                        }
                        onClick={() => {
                          setOffset((n) => n + 100);
                          setFetching(true);
                        }}
                      >
                        <ChevronRight size={16} />
                      </button>
                    </div>
                  </div>
                </section>
                <p className="footnote">
                  « En cours » est un état de suivi. « Fermée » peut provenir
                  d’un nouvel audit ou d’une clôture dans une ancienne version ;
                  ce statut ne certifie pas la sécurité de la ressource.
                </p>
              </>
            )}
            {page === "history" && (
              <>
                <section className="panel">
                  <div className="panel-title">
                    <div>
                      <h2>
                        Audits de{" "}
                        {source === "aws"
                          ? "votre environnement AWS"
                          : "démonstration"}
                      </h2>
                      <p>
                        Audits de cette source parmi les 100 dernières
                        exécutions.
                      </p>
                    </div>
                    <button disabled={busy || fetching} onClick={refresh}>
                      <RefreshCw size={16} />
                      Actualiser
                    </button>
                  </div>
                  {scopedScans.length ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Démarré le</th>
                            <th>Résultat</th>
                            <th>Ressources</th>
                            <th>Alertes observées</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scopedScans.map((item) => (
                            <tr key={item.scan_id}>
                              <td>{date(item.started_at)}</td>
                              <td>
                                <span
                                  className={`status status-${item.status}`}
                                >
                                  {scanNames[item.status]}
                                </span>
                                {item.error_code && (
                                  <small>{item.error_code}</small>
                                )}
                              </td>
                              <td>
                                {item.status === "succeeded"
                                  ? item.assets_scanned
                                  : "—"}
                              </td>
                              <td>
                                {item.status === "succeeded"
                                  ? item.findings_count
                                  : "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty">
                      <FileClock size={30} />
                      <h3>Aucun audit enregistré</h3>
                      <p>Les prochaines exécutions apparaîtront ici.</p>
                    </div>
                  )}
                </section>
                <details className="panel audit-log">
                  <summary>Journal des actions · toutes sources</summary>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Date</th>
                          <th>Acteur</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {audit.map((event) => (
                          <tr key={event.event_id}>
                            <td>{date(event.timestamp)}</td>
                            <td>{event.subject}</td>
                            <td>{event.action}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              </>
            )}
            {page === "connection" && (
              <AwsSetup
                session={session}
                onDone={(value) => {
                  setSession(value);
                  setSource("aws");
                  setOffset(0);
                  setSummary(null);
                  setFindings([]);
                  refresh();
                }}
              />
            )}
            {page === "settings" && (
              <>
                <DiagnosticsPanel session={session} source={source} />
                <section className="panel product-scope">
                  <h2>Un périmètre clair</h2>
                  <p>
                    AegisShield audite les configurations AWS couvertes par ses
                    règles et aide à prioriser leur correction. Il ne surveille
                    pas les attaques en temps réel.
                  </p>
                  <p>
                    Les données de démonstration sont isolées des résultats AWS.
                    Les contrôles non accessibles sont signalés, jamais
                    présentés comme validés.
                  </p>
                </section>
              </>
            )}
          </div>
          <footer className="app-footer">
            <span>AegisShield · Audit AWS</span>
            <span>Lecture seule · Résultats explicables</span>
          </footer>
        </main>
      </div>
      {selected && (
        <FindingDialog
          finding={selected}
          operator={session.role === "operator"}
          busy={busy || fetching || !canScan}
          onClose={() => setSelected(null)}
          onStatus={(status) => void changeStatus(status)}
          feedback={{ error, notice }}
          onVerify={() => void scan()}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <AccessGate>
      {(session, logout) => <Dashboard session={session} logout={logout} />}
    </AccessGate>
  );
}
