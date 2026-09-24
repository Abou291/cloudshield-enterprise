import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getSession, setApiToken } from "./api";
import type { Session } from "./types";

export default function AccessGate({ children }: {
  children: (session: Session, logout: () => void) => ReactNode;
}) {
  const [session, setSession] = useState<Session | null>(null);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  useEffect(() => {
    let active = true;
    getSession().then((value) => { if (active) setSession(value); })
      .catch((caught: unknown) => {
        if (active) setError(caught instanceof Error ? caught.message : "Connection failed");
      }).finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, []);
  const logout = () => { setApiToken(""); setSession(null); setToken(""); setError(""); };
  if (session) return children(session, logout);
  return <main className="access-panel">
    <h1>AegisShield</h1>
    <p>Connect to your organization with an API token supplied by your administrator.</p>
    <form onSubmit={async (event) => {
      event.preventDefault(); setBusy(true); setError(""); setApiToken(token.trim());
      try { setSession(await getSession()); setToken(""); }
      catch (caught) {
        setApiToken("");
        setError(caught instanceof Error ? caught.message : "Connection failed");
      } finally { setBusy(false); }
    }}>
      <label htmlFor="api-token">API token</label>
      <input id="api-token" type="password" autoComplete="off" value={token}
        onChange={(event) => setToken(event.target.value)} required />
      <button disabled={busy}>{busy ? "Connecting…" : "Connect"}</button>
    </form>
    {error && <p role="alert" className="error">{error}</p>}
    <p>The token is held in memory only and forgotten on reload or sign-out.</p>
  </main>;
}
