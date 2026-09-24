import { useState } from "react";
import { Bot, Send, Sparkles, X } from "lucide-react";
import { askAssistant } from "./api";
import type { AssistantMessage, Finding } from "./types";

const suggestions = ["Prioritize my highest risks", "Summarize my cloud posture", "What should I fix first?"];

export default function SecurityCopilot({ findings }: { findings: Finding[] }) {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<AssistantMessage[]>([
    { role: "assistant", content: "I’m Aegis. I use findings in your current scope to explain risk and remediation. I never modify AWS." },
  ]);
  const send = async (prompt = question) => {
    const clean = prompt.trim();
    if (!clean || busy) return;
    setMessages((current) => [...current, { role: "user", content: clean }]);
    setQuestion(""); setBusy(true);
    try {
      const result = await askAssistant(clean, findings[0]?.source ?? "demo-fixture");
      setMessages((current) => [...current, { role: "assistant", content: result.answer, model: result.model }]);
    } catch (caught) {
      setMessages((current) => [...current, { role: "assistant", content: caught instanceof Error ? caught.message : "Assistant unavailable." }]);
    } finally { setBusy(false); }
  };
  return <>
    <button className="copilot-launcher" onClick={() => setOpen(true)} aria-label="Open Aegis Copilot"><Sparkles size={18} /><span>Ask Aegis</span></button>
    {open && <aside className="copilot" aria-label="Aegis security copilot">
      <div className="copilot-head"><div><Bot size={20}/><div><strong>Aegis Copilot</strong><small>Evidence-grounded · read-only</small></div></div><button onClick={() => setOpen(false)}><X size={18}/></button></div>
      <div className="copilot-messages">
        {messages.map((message, index) => <div key={index} className={"message " + message.role}><p>{message.content}</p>{message.model && <small>{message.model}</small>}</div>)}
        {busy && <div className="message assistant"><p className="thinking">Analyzing current findings…</p></div>}
      </div>
      <div className="suggestions">{suggestions.map((item) => <button key={item} onClick={() => void send(item)}>{item}</button>)}</div>
      <form className="copilot-input" onSubmit={(event) => { event.preventDefault(); void send(); }}>
        <textarea value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about a risk, IAM policy, remediation…" maxLength={2000}/>
        <button disabled={busy || !question.trim()} aria-label="Send"><Send size={17}/></button>
      </form>
    </aside>}
  </>;
}
