import { ArrowRight, Bot, Eye, EyeOff, Fingerprint, Gauge, Lock, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Logo } from "../components/layout/Logo";
import { ThemeToggle } from "../components/layout/TopBar";
import { Button, ErrorState, Field, inputCls } from "../components/ui";
import { useAuth } from "../hooks/useAuth";

const FEATURES = [
  { icon: <Fingerprint />, title: "Volatility 3 evidence pipeline", text: "Staged, sandboxed plugin runs with cross-view process analysis and hash-verified evidence." },
  { icon: <Gauge />, title: "Explainable risk scoring", text: "Every point of every score traces back to a rule, its evidence and its confidence." },
  { icon: <Bot />, title: "Evidence-grounded AI", text: "Answers cite stored artifacts and are validated - or it says the evidence is insufficient." },
];

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen bg-page lg:grid-cols-[1.05fr_1fr]">
      <aside className="relative hidden overflow-hidden border-r border-line bg-sidebar lg:flex lg:flex-col lg:justify-between lg:p-14 xl:p-20">
        <div aria-hidden className="pointer-events-none absolute inset-0 canvas-grid opacity-60 [mask-image:radial-gradient(ellipse_at_top_left,black,transparent_70%)]" />
        <div aria-hidden className="pointer-events-none absolute -left-40 -top-40 h-[520px] w-[520px] rounded-full bg-accent/10 blur-3xl" />
        <div className="relative"><Logo /></div>
        <div className="relative max-w-lg">
          <h1 className="text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-ink">
            Windows memory forensics, <span className="text-accent-text">explained.</span>
          </h1>
          <p className="mt-5 text-base leading-relaxed text-muted">
            Analyse memory images for injection, masquerading, suspicious network activity and IOCs - with every conclusion tied to forensic evidence.
          </p>
          <ul className="mt-12 space-y-7">
            {FEATURES.map((f) => (
              <li key={f.title} className="flex gap-4">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-line bg-surface text-accent-text shadow-card [&_svg]:h-5 [&_svg]:w-5">{f.icon}</span>
                <div>
                  <div className="font-semibold text-ink">{f.title}</div>
                  <div className="mt-1 text-sm leading-relaxed text-muted">{f.text}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative flex items-center gap-2 text-[13px] text-muted"><ShieldCheck className="h-4 w-4" />Defensive digital forensics · Authorised investigators only</p>
      </aside>

      <main className="relative flex items-center justify-center px-5 py-16 sm:px-10">
        <div className="absolute right-5 top-5"><ThemeToggle /></div>
        <div className="w-full max-w-[400px] animate-page-in">
          <div className="mb-10 lg:hidden"><Logo /></div>
          <h2 className="text-[28px] font-semibold tracking-[-0.02em] text-ink">Sign in</h2>
          <p className="mt-2 text-[15px] text-muted">Access your forensic investigations.</p>
          <form onSubmit={submit} className="mt-10 space-y-6">
            <Field label="Username">
              <input className={`${inputCls} h-11`} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
            </Field>
            <Field label="Password">
              <span className="relative block">
                <input className={`${inputCls} h-11 pr-11`} type={show ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password" required autoFocus />
                <button type="button" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-muted hover:text-ink">
                  {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </span>
            </Field>
            {error && <ErrorState compact message={error} />}
            <Button type="submit" variant="primary" size="lg" disabled={busy} className="w-full" icon={<Lock />}>
              {busy ? "Signing in..." : "Sign in"}{!busy && <ArrowRight className="ml-auto" />}
            </Button>
          </form>
          <p className="mt-10 text-center text-xs leading-relaxed text-faint lg:hidden">Defensive digital forensics · Authorised investigators only</p>
        </div>
      </main>
    </div>
  );
}
