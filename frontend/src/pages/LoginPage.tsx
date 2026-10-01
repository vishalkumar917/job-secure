import { Lock } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button, ErrorState, Field, inputCls } from "../components/ui";
import { useAuth } from "../hooks/useAuth";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
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
    <div className="flex min-h-screen items-center justify-center bg-page px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <img src="/favicon.svg" alt="" className="mb-3 h-12 w-12" />
          <h1 className="text-xl font-semibold text-ink">MemTrace</h1>
          <p className="mt-1 text-sm text-muted">AI-Assisted Windows Memory Forensics &amp; Analysis</p>
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-xl border border-line bg-surface p-6">
          <Field label="Username">
            <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </Field>
          <Field label="Password">
            <input className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus />
          </Field>
          {error && <ErrorState message={error} />}
          <Button type="submit" variant="primary" disabled={busy} className="w-full justify-center">
            <Lock className="h-4 w-4" /> {busy ? "Signing in..." : "Sign in"}
          </Button>
        </form>
        <p className="mt-4 text-center text-xs text-muted">Defensive digital-forensics platform. Authorised investigators only.</p>
      </div>
    </div>
  );
}
