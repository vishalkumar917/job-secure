import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { Button, Card, ErrorState, Field, inputCls, PageHeader } from "../components/ui";
import { api } from "../services/api";

export default function CreateInvestigationPage() {
  const nav = useNavigate();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [caseNumber, setCaseNumber] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = await api.createCase({ title, description, case_number: caseNumber.trim() || undefined });
      nav(`/investigations/${c.id}/upload`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Page>
      <PageHeader title="Create investigation" subtitle="Opening a case records the first chain-of-custody event." />
      <Card className="max-w-2xl">
        <form onSubmit={submit} className="space-y-4">
          <Field label="Title">
            <input className={inputCls} value={title} onChange={(e) => setTitle(e.target.value)} minLength={3} maxLength={200} required
              placeholder="e.g. Workstation WS-0142 suspected compromise" />
          </Field>
          <Field label="Case number (optional)" hint="Leave blank to generate CASE-YYYY-NNNN. Letters, digits, '-' and '_' only.">
            <input className={inputCls} value={caseNumber} onChange={(e) => setCaseNumber(e.target.value)} pattern="[A-Za-z0-9_\-]{3,32}" />
          </Field>
          <Field label="Description">
            <textarea className={inputCls} rows={4} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000}
              placeholder="Scope, source of the memory image, acquisition tool and time, authorisation reference..." />
          </Field>
          {error && <ErrorState message={error} />}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating..." : "Create and upload evidence"}</Button>
            <Button onClick={() => nav(-1)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </Page>
  );
}
