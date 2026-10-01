/**
 * Chart components (Recharts). Conventions:
 * - severity/risk use the fixed status palette and every bar is labelled on its axis, so colour never carries meaning alone;
 * - single-series charts have no legend (the card title names the series); multi-series charts always have one;
 * - recessive grid/axes, 4px rounded bar ends, tooltips on every mark.
 */
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import type { Connection, Process, RiskBand, Severity } from "../../types";
import { BAND_COLOR, EmptyState } from "../ui";

const AXIS = { fill: "#8a93a3", fontSize: 11 };
const GRID = "#262d38";
const SERIES_1 = "#3987e5";
const SERIES_2 = "#d95926";
export const SEV_COLOR: Record<Severity, string> = {
  critical: "#d03b3b", high: "#ec835a", medium: "#fab219", low: "#3987e5", info: "#8a93a3",
};

function TooltipBox({ title, rows }: { title: string; rows: [string, string | number, string?][] }) {
  return (
    <div className="rounded-lg border border-line-strong bg-surface-2 px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 text-muted">{title}</div>
      {rows.map(([label, value, color]) => (
        <div key={label} className="flex items-center gap-2">
          {color && <span className="inline-block h-0.5 w-3" style={{ background: color }} />}
          <span className="font-semibold text-ink tabular">{value}</span>
          <span className="text-ink-2">{label}</span>
        </div>
      ))}
    </div>
  );
}

export function SeverityChart({ counts, height = 220 }: { counts: Partial<Record<Severity, number>>; height?: number }) {
  const data = (["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => ({ name: s, value: counts[s] ?? 0 }));
  if (data.every((d) => d.value === 0)) return <EmptyState title="No findings" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 16, right: 8, left: -16, bottom: 0 }} barCategoryGap="28%">
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey="name" tick={AXIS} axisLine={{ stroke: "#343c4a" }} tickLine={false}
          tickFormatter={(v: string) => v[0].toUpperCase() + v.slice(1)} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title="Findings" rows={[[String(payload[0].payload.name), payload[0].value as number, SEV_COLOR[payload[0].payload.name as Severity]]]} /> : null} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {data.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
          <LabelList dataKey="value" position="top" fill="#c3c8d2" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TopRiskChart({ processes, onSelect, limit = 10 }: { processes: Process[]; onSelect?: (pid: number) => void; limit?: number }) {
  const data = processes.filter((p) => p.risk_score > 0).sort((a, b) => b.risk_score - a.risk_score).slice(0, limit)
    .map((p) => ({ label: `${p.name} (${p.pid})`, pid: p.pid, score: p.risk_score, band: p.risk_band }));
  if (!data.length) return <EmptyState title="No process triggered a detection rule" />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 30 + 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 36, left: 8, bottom: 4 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" domain={[0, 100]} tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="label" width={170} tick={{ ...AXIS, fill: "#c3c8d2" }} axisLine={false} tickLine={false} />
        <ReferenceLine x={30} stroke="#343c4a" strokeDasharray="3 3" />
        <ReferenceLine x={60} stroke="#343c4a" strokeDasharray="3 3" />
        <ReferenceLine x={80} stroke="#343c4a" strokeDasharray="3 3" />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title={String(payload[0].payload.label)}
            rows={[[`risk (${payload[0].payload.band})`, payload[0].value as number, BAND_COLOR[payload[0].payload.band as RiskBand]]]} /> : null} />
        <Bar dataKey="score" radius={[0, 4, 4, 0]} cursor={onSelect ? "pointer" : undefined}
          onClick={(d: { pid?: number }) => d.pid != null && onSelect?.(d.pid)} isAnimationActive={false}>
          {data.map((d) => <Cell key={d.pid} fill={BAND_COLOR[d.band]} />)}
          <LabelList dataKey="score" position="right" fill="#c3c8d2" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryChart({ counts }: { counts: Record<string, number> }) {
  const data = Object.entries(counts).map(([k, v]) => ({ name: k.replace(/_/g, " "), value: v })).sort((a, b) => b.value - a.value);
  if (!data.length) return <EmptyState title="No findings" />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(150, data.length * 28 + 20)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 30, left: 8, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={120} tick={{ ...AXIS, fill: "#c3c8d2" }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title={String(payload[0].payload.name)} rows={[["findings", payload[0].value as number, SERIES_1]]} /> : null} />
        <Bar dataKey="value" fill={SERIES_1} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          <LabelList dataKey="value" position="right" fill="#c3c8d2" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Process creation time vs. risk score - shows when the suspicious activity clustered. */
export function ProcessTimelineChart({ processes, onSelect }: { processes: Process[]; onSelect?: (pid: number) => void }) {
  const pts = processes.filter((p) => p.create_time && p.risk_score > 0)
    .map((p) => ({ t: new Date(p.create_time!).getTime(), score: p.risk_score, name: p.name, pid: p.pid, band: p.risk_band }));
  if (!pts.length) return <EmptyState title="No timestamped suspicious processes" />;
  const fmt = (t: number) => new Date(t).toISOString().slice(11, 16);
  return (
    <ResponsiveContainer width="100%" height={240}>
      <ScatterChart margin={{ top: 12, right: 16, left: -16, bottom: 4 }}>
        <CartesianGrid stroke={GRID} />
        <XAxis type="number" dataKey="t" domain={["dataMin - 600000", "dataMax + 600000"]} tickFormatter={fmt} tick={AXIS}
          axisLine={{ stroke: "#343c4a" }} tickLine={false} name="Created (UTC)" />
        <YAxis type="number" dataKey="score" domain={[0, 100]} tick={AXIS} axisLine={false} tickLine={false} name="Risk" />
        <ZAxis range={[90, 90]} />
        <ReferenceLine y={60} stroke="#343c4a" strokeDasharray="3 3" />
        <Tooltip cursor={{ stroke: "#343c4a" }} content={({ active, payload }) => {
          if (!active || !payload?.length) return null;
          const d = payload[0].payload as (typeof pts)[number];
          return <TooltipBox title={`${d.name} (PID ${d.pid}) - ${new Date(d.t).toISOString().replace("T", " ").slice(0, 19)} UTC`}
            rows={[[`risk (${d.band})`, d.score, BAND_COLOR[d.band]]]} />;
        }} />
        <Scatter data={pts} isAnimationActive={false} cursor={onSelect ? "pointer" : undefined} onClick={(d: { pid?: number }) => d.pid != null && onSelect?.(d.pid)}
          shape={(props: { cx?: number; cy?: number; payload?: (typeof pts)[number] }) => (
            <g>
              <circle cx={props.cx} cy={props.cy} r={12} fill="transparent" />
              <circle cx={props.cx} cy={props.cy} r={5} fill={BAND_COLOR[props.payload!.band]} stroke="#13171d" strokeWidth={2} />
            </g>
          )} />
      </ScatterChart>
    </ResponsiveContainer>
  );
}

export function NetworkChart({ connections }: { connections: Connection[] }) {
  const by = new Map<string, { name: string; external: number; internal: number }>();
  for (const c of connections) {
    const key = `${c.owner ?? "?"} (${c.pid ?? "?"})`;
    const row = by.get(key) ?? { name: key, external: 0, internal: 0 };
    if (c.is_external) row.external++;
    else row.internal++;
    by.set(key, row);
  }
  const data = [...by.values()].sort((a, b) => b.external + b.internal - (a.external + a.internal)).slice(0, 12);
  if (!data.length) return <EmptyState title="No network endpoints recovered" />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 28 + 50)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }} barCategoryGap={6}>
        <CartesianGrid horizontal={false} stroke={GRID} />
        <XAxis type="number" tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={160} tick={{ ...AXIS, fill: "#c3c8d2" }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={({ active, payload, label }) =>
          active && payload?.length ? <TooltipBox title={String(label)} rows={payload.map((p) => [String(p.name), p.value as number, p.color])} /> : null} />
        <Legend verticalAlign="top" height={26} iconType="square" wrapperStyle={{ fontSize: 12, color: "#c3c8d2" }} />
        <Bar dataKey="internal" name="internal / local" stackId="a" isAnimationActive={false} fill={SERIES_1} stroke="#13171d" strokeWidth={2} />
        <Bar dataKey="external" name="external" stackId="a" isAnimationActive={false} fill={SERIES_2} stroke="#13171d" strokeWidth={2} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
