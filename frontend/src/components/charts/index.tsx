/**
 * Chart components (Recharts), theme-aware via useChartTheme. Conventions:
 * - severity/risk use the fixed status palette and every bar is labelled on its axis, so colour never carries meaning alone;
 * - single-series charts have no legend (the card title names the series); multi-series charts always have one;
 * - recessive grid/axes, 4px rounded data ends, tooltips on every mark, a 2px surface gap between stacked fills.
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
import { useChartTheme } from "../../hooks/useTheme";
import { CATEGORY_LABEL } from "../../services/format";
import type { Connection, Process, RiskBand, Severity } from "../../types";
import { BAND_HEX, EmptyState, SEV_HEX } from "../ui";

export { SEV_HEX as SEV_COLOR };

function TooltipBox({ title, rows }: { title: string; rows: [string, string | number, string?][] }) {
  return (
    <div className="rounded-xl border border-line bg-surface px-3.5 py-2.5 text-xs shadow-overlay">
      <div className="mb-1.5 font-medium text-ink">{title}</div>
      {rows.map(([label, value, color]) => (
        <div key={label} className="flex items-center gap-2 py-0.5">
          {color && <span className="inline-block h-2 w-2 rounded-sm" style={{ background: color }} />}
          <span className="font-semibold tabular text-ink">{value}</span>
          <span className="text-muted">{label}</span>
        </div>
      ))}
    </div>
  );
}

export function SeverityChart({ counts, height = 240 }: { counts: Partial<Record<Severity, number>>; height?: number }) {
  const t = useChartTheme();
  const data = (["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => ({ name: s, value: counts[s] ?? 0 }));
  if (data.every((d) => d.value === 0)) return <EmptyState title="No findings" compact />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 22, right: 4, left: -18, bottom: 0 }} barCategoryGap="30%">
        <CartesianGrid vertical={false} stroke={t.grid} />
        <XAxis dataKey="name" tick={{ fill: t.tick, fontSize: 12 }} axisLine={{ stroke: t.axis }} tickLine={false}
          tickFormatter={(v: string) => v[0].toUpperCase() + v.slice(1)} />
        <YAxis tick={{ fill: t.tick, fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip cursor={{ fill: t.cursor }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title="Findings" rows={[[String(payload[0].payload.name), payload[0].value as number, SEV_HEX[payload[0].payload.name as Severity]]]} /> : null} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} isAnimationActive={false} maxBarSize={44}>
          {data.map((d) => <Cell key={d.name} fill={SEV_HEX[d.name]} />)}
          <LabelList dataKey="value" position="top" fill={t.label} fontSize={12} fontWeight={600} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TopRiskChart({ processes, onSelect, limit = 10 }: { processes: Process[]; onSelect?: (pid: number) => void; limit?: number }) {
  const t = useChartTheme();
  const data = processes.filter((p) => p.risk_score > 0).sort((a, b) => b.risk_score - a.risk_score).slice(0, limit)
    .map((p) => ({ label: `${p.name} (${p.pid})`, pid: p.pid, score: p.risk_score, band: p.risk_band }));
  if (!data.length) return <EmptyState title="No process triggered a detection rule" compact />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 36 + 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 40, left: 4, bottom: 4 }} barCategoryGap={8}>
        <CartesianGrid horizontal={false} stroke={t.grid} />
        <XAxis type="number" domain={[0, 100]} ticks={[0, 30, 60, 80, 100]} tick={{ fill: t.tick, fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="label" width={176} tick={{ fill: t.label, fontSize: 12.5 }} axisLine={false} tickLine={false} />
        {[30, 60, 80].map((x) => <ReferenceLine key={x} x={x} stroke={t.axis} strokeDasharray="3 4" />)}
        <Tooltip cursor={{ fill: t.cursor }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title={String(payload[0].payload.label)}
            rows={[[`risk (${payload[0].payload.band})`, payload[0].value as number, BAND_HEX[payload[0].payload.band as RiskBand]]]} /> : null} />
        <Bar dataKey="score" radius={[0, 4, 4, 0]} cursor={onSelect ? "pointer" : undefined} maxBarSize={22}
          onClick={(d: { pid?: number }) => d.pid != null && onSelect?.(d.pid)} isAnimationActive={false}>
          {data.map((d) => <Cell key={d.pid} fill={BAND_HEX[d.band]} />)}
          <LabelList dataKey="score" position="right" fill={t.label} fontSize={12} fontWeight={600} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryChart({ counts }: { counts: Record<string, number> }) {
  const t = useChartTheme();
  const data = Object.entries(counts).map(([k, v]) => ({ name: CATEGORY_LABEL[k] ?? k.replace(/_/g, " "), value: v })).sort((a, b) => b.value - a.value);
  if (!data.length) return <EmptyState title="No findings" compact />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(170, data.length * 32 + 20)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 32, left: 4, bottom: 0 }} barCategoryGap={7}>
        <CartesianGrid horizontal={false} stroke={t.grid} />
        <XAxis type="number" tick={{ fill: t.tick, fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={138} tick={{ fill: t.label, fontSize: 12.5 }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: t.cursor }} content={({ active, payload }) =>
          active && payload?.length ? <TooltipBox title={String(payload[0].payload.name)} rows={[["findings", payload[0].value as number, t.series1]]} /> : null} />
        <Bar dataKey="value" fill={t.series1} radius={[0, 4, 4, 0]} isAnimationActive={false} maxBarSize={20}>
          <LabelList dataKey="value" position="right" fill={t.label} fontSize={12} fontWeight={600} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Process creation time vs. risk score - shows when the suspicious activity clustered. */
export function ProcessTimelineChart({ processes, onSelect }: { processes: Process[]; onSelect?: (pid: number) => void }) {
  const t = useChartTheme();
  const pts = processes.filter((p) => p.create_time && p.risk_score > 0)
    .map((p) => ({ t: new Date(p.create_time!).getTime(), score: p.risk_score, name: p.name, pid: p.pid, band: p.risk_band }));
  if (!pts.length) return <EmptyState title="No timestamped suspicious processes" compact />;
  const fmt = (v: number) => new Date(v).toISOString().slice(11, 16);
  return (
    <ResponsiveContainer width="100%" height={260}>
      <ScatterChart margin={{ top: 14, right: 18, left: -14, bottom: 4 }}>
        <CartesianGrid stroke={t.grid} />
        <XAxis type="number" dataKey="t" domain={["dataMin - 600000", "dataMax + 600000"]} tickFormatter={fmt} tick={{ fill: t.tick, fontSize: 12 }}
          axisLine={{ stroke: t.axis }} tickLine={false} name="Created (UTC)" />
        <YAxis type="number" dataKey="score" domain={[0, 100]} ticks={[0, 30, 60, 80, 100]} tick={{ fill: t.tick, fontSize: 12 }} axisLine={false} tickLine={false} name="Risk" />
        <ZAxis range={[90, 90]} />
        <ReferenceLine y={60} stroke={t.axis} strokeDasharray="3 4" />
        <Tooltip cursor={{ stroke: t.axis }} content={({ active, payload }) => {
          if (!active || !payload?.length) return null;
          const d = payload[0].payload as (typeof pts)[number];
          return <TooltipBox title={`${d.name} (PID ${d.pid}) - ${new Date(d.t).toISOString().replace("T", " ").slice(0, 19)} UTC`}
            rows={[[`risk (${d.band})`, d.score, BAND_HEX[d.band]]]} />;
        }} />
        <Scatter data={pts} isAnimationActive={false} cursor={onSelect ? "pointer" : undefined} onClick={(d: { pid?: number }) => d.pid != null && onSelect?.(d.pid)}
          shape={(props: { cx?: number; cy?: number; payload?: (typeof pts)[number] }) => (
            <g>
              <circle cx={props.cx} cy={props.cy} r={13} fill="transparent" />
              <circle cx={props.cx} cy={props.cy} r={6} fill={BAND_HEX[props.payload!.band]} stroke={t.surface} strokeWidth={2} />
            </g>
          )} />
      </ScatterChart>
    </ResponsiveContainer>
  );
}

export function NetworkChart({ connections }: { connections: Connection[] }) {
  const t = useChartTheme();
  const by = new Map<string, { name: string; external: number; internal: number }>();
  for (const c of connections) {
    const key = `${c.owner ?? "?"} (${c.pid ?? "?"})`;
    const row = by.get(key) ?? { name: key, external: 0, internal: 0 };
    if (c.is_external) row.external++;
    else row.internal++;
    by.set(key, row);
  }
  const data = [...by.values()].sort((a, b) => b.external + b.internal - (a.external + a.internal)).slice(0, 12);
  if (!data.length) return <EmptyState title="No network endpoints recovered" compact />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 32 + 56)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 4, bottom: 0 }} barCategoryGap={7}>
        <CartesianGrid horizontal={false} stroke={t.grid} />
        <XAxis type="number" tick={{ fill: t.tick, fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={170} tick={{ fill: t.label, fontSize: 12.5 }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: t.cursor }} content={({ active, payload, label }) =>
          active && payload?.length ? <TooltipBox title={String(label)} rows={payload.map((p) => [String(p.name), p.value as number, p.color])} /> : null} />
        <Legend verticalAlign="top" align="left" height={34} iconType="square" iconSize={10} wrapperStyle={{ fontSize: 12.5, color: t.label, paddingLeft: 8 }} />
        <Bar dataKey="internal" name="Internal / local" stackId="a" isAnimationActive={false} fill={t.series1} stroke={t.surface} strokeWidth={2} maxBarSize={20} />
        <Bar dataKey="external" name="External" stackId="a" isAnimationActive={false} fill={t.series2} stroke={t.surface} strokeWidth={2} radius={[0, 4, 4, 0]} maxBarSize={20} />
      </BarChart>
    </ResponsiveContainer>
  );
}
