import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import type { Citation } from "../../types";

/** Navigate from an evidence citation ID (F-12, PROC-4528, NET-3, ...) to the view that holds that evidence. */
export function useCitationNav(jobId: number) {
  const nav = useNavigate();
  return useCallback((id: string, citations: Citation[] = []) => {
    const base = `/analysis/${jobId}`;
    const c = citations.find((x) => x.id === id);
    const procPid = /^PROC-(\d+)/.exec(id)?.[1];
    if (id.startsWith("F-")) nav(`${base}/findings?f=${id.slice(2)}`);
    else if (id.startsWith("NET-")) nav(`${base}/network`);
    else if (id.startsWith("MEM-")) nav(`${base}/memory`);
    else if (id.startsWith("IOC-")) nav(`${base}/iocs`);
    else if (id.startsWith("TL-")) nav(`${base}/timeline`);
    else if (id.startsWith("YARA-")) nav(`${base}/memory#yara`);
    else if (id.startsWith("MOD-") && c?.pid != null) nav(`${base}/processes/${c.pid}?tab=modules`);
    else if (procPid) nav(`${base}/processes/${procPid}`);
    else if (c?.pid != null) nav(`${base}/processes/${c.pid}`);
    else if (id === "SUMMARY") nav(base);
  }, [jobId, nav]);
}
