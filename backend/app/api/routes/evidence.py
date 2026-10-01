"""Read-only access to extracted artifacts: processes, process tree, modules, network, memory, timeline."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_job
from app.core.database import get_db
from app.models import (
    AnalysisJob,
    Finding,
    HandleRecord,
    MemoryRegion,
    Module,
    NetworkConnection,
    Process,
    ProcessRelationship,
    TimelineEvent,
    YaraMatch,
)
from app.schemas.common import (
    FindingOut,
    HandleOut,
    ModuleOut,
    NetworkOut,
    ProcessDetail,
    ProcessOut,
    RegionOut,
    TimelineOut,
    YaraMatchOut,
)

router = APIRouter(prefix="/api", tags=["evidence"])


@router.get("/processes", response_model=list[ProcessOut])
def processes(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
              suspicious_only: bool = False, search: str | None = Query(None, max_length=200)):
    q = select(Process).where(Process.job_id == job.id)
    if suspicious_only:
        q = q.where(Process.risk_score >= 30)
    if search:
        like = f"%{search}%"
        q = q.where(or_(Process.name.ilike(like), Process.path.ilike(like), Process.cmdline.ilike(like)))
    return list(db.scalars(q.order_by(Process.risk_score.desc(), Process.pid)).all())


@router.get("/processes/tree")
def process_tree(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db)) -> list[dict]:
    """Nested process tree built from stored parent/child relationships (PID-reuse aware)."""
    procs = db.scalars(select(Process).where(Process.job_id == job.id)).all()
    rels = db.scalars(select(ProcessRelationship).where(ProcessRelationship.job_id == job.id)).all()
    parent_of = {r.child_process_id: r.parent_process_id for r in rels}
    anomalous = {r.child_process_id for r in rels if r.is_anomalous}
    nodes = {p.id: {"id": p.id, "pid": p.pid, "ppid": p.ppid, "name": p.name, "risk_score": p.risk_score,
                    "risk_band": p.risk_band, "hidden": p.is_hidden_candidate, "terminated": p.is_terminated,
                    "anomalous_parent": p.id in anomalous, "path": p.path, "children": []} for p in procs}
    roots = []
    for pid_row, node in sorted(nodes.items(), key=lambda kv: kv[1]["pid"]):
        parent = parent_of.get(pid_row)
        if parent and parent in nodes:
            nodes[parent]["children"].append(node)
        else:
            roots.append(node)

    def max_risk(n: dict) -> int:
        n["subtree_risk"] = max([n["risk_score"], *(max_risk(c) for c in n["children"])])
        return n["subtree_risk"]

    for r in roots:
        max_risk(r)
    return roots


@router.get("/processes/{pid}", response_model=ProcessDetail)
def process_detail(pid: int, job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
                   process_id: int | None = None) -> ProcessDetail:
    q = select(Process).where(Process.job_id == job.id, Process.pid == pid)
    if process_id is not None:
        q = q.where(Process.id == process_id)
    candidates = db.scalars(q.order_by(Process.is_terminated, Process.id)).all()
    if not candidates:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No process with PID {pid} in this analysis")
    p = candidates[0]
    rel = db.scalar(select(ProcessRelationship).where(ProcessRelationship.child_process_id == p.id))
    parent = db.get(Process, rel.parent_process_id) if rel and rel.parent_process_id else None
    child_ids = db.scalars(select(ProcessRelationship.child_process_id)
                           .where(ProcessRelationship.parent_process_id == p.id)).all()
    children = db.scalars(select(Process).where(Process.id.in_(child_ids))).all() if child_ids else []
    by_proc = lambda model: select(model).where(model.job_id == job.id, model.process_id == p.id)  # noqa: E731
    return ProcessDetail(
        process=ProcessOut.model_validate(p),
        parent=ProcessOut.model_validate(parent) if parent else None,
        children=[ProcessOut.model_validate(c) for c in children],
        modules=[ModuleOut.model_validate(m) for m in db.scalars(by_proc(Module)).all()],
        network=[NetworkOut.model_validate(n) for n in db.scalars(by_proc(NetworkConnection)).all()],
        regions=[RegionOut.model_validate(r) for r in db.scalars(by_proc(MemoryRegion)).all()],
        handles=[HandleOut.model_validate(h) for h in db.scalars(by_proc(HandleRecord).limit(500)).all()],
        findings=[FindingOut.model_validate(f) for f in db.scalars(by_proc(Finding)).all()],
        sids=p.user_sids or [], privileges=p.privileges or [],
    )


@router.get("/network", response_model=list[NetworkOut])
def network(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db), suspicious_only: bool = False):
    q = select(NetworkConnection).where(NetworkConnection.job_id == job.id)
    if suspicious_only:
        q = q.where(NetworkConnection.is_suspicious)
    return list(db.scalars(q.order_by(NetworkConnection.is_suspicious.desc(), NetworkConnection.id)).all())


@router.get("/memory-regions", response_model=list[RegionOut])
def memory_regions(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
                   source: str | None = Query(None, pattern=r"^(malfind|vadinfo)$"), pid: int | None = None):
    q = select(MemoryRegion).where(MemoryRegion.job_id == job.id)
    if source:
        q = q.where(MemoryRegion.source == source)
    if pid is not None:
        q = q.where(MemoryRegion.pid == pid)
    return list(db.scalars(q.order_by(MemoryRegion.pid, MemoryRegion.start)).all())


@router.get("/modules", response_model=list[ModuleOut])
def modules(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db), pid: int | None = None,
            suspicious_only: bool = False, limit: int = Query(2000, le=20000)):
    q = select(Module).where(Module.job_id == job.id)
    if pid is not None:
        q = q.where(Module.pid == pid)
    if suspicious_only:
        q = q.where(Module.is_suspicious)
    return list(db.scalars(q.order_by(Module.is_suspicious.desc(), Module.pid).limit(limit)).all())


@router.get("/timeline", response_model=list[TimelineOut])
def timeline(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
             min_severity: str | None = Query(None, pattern=r"^(info|low|medium|high|critical)$")):
    q = select(TimelineEvent).where(TimelineEvent.job_id == job.id)
    if min_severity:
        order = ["info", "low", "medium", "high", "critical"]
        q = q.where(TimelineEvent.severity.in_(order[order.index(min_severity):]))
    rows = db.scalars(q).all()
    return sorted(rows, key=lambda t: (t.timestamp is None, t.timestamp.timestamp() if t.timestamp else 0, t.id))


@router.get("/yara/matches", response_model=list[YaraMatchOut])
def yara_matches(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db)):
    return list(db.scalars(select(YaraMatch).where(YaraMatch.job_id == job.id)).all())
