"""
WebSocket endpoint for real-time backup job progress.

Clients connect to /ws/jobs/{job_id} and receive JSON status updates every
2 seconds until the job reaches a terminal state (completed or failed).
"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.backup import BackupJob, JobStatus

router = APIRouter()

_TERMINAL_STATES = {JobStatus.completed, JobStatus.failed}


@router.websocket("/jobs/{job_id}")
async def job_status_ws(websocket: WebSocket, job_id: int):
    """
    Stream backup job status to the connected WebSocket client.

    Sends JSON every 2 seconds:
        {"job_id": <int>, "status": <str>, "progress": <float 0.0–1.0>}

    Progress is estimated from status:
        pending   → 0.0
        running   → 0.5
        verifying → 0.8
        completed → 1.0
        failed    → 0.0
    """
    await websocket.accept()

    _progress_map = {
        JobStatus.pending: 0.0,
        JobStatus.running: 0.5,
        JobStatus.verifying: 0.8,
        JobStatus.completed: 1.0,
        JobStatus.failed: 0.0,
    }

    try:
        while True:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(BackupJob).where(BackupJob.id == job_id)
                )
                job = result.scalar_one_or_none()

            if job is None:
                await websocket.send_text(
                    json.dumps(
                        {"job_id": job_id, "status": "not_found", "progress": 0.0}
                    )
                )
                break

            payload = {
                "job_id": job_id,
                "status": job.status.value,
                "progress": _progress_map.get(job.status, 0.0),
            }
            await websocket.send_text(json.dumps(payload))

            if job.status in _TERMINAL_STATES:
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    except Exception:
        # Best-effort: close quietly on unexpected errors
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
