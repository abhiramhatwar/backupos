from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.core.rate_limit import RateLimiter
import app.core.rate_limit as rate_limit_module
from app.api import auth, sources, backups, policies, anomalies, restore, ws


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialise database tables
    await init_db()

    # Initialise rate limiter singleton
    rate_limit_module.rate_limiter = RateLimiter(settings.redis_url)

    yield

    # Teardown
    if rate_limit_module.rate_limiter is not None:
        await rate_limit_module.rate_limiter.close()


app = FastAPI(
    title="BackupOS",
    description="Distributed Backup Engine with incremental-forever backups, deduplication, and ransomware detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(sources.router, prefix="/api/v1/sources", tags=["Data Sources"])
app.include_router(backups.router, prefix="/api/v1/backups", tags=["Backups"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["Policies"])
app.include_router(anomalies.router, prefix="/api/v1/anomalies", tags=["Anomalies & Compliance"])
app.include_router(restore.router, prefix="/api/v1/restore", tags=["Recovery"])
app.include_router(ws.router, prefix="/ws", tags=["WebSocket"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "BackupOS"}
