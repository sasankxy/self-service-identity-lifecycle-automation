import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.agents import checkpoint, graph as agent_graph, llm as agent_llm
from app.api.v1 import admin, agent, approvals, assistant, audit_logs, auth, dashboard, governance, identities, meta, risk
from app.core.config import Settings, get_settings
from app.core.errors import install_error_handlers
from app.services import nlu, scheduler
from app.services.accounts import ensure_reference_data


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine: AsyncEngine = create_async_engine(
            settings.database_url, pool_pre_ping=True,
            **({"poolclass": NullPool} if settings.env == "test" else {"pool_size": 10, "max_overflow": 10}),
        )
        app.state.engine = engine
        app.state.sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
        app.state.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        async with app.state.sessionmaker() as db:
            await ensure_reference_data(db)
        async with app.state.sessionmaker() as db:
            nlu.configure(await nlu.load_catalogue(db))      # NLU vocabulary = the directory's departments/apps/entitlements
        await run_in_threadpool(nlu.warm_up)      # load NLU models once; failure only disables the NLU layer
        app.state.scan_task = scheduler.start(app, settings)      # proactive governance loop (None when disabled / ENV=test)
        saver, close_saver = await checkpoint.open_checkpointer(settings)
        app.state.agent_graph = agent_graph.build(saver)          # multi-agent conversation graph (/api/v1/agent/*)
        app.state.agent_llm = agent_llm.build(settings)          # LLM agents (None when disabled / no API key)
        yield
        if app.state.agent_llm is not None:
            await app.state.agent_llm.aclose()
        if close_saver:
            await close_saver()
        if app.state.scan_task:
            app.state.scan_task.cancel()
            await asyncio.gather(app.state.scan_task, return_exceptions=True)
        await app.state.redis.aclose()
        await engine.dispose()

    app = FastAPI(title="IdentityOS API", version="0.1.0", lifespan=lifespan,
                  docs_url=None if settings.env == "prod" else "/api/docs",
                  openapi_url=None if settings.env == "prod" else "/api/openapi.json")
    app.state.settings = settings
    install_error_handlers(app)

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PUT", "DELETE"],
                           allow_headers=["Content-Type", "X-CSRF-Token"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/api/v1/health", tags=["meta"])
    async def health(request: Request):
        status = {"postgres": "ok", "redis": "ok"}
        try:
            async with request.app.state.sessionmaker() as db:
                await db.execute(text("SELECT 1"))
        except Exception:
            status["postgres"] = "down"
        try:
            await request.app.state.redis.ping()
        except Exception:
            status["redis"] = "down"
        return status

    app.include_router(auth.router, prefix="/api/v1")
    for r in (admin, agent, approvals, assistant, audit_logs, dashboard, governance, identities, meta, risk):
        app.include_router(r.router, prefix="/api/v1")

    frontend = Path(settings.frontend_dir)
    if frontend.is_dir():
        app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
    return app


app = create_app()
