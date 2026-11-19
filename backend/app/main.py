import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.routers import assets, audit, auth, cases, dashboard, discovery, indicators, intelligence, scanners, siem, users, vulnerabilities

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("cti-platform")
app = FastAPI(title=settings.app_name, version="0.2.0", description="Defensive Cyber Threat Intelligence and Vulnerability Management API", docs_url="/docs" if settings.app_env != "production" else None, redoc_url="/redoc" if settings.app_env != "production" else None)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "X-Request-ID"])

@app.middleware("http")
async def security_headers_and_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:100]
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled_error request_id=%s path=%s", request_id, request.url.path)
        response = JSONResponse(status_code=500, content={"detail": "Erro interno", "request_id": request_id})
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    logger.info("request method=%s path=%s status=%s duration_ms=%.2f request_id=%s", request.method, request.url.path, response.status_code, (time.perf_counter() - started) * 1000, request_id)
    return response

@app.get("/health", tags=["operations"])
def health():
    return {"status": "ok", "service": "cti-platform-api", "version": "0.2.0"}

for router in (auth.router, assets.router, vulnerabilities.router, indicators.router, cases.router, intelligence.router, discovery.router, scanners.router, siem.router, dashboard.router, audit.router, users.router):
    app.include_router(router, prefix="/api/v1")
