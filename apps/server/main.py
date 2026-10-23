from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from apps.server.api import router as api_router
from apps.server.bundle_routes import router as bundle_router
from apps.server.db import engine_for
from apps.server.pages import router as page_router

app = FastAPI(
    title="LY2U SecWatch API",
    version="0.1.0",
    description="只读 API。数据来源与许可见 https://sec.ly2u.com/about",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)
app.include_router(bundle_router)
app.include_router(api_router)
app.include_router(page_router)

# No scripts, no external resources: the policy states exactly what pages may load.
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Frame-Options"] = "DENY"
    if "cache-control" not in response.headers:
        ok = response.status_code < 400
        response.headers["Cache-Control"] = "public, max-age=60" if ok else "no-store"
    return response


@app.get("/api/v1/health", include_in_schema=False)
def health():
    engine = engine_for()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})
    except SQLAlchemyError:
        return JSONResponse(
            {"status": "unavailable"}, status_code=503, headers={"Cache-Control": "no-store"}
        )
    finally:
        engine.dispose()
