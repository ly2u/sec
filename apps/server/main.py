from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from apps.server.bundle_routes import router as bundle_router
from apps.server.db import engine_for

app = FastAPI(title="LY2U SecWatch", version="0.1.0", docs_url=None, redoc_url=None)
app.include_router(bundle_router)


@app.get("/api/v1/health")
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
