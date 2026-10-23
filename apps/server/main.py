from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from apps.server.db import engine_for

app = FastAPI(title="LY2U SecWatch", version="0.1.0")


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
