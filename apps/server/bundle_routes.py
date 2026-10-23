import hashlib
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response

from collector.bundles import FILENAME

router = APIRouter()


@router.get("/bundles/{filename}")
def download(filename: str, request: Request):
    if filename != "manifest.json" and not FILENAME.fullmatch(filename):
        raise HTTPException(404)
    root = Path(os.environ.get("BUNDLES_DIR", "/bundles")).resolve()
    path = root / filename
    if not path.is_file() or path.is_symlink() or path.resolve().parent != root:
        raise HTTPException(404)
    data = path.read_bytes() if filename == "manifest.json" else None
    etag = '"' + (hashlib.sha256(data).hexdigest() if data is not None else filename) + '"'
    headers = {
        "Cache-Control": "public, max-age=60, must-revalidate"
        if data is not None
        else "public, max-age=31536000, immutable",
        "ETag": etag,
        "X-Content-Type-Options": "nosniff",
    }
    matches = [
        v.strip().removeprefix("W/") for v in request.headers.get("if-none-match", "").split(",")
    ]
    if etag in matches or "*" in matches:
        return Response(status_code=304, headers=headers)
    if data is not None:
        return Response(data, media_type="application/json", headers=headers)
    return FileResponse(
        path,
        media_type="application/zstd" if filename.endswith(".zst") else "text/plain",
        headers=headers,
    )
