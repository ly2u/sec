"""Read-only JSON API. Same facts as the pages; paginated with a hard cap."""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from apps.server import site
from apps.server.deps import DB

router = APIRouter(prefix="/api/v1", tags=["v1"])
CACHE = {"Cache-Control": "public, max-age=60"}


def _json(data):
    return JSONResponse(data, headers=CACHE)


@router.get(
    "/vulnerabilities/{vid}", summary="一条漏洞的事实：评分、KEV、EPSS、发行版状态、上游版本范围"
)
def vulnerability(vid: str, session: DB):
    data = site.vulnerability_page(session, vid) if site.PATH_ID.fullmatch(vid) else None
    if data is None:
        raise HTTPException(404, "not found")
    data.pop("title_full", None)
    return _json(data)


@router.get("/resolve", summary="把编号或别名精确解析为站内漏洞编号（不做模糊匹配）")
def resolve(session: DB, id: str = Query(..., max_length=64)):
    state, value = site.resolve(session, id)
    return _json({"state": state, "id": value})


@router.get("/kev", summary="CISA KEV 当前条目，按加入时间倒序，每页 50 条")
def kev(session: DB, page: int = Query(1, ge=1, le=site.MAX_PAGE)):
    return _json({"page": page, "items": site.kev_page(session, page)})


@router.get("/events", summary="公开事件（P0–P2），按时间倒序，每页 50 条")
def events(session: DB, page: int = Query(1, ge=1, le=site.MAX_PAGE)):
    items = site.recent_events(session, limit=site.PAGE_SIZE, page=page)
    for item in items:
        item["happened_at"] = item["happened_at"].isoformat()
    return _json({"page": page, "items": items})


@router.get("/products", summary="产品列表与漏洞数量")
def products(session: DB):
    counts = site.product_counts(session)
    return _json(
        [
            {"slug": slug, "name": rule["name"], **counts[slug]}
            for slug, rule in site.products().items()
        ]
    )


@router.get("/products/{slug}", summary="一个产品的漏洞（上游版本范围），每页 50 条")
def product(session: DB, slug: str, page: int = Query(1, ge=1, le=site.MAX_PAGE)):
    data = site.product_page(session, slug, page)
    if data is None:
        raise HTTPException(404, "not found")
    return _json(
        {
            "slug": slug,
            "name": data["rule"]["name"],
            "total": data["total"],
            "page": data["page"],
            "pages": data["pages"],
            "items": data["history"],
        }
    )
