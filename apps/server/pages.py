"""Server-rendered pages. No JavaScript; every page is cacheable by Cloudflare."""

import hashlib
from datetime import UTC, datetime
from email.utils import format_datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote
from xml.sax.saxutils import escape

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from apps.server import site
from apps.server.deps import DB

HERE = Path(__file__).resolve().parent
SITE_URL = "https://sec.ly2u.com"
PAGE_CACHE = "public, max-age=300"
SHORT_CACHE = "public, max-age=60"

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=HERE / "templates")


@lru_cache(maxsize=1)
def stylesheet():
    data = (HERE / "static" / "site.css").read_bytes()
    return data, hashlib.sha256(data).hexdigest()[:12]


def _date(value):
    if value is None:
        return "—"
    if isinstance(value, datetime):
        value = value.replace(tzinfo=UTC) if value.tzinfo is None else value
        return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def _percent(value):
    if value is None:
        return "—"
    pct = value * 100
    return f"{pct:.1f}%" if pct >= 0.1 else "<0.1%"


templates.env.filters["when"] = _date
templates.env.filters["pct"] = _percent
templates.env.globals["css_version"] = lambda: stylesheet()[1]
templates.env.globals["site_url"] = SITE_URL


def render(request, name, context, status=200, cache=PAGE_CACHE):
    response = templates.TemplateResponse(request, name, context, status_code=status)
    response.headers["Cache-Control"] = cache
    return response


@router.get("/static/site.css")
def css():
    data, _ = stylesheet()
    return Response(
        data,
        media_type="text/css",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@router.get("/", response_class=HTMLResponse)
def home(request: Request, session: DB):
    return render(
        request,
        "home.html",
        {
            "kev": site.recent_kev(session),
            "events": site.recent_events(session, limit=12),
            "products": site.products(),
            "counts": site.product_counts(session),
            "freshness": site.freshness(session),
        },
    )


@router.get("/go")
def go(request: Request, session: DB, id: str = Query("", max_length=200)):
    state, value = site.resolve(session, id)
    if state == "found":
        return RedirectResponse(
            f"/cve/{quote(value, safe='')}", status_code=302, headers={"Cache-Control": PAGE_CACHE}
        )
    return render(
        request,
        "go.html",
        {"query": id.strip()[:64], "state": state, "value": value, "products": site.products()},
        status=404 if state == "missing" else 400,
        cache=SHORT_CACHE,
    )


@router.get("/cve/{vid}", response_class=HTMLResponse)
def vulnerability(request: Request, vid: str, session: DB):
    data = site.vulnerability_page(session, vid) if site.PATH_ID.fullmatch(vid) else None
    if data is None:
        canonical = site.normalize_id(vid)
        if canonical and canonical != vid and site.vulnerability_page(session, canonical):
            return RedirectResponse(f"/cve/{quote(canonical, safe='')}", status_code=301)
        return render(
            request,
            "go.html",
            {
                "query": vid[:64],
                "state": "missing" if canonical else "invalid",
                "value": canonical,
                "products": site.products(),
            },
            status=404,
            cache=SHORT_CACHE,
        )
    return render(request, "cve.html", {"v": data})


@router.get("/products", response_class=HTMLResponse)
def product_list(request: Request, session: DB):
    return render(
        request,
        "products.html",
        {"products": site.products(), "counts": site.product_counts(session)},
    )


@router.get("/product/{slug}", response_class=HTMLResponse)
def product(request: Request, session: DB, slug: str, page: int = Query(1, ge=1, le=site.MAX_PAGE)):
    data = site.product_page(session, slug, page)
    if data is None:
        return render(request, "not_found.html", {}, status=404, cache=SHORT_CACHE)
    return render(request, "product.html", {"p": data})


def _release_key():
    path = site.ROOT / "keys" / "release-signing.pub"
    lines = path.read_text().splitlines() if path.is_file() else []
    return lines[1].strip() if len(lines) == 2 else None


@router.get("/scanner", response_class=HTMLResponse)
def scanner(request: Request):
    return render(
        request, "scanner.html", {"products": site.products(), "release_key": _release_key()}
    )


@router.get("/about", response_class=HTMLResponse)
def about(request: Request, session: DB):
    return render(request, "about.html", {"freshness": site.freshness(session)})


@router.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    return render(request, "privacy.html", {})


@router.get("/security", response_class=HTMLResponse)
def security(request: Request):
    return render(request, "security.html", {})


@router.get("/install.sh")
def install_script():
    path = site.ROOT / "scanner" / "install.sh"
    return PlainTextResponse(
        path.read_text(),
        media_type="text/x-shellscript; charset=utf-8",
        headers={"Cache-Control": PAGE_CACHE},
    )


@router.get("/keys/{name}.pub")
def public_key(name: str):
    path = site.ROOT / "keys" / f"{name}.pub"
    if name not in ("release-signing", "bundle-signing") or not path.is_file():
        return PlainTextResponse("not found\n", status_code=404)
    return PlainTextResponse(path.read_text(), headers={"Cache-Control": PAGE_CACHE})


@router.get("/rss.xml")
def rss(session: DB):
    items = []
    for event in site.recent_events(session, limit=50, priorities=("P0", "P1")):
        link = f"{SITE_URL}/cve/{quote(event['vulnerability_id'], safe='')}"
        items.append(
            "<item>"
            f"<title>{escape(event['priority'] + ' ' + event['vulnerability_id'] + '：' + event['text'])}</title>"
            f"<link>{escape(link)}</link>"
            f'<guid isPermaLink="false">secwatch-event-{event["id"]}</guid>'
            f"<pubDate>{format_datetime(event['happened_at'])}</pubDate>"
            f"<description>{escape(event['text'] + '（来源：' + event['source'] + '）')}</description>"
            "</item>"
        )
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<rss version="2.0"><channel>'
        "<title>LY2U SecWatch：需要立即关注的漏洞</title>"
        f"<link>{SITE_URL}/</link>"
        "<description>已确认在野利用或利用概率较高的漏洞事件</description>"
        "<language>zh-cn</language>" + "".join(items) + "</channel></rss>"
    )
    return Response(
        body,
        media_type="application/rss+xml; charset=utf-8",
        headers={"Cache-Control": PAGE_CACHE},
    )


@router.get("/robots.txt")
def robots():
    return PlainTextResponse(
        "User-agent: *\nDisallow: /go\nDisallow: /api/\n", headers={"Cache-Control": PAGE_CACHE}
    )
