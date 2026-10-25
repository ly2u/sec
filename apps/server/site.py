"""Read-only queries behind the web pages and the JSON API.

Every function takes a session and returns plain dicts/lists, so pages and API
show the same facts. No function here accepts free text for matching: lookups
are exact (IDs, product slugs) and lists are paginated with a hard cap.
"""

import json
import re
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only

from apps.server.models import (
    AffectedPackage,
    EPSSScore,
    IngestionState,
    KEVEntry,
    UpstreamAdvisory,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityEvent,
)

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "products"
PAGE_SIZE = 50
MAX_PAGE = 200
DISTRO_NAMES = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "rocky": "Rocky Linux",
    "alma": "AlmaLinux",
    "alpine": "Alpine",
}
DISTRO_ORDER = list(DISTRO_NAMES)
STATUS_NAMES = {"fixed": "已修复", "unfixed": "未修复", "wont_fix": "不修复", "unknown": "未知"}
METHOD_NAMES = {
    "baota": "宝塔面板",
    "lnmp": "LNMP / OneinStack 等一键包",
    "source": "源码编译",
    "binary": "官方二进制",
    "nvm": "nvm",
    "package": "第三方软件源",
    "process": "运行中的进程",
}
SOURCES = {
    "cvelistV5": ("CVE Program (cvelistV5)", "https://github.com/CVEProject/cvelistV5"),
    "kev": ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    "epss": ("FIRST EPSS", "https://www.first.org/epss/"),
    "osv": ("OSV", "https://osv.dev/"),
    "nodejs": ("Node.js Security WG", "https://github.com/nodejs/security-wg"),
}
EVENT_NAMES = {
    "added_to_kev": "加入 CISA KEV（已确认在野利用）",
    "removed_from_kev": "移出 CISA KEV",
    "fixed_version_published": "发行版发布修复版本",
    "severity_changed": "严重程度调整",
    "rejected": "CVE 被撤销",
}

# IDs accepted by the lookup box. Matching is exact; nothing is searched.
ID_FORMS = [
    (re.compile(r"CVE-\d{4}-\d{4,7}", re.I), str.upper),
    (
        re.compile(r"GHSA(-[23456789CFGHJMPQRVWX]{4}){3}", re.I),
        lambda v: "GHSA" + v[4:].lower(),
    ),
    (re.compile(r"(DSA|DLA|USN|DTSA)-\d{1,6}(-\d{1,3})?", re.I), str.upper),
    (re.compile(r"(RLSA|ALSA|RHSA|ALBA)-\d{4}:\d{1,6}", re.I), str.upper),
    (re.compile(r"(DEBIAN|UBUNTU|ALPINE|ALMA|ROCKY)-CVE-\d{4}-\d{4,7}", re.I), str.upper),
    (re.compile(r"(PYSEC|GO|RUSTSEC)-\d{4}-\d{1,6}", re.I), str.upper),
]
PATH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,63}")


def normalize_id(raw):
    """Canonical form of a typed ID, or None if it is not a known ID format."""
    value = (raw or "").strip()
    if len(value) > 64:
        return None
    for pattern, canon in ID_FORMS:
        if pattern.fullmatch(value):
            return canon(value)
    return None


def resolve(session: Session, raw):
    """('found', id) | ('missing', canonical) | ('invalid', None). Exact matches only."""
    value = normalize_id(raw)
    if value is None:
        return "invalid", None
    if session.get(Vulnerability, value) is not None:
        return "found", value
    owner = session.scalar(
        select(VulnerabilityAlias.vulnerability_id)
        .where(VulnerabilityAlias.alias == value)
        .order_by(VulnerabilityAlias.vulnerability_id)
        .limit(1)
    )
    return ("found", owner) if owner else ("missing", value)


# ------------------------------------------------------------------ priority


def cvss3(vuln):
    """Highest-preference CVSS 3.x score (D4 thresholds are defined on 3.x only)."""
    if vuln is None:
        return None
    if vuln.cvss_version in ("3.0", "3.1"):
        return vuln.cvss
    scores = [
        m["score"] for m in vuln.cvss_metrics or [] if str(m.get("version", "")).startswith("3")
    ]
    return max(scores) if scores else None


def priority(kev, epss, score3, severity):
    """Site-wide priority: D4 without the exposure conditions (those need the host)."""
    if kev:
        return "P0"
    if epss is not None and epss >= 0.1:
        return "P1"
    if (score3 is not None and score3 >= 7.0) or (severity or "").upper() in ("HIGH", "CRITICAL"):
        return "P2"
    return "P3"


PRIORITY_TEXT = {
    "P0": "立即处理：已确认在野利用",
    "P1": "尽快处理：未来 30 天被利用的概率较高",
    "P2": "有空时处理：高危或严重",
    "P3": "了解即可",
}


def _facts(session, ids):
    """{id: {"vuln", "kev", "epss"}} for a list of vulnerability IDs."""
    ids = sorted({i for i in ids if i})
    out = {i: {"vuln": None, "kev": None, "epss": None} for i in ids}
    for start in range(0, len(ids), 1000):
        chunk = ids[start : start + 1000]
        # Lists need a few columns only; never load raw_record (the full CVE JSON) here.
        columns = load_only(
            Vulnerability.id,
            Vulnerability.title,
            Vulnerability.description,
            Vulnerability.published_at,
            Vulnerability.cvss,
            Vulnerability.cvss_version,
            Vulnerability.cvss_metrics,
            Vulnerability.severity,
        )
        query = select(Vulnerability).options(columns).where(Vulnerability.id.in_(chunk))
        for vuln in session.scalars(query):
            out[vuln.id]["vuln"] = vuln
        for kev in session.scalars(
            select(KEVEntry).where(KEVEntry.vulnerability_id.in_(chunk), KEVEntry.is_active)
        ):
            out[kev.vulnerability_id]["kev"] = kev
        for score in session.scalars(
            select(EPSSScore).where(EPSSScore.vulnerability_id.in_(chunk))
        ):
            out[score.vulnerability_id]["epss"] = score
    return out


def summary(vid, facts):
    """Compact row used in every list."""
    vuln, kev, epss = facts["vuln"], facts["kev"], facts["epss"]
    epss_value = float(epss.epss) if epss else None
    score3 = cvss3(vuln)
    level = priority(kev is not None, epss_value, score3, vuln.severity if vuln else None)
    title = (vuln.title or vuln.description or "") if vuln else ""
    return {
        "id": vid,
        "title": _clip(title, 140),
        "published": vuln.published_at.date().isoformat() if vuln and vuln.published_at else None,
        "cvss": vuln.cvss if vuln else None,
        "cvss_version": vuln.cvss_version if vuln else None,
        "severity": vuln.severity if vuln else None,
        "kev": kev is not None,
        "kev_added": kev.date_added.isoformat() if kev else None,
        "ransomware": bool(kev and kev.ransomware.lower() == "known"),
        "epss": epss_value,
        "epss_percentile": float(epss.percentile) if epss else None,
        "priority": level,
    }


def _clip(text, n):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def sort_key(row):
    return (row["priority"], -(row["epss"] or 0), -(row["cvss"] or 0), row["id"])


# ------------------------------------------------------------------ ranges


def describe_range(events):
    """Human text for one OSV-style range of upstream versions."""
    start = next((e["introduced"] for e in events if "introduced" in e), "0")
    fixed = next((e["fixed"] for e in events if "fixed" in e), None)
    last = next((e["last_affected"] for e in events if "last_affected" in e), None)
    limit = next((e["limit"] for e in events if "limit" in e), None)
    low = "" if start == "0" else f"{start} ≤ "
    if fixed:
        return {"text": f"{low}版本 < {fixed}", "fixed": fixed}
    if last and last == start:
        return {"text": f"仅 {last}", "fixed": None}
    if last:
        return {"text": f"{low}版本 ≤ {last}", "fixed": None}
    if limit:
        return {"text": f"{low}版本 < {limit}（该分支不再修复）", "fixed": None}
    return {"text": f"{start} 及以后（尚无修复版本）", "fixed": None}


# ------------------------------------------------------------------ products


@lru_cache(maxsize=1)
def products():
    """Product rules keyed by slug, in display order."""
    out = {}
    for path in sorted(RULES.glob("*.json")):
        rule = json.loads(path.read_text())
        out[rule["slug"]] = rule
    return dict(sorted(out.items(), key=lambda kv: kv[1]["name"].lower()))


def product_counts(session):
    """{slug: {"total", "kev", "recent"}} from upstream advisories."""
    since = datetime.now(UTC) - timedelta(days=90)
    counts = {slug: {"total": 0, "kev": 0, "recent": 0} for slug in products()}
    vid = func.coalesce(UpstreamAdvisory.vulnerability_id, UpstreamAdvisory.id)
    for slug, total in session.execute(
        select(UpstreamAdvisory.product, func.count(func.distinct(vid))).group_by(
            UpstreamAdvisory.product
        )
    ):
        if slug in counts:
            counts[slug]["total"] = total
    for slug, kev in session.execute(
        select(UpstreamAdvisory.product, func.count(func.distinct(KEVEntry.vulnerability_id)))
        .join(KEVEntry, KEVEntry.vulnerability_id == UpstreamAdvisory.vulnerability_id)
        .where(KEVEntry.is_active)
        .group_by(UpstreamAdvisory.product)
    ):
        if slug in counts:
            counts[slug]["kev"] = kev
    for slug, recent in session.execute(
        select(UpstreamAdvisory.product, func.count(func.distinct(Vulnerability.id)))
        .join(Vulnerability, Vulnerability.id == UpstreamAdvisory.vulnerability_id)
        .where(Vulnerability.published_at >= since)
        .group_by(UpstreamAdvisory.product)
    ):
        if slug in counts:
            counts[slug]["recent"] = recent
    return counts


def product_page(session, slug, page=1):
    rule = products().get(slug)
    if rule is None:
        return None
    rows = session.scalars(select(UpstreamAdvisory).where(UpstreamAdvisory.product == slug)).all()
    by_id = {}
    for row in rows:
        key = row.vulnerability_id or row.id
        entry = by_id.setdefault(key, {"ranges": [], "ref": row.ref, "cve_ids": set()})
        entry["ranges"].extend(describe_range(r["events"]) for r in row.ranges)
        entry["cve_ids"].update(row.cve_ids or [])
    facts = _facts(session, by_id)
    items = []
    for key, entry in by_id.items():
        row = summary(key, facts.get(key) or {"vuln": None, "kev": None, "epss": None})
        row["ranges"] = entry["ranges"][:4]
        row["more_ranges"] = max(0, len(entry["ranges"]) - 4)
        row["ref"] = entry["ref"]
        row["linkable"] = key in facts and facts[key]["vuln"] is not None
        items.append(row)
    since = (datetime.now(UTC) - timedelta(days=90)).date().isoformat()
    recent = sorted((r for r in items if (r["published"] or "") >= since), key=sort_key)
    kev = sorted((r for r in items if r["kev"]), key=lambda r: r["kev_added"] or "", reverse=True)
    history = sorted(items, key=lambda r: (r["published"] or "", r["id"]), reverse=True)
    pages = max(1, -(-len(history) // PAGE_SIZE))
    page = min(max(1, page), pages, MAX_PAGE)
    return {
        "slug": slug,
        "rule": rule,
        "total": len(items),
        "recent": recent,
        "kev": kev,
        "history": history[(page - 1) * PAGE_SIZE : page * PAGE_SIZE],
        "page": page,
        "pages": pages,
        "detection": _detection(rule),
    }


def _detection(rule):
    detect = rule.get("detect") or {}
    places = [
        {"path": b["glob"], "method": METHOD_NAMES.get(b.get("method"), b.get("method", ""))}
        for b in detect.get("binaries", [])
    ]
    return {
        "places": places,
        "packages": (detect.get("packages") or {}).get("names", []),
        "processes": detect.get("process_names", []),
        "bundled": [b["product"] for b in detect.get("bundled", [])],
        "notes": (rule.get("identity") or {}).get("notes", ""),
        "sources": [
            f"{p['vendor']} / {p['product']}"
            for p in (rule.get("identity") or {}).get("cve_affected", [])
        ],
    }


# ------------------------------------------------------------------ CVE page


def vulnerability_page(session, vid):
    vuln = session.get(Vulnerability, vid)
    if vuln is None:
        return None
    facts = _facts(session, [vid])[vid]
    row = summary(vid, facts)
    kev = facts["kev"]
    record = vuln.raw_record or {}
    cna = record.get("containers", {}).get("cna", {})
    references = [
        {"url": r["url"], "tags": r.get("tags", [])}
        for r in cna.get("references", [])
        if isinstance(r.get("url"), str) and r["url"].startswith(("https://", "http://"))
    ][:20]
    aliases = session.scalars(
        select(VulnerabilityAlias.alias)
        .where(VulnerabilityAlias.vulnerability_id == vid)
        .order_by(VulnerabilityAlias.alias)
        .limit(50)
    ).all()
    return {
        **row,
        "status": vuln.status,
        "title_full": vuln.title,
        "description": vuln.description,
        "modified": vuln.modified_at.date().isoformat() if vuln.modified_at else None,
        "cvss_vector": vuln.cvss_vector,
        "cvss_source": vuln.cvss_source,
        "cvss3": cvss3(vuln),
        "cwes": vuln.cwes or [],
        "ssvc": _ssvc(vuln.ssvc),
        "kev_detail": {
            "added": kev.date_added.isoformat(),
            "due": kev.due_date.isoformat() if kev.due_date else None,
            "name": kev.name,
            "action": kev.required_action,
            "ransomware": kev.ransomware,
        }
        if kev
        else None,
        "epss_date": facts["epss"].score_date.isoformat() if facts["epss"] else None,
        "priority_text": PRIORITY_TEXT[row["priority"]],
        "distros": (distros := _distro_matrix(session, vid)),
        "upstream": (upstream := _upstream_for(session, vid)),
        "guidance": _guidance(distros, upstream),
        "timeline": _timeline(session, vuln, kev),
        "aliases": [a for a in aliases if a != vid],
        "references": references,
        "cve_org": f"https://www.cve.org/CVERecord?id={vid}" if vid.startswith("CVE-") else None,
    }


def _guidance(distros, upstream):
    """What to do, in one glance: distro fix coverage and upstream fixed versions."""
    fixed, unfixed, minor = [], [], 0
    for group in distros:
        label = f"{group['distro']} {group['release']}".strip()
        pending = [p for p in group["packages"] if p["status"] != "fixed"]
        if not pending:
            fixed.append(label)
            continue
        unfixed.append(label)
        if all(p["minor"] for p in pending):
            minor += 1  # the distro rates every open item as unimportant
    versions = []
    for item in upstream:
        for rng in item["ranges"]:
            if rng.get("fixed") and rng["fixed"] not in versions:
                versions.append(rng["fixed"])
    return {
        "distro_fixed": fixed,
        "distro_unfixed": unfixed,
        "distro_minor": minor,
        "upstream_fixed": versions[:8],
        "upstream_names": sorted({u["name"] for u in upstream}),
        "upstream_unfixed": bool(upstream) and not versions,
    }


def _ssvc(value):
    if not isinstance(value, dict):
        return None
    options = {}
    for item in value.get("options", []) if isinstance(value.get("options"), list) else []:
        if isinstance(item, dict):
            options.update({str(k): str(v) for k, v in item.items()})
    return options or None


def _distro_matrix(session, vid):
    rows = session.scalars(
        select(AffectedPackage).where(AffectedPackage.vulnerability_id == vid)
    ).all()
    groups = {}
    for row in rows:
        if not row.distro:
            continue
        key = (row.distro, row.release or "")
        meta = row.source_metadata or {}
        urgency = ((meta.get("ecosystem_specific") or {}).get("urgency") or "").strip("* ").lower()
        groups.setdefault(key, []).append(
            {
                "package": row.package_name,
                "status": row.status,
                "status_text": STATUS_NAMES.get(row.status, row.status),
                "fixed": row.fixed_version,
                "url": row.source_url,
                "minor": urgency in ("unimportant", "end-of-life"),
                "subscription": row.requires_subscription,
            }
        )

    def order(key):
        distro, release = key
        rank = DISTRO_ORDER.index(distro) if distro in DISTRO_ORDER else 99
        parts = [int(p) if p.isdigit() else 0 for p in release.split(".")]
        return (rank, parts)

    return [
        {
            "distro": DISTRO_NAMES.get(distro, distro),
            "release": release,
            "packages": sorted(groups[(distro, release)], key=lambda p: p["package"]),
        }
        for distro, release in sorted(groups, key=order)
    ]


def _upstream_for(session, vid):
    rows = session.scalars(
        select(UpstreamAdvisory)
        .where(UpstreamAdvisory.vulnerability_id == vid)
        .order_by(UpstreamAdvisory.product)
    ).all()
    rules = products()
    out = []
    for row in rows:
        out.append(
            {
                "slug": row.product,
                "name": rules.get(row.product, {}).get("name", row.product),
                "ranges": [describe_range(r["events"]) for r in row.ranges],
                "ref": row.ref,
                "source": "Node.js Security WG" if row.source != "cve" else "CVE 记录（CNA）",
            }
        )
    return out


def _timeline(session, vuln, kev):
    items = []
    if vuln.published_at:
        items.append((vuln.published_at, "CVE 公开", "cvelistV5"))
    if kev:
        items.append(
            (
                datetime.combine(kev.date_added, datetime.min.time(), tzinfo=UTC),
                EVENT_NAMES["added_to_kev"],
                "kev",
            )
        )
    events = session.scalars(
        select(VulnerabilityEvent)
        .where(
            VulnerabilityEvent.vulnerability_id == vuln.id,
            VulnerabilityEvent.is_baseline.is_(False),
            VulnerabilityEvent.event_type != "added_to_kev",
        )
        .order_by(VulnerabilityEvent.happened_at)
        .limit(50)
    ).all()
    for e in events:
        items.append((e.happened_at, EVENT_NAMES.get(e.event_type, e.event_type), e.source))
    if vuln.modified_at and (not vuln.published_at or vuln.modified_at > vuln.published_at):
        items.append((vuln.modified_at, "CVE 记录最近更新", "cvelistV5"))

    def when(value):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value

    items.sort(key=lambda i: when(i[0]))
    return [
        {"date": when(t).date().isoformat(), "text": text, "source": SOURCES.get(src, (src,))[0]}
        for t, text, src in items
    ]


# ------------------------------------------------------------------ home, feeds


def recent_kev(session, days=30, limit=15):
    since = date.today() - timedelta(days=days)
    entries = session.scalars(
        select(KEVEntry)
        .where(KEVEntry.is_active, KEVEntry.date_added >= since)
        .order_by(KEVEntry.date_added.desc(), KEVEntry.vulnerability_id.desc())
        .limit(limit)
    ).all()
    facts = _facts(session, [e.vulnerability_id for e in entries])
    out = []
    for e in entries:
        row = summary(e.vulnerability_id, facts[e.vulnerability_id])
        row["kev_name"] = e.name
        row["vendor_product"] = f"{e.vendor} {e.product}"
        out.append(row)
    return out


def kev_page(session, page=1):
    page = min(max(1, page), MAX_PAGE)
    entries = session.scalars(
        select(KEVEntry)
        .where(KEVEntry.is_active)
        .order_by(KEVEntry.date_added.desc(), KEVEntry.vulnerability_id.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    return [
        {
            "id": e.vulnerability_id,
            "date_added": e.date_added.isoformat(),
            "vendor": e.vendor,
            "product": e.product,
            "name": e.name,
            "ransomware": e.ransomware,
        }
        for e in entries
    ]


def recent_events(session, limit=30, page=1, priorities=("P0", "P1", "P2")):
    page = min(max(1, page), MAX_PAGE)
    events = session.scalars(
        select(VulnerabilityEvent)
        .where(
            VulnerabilityEvent.is_baseline.is_(False),
            VulnerabilityEvent.priority.in_(priorities),
        )
        .order_by(VulnerabilityEvent.happened_at.desc(), VulnerabilityEvent.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    ).all()
    return [
        {
            "id": e.id,
            "vulnerability_id": e.vulnerability_id,
            "type": e.event_type,
            "text": EVENT_NAMES.get(e.event_type, e.event_type),
            "priority": e.priority,
            "happened_at": (
                e.happened_at.replace(tzinfo=UTC) if e.happened_at.tzinfo is None else e.happened_at
            ),
            "source": SOURCES.get(e.source, (e.source,))[0],
        }
        for e in events
    ]


def freshness(session):
    """Last successful run per data source, for the footer and /about."""
    names = {"cve:delta": "CVE 记录", "kev": "CISA KEV", "epss": "FIRST EPSS"}
    found = {}
    for state in session.scalars(select(IngestionState)):
        if state.source in names:
            label = names[state.source]
        elif state.source.startswith("osv:"):
            label = "发行版安全公告（OSV）"  # several feeds; the oldest one is shown
        else:
            continue
        when = state.last_success_at
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if label not in found or (
            when is not None and (found[label] is None or when < found[label])
        ):
            found[label] = when
    order = [*names.values(), "发行版安全公告（OSV）"]
    return [{"source": k, "last_success": found[k]} for k in order if k in found]


def risk_breakdown(session, days=30):
    """Newly published CVEs in the window, counted by site priority."""
    since = datetime.now(UTC) - timedelta(days=days)
    rows = session.execute(
        select(
            Vulnerability.severity,
            Vulnerability.cvss,
            Vulnerability.cvss_version,
            KEVEntry.vulnerability_id,
            EPSSScore.epss,
        )
        .outerjoin(
            KEVEntry,
            (KEVEntry.vulnerability_id == Vulnerability.id) & KEVEntry.is_active,
        )
        .outerjoin(EPSSScore, EPSSScore.vulnerability_id == Vulnerability.id)
        .where(Vulnerability.status == "PUBLISHED", Vulnerability.published_at >= since)
    ).all()
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for severity, cvss, version, kev, epss in rows:
        score3 = cvss if version in ("3.0", "3.1") else None
        counts[
            priority(kev is not None, float(epss) if epss is not None else None, score3, severity)
        ] += 1
    total = sum(counts.values())
    return {
        "days": days,
        "total": total,
        "segments": [
            {"level": level, "count": n, "share": (n / total * 100) if total else 0}
            for level, n in counts.items()
        ],
    }


def kev_list(session, page=1):
    total = (
        session.scalar(select(func.count()).select_from(KEVEntry).where(KEVEntry.is_active)) or 0
    )
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(1, page), pages, MAX_PAGE)
    entries = session.scalars(
        select(KEVEntry)
        .where(KEVEntry.is_active)
        .order_by(KEVEntry.date_added.desc(), KEVEntry.vulnerability_id.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    facts = _facts(session, [e.vulnerability_id for e in entries])
    items = []
    for e in entries:
        row = summary(e.vulnerability_id, facts[e.vulnerability_id])
        row["kev_name"] = e.name
        row["vendor_product"] = f"{e.vendor} {e.product}"
        items.append(row)
    return {"rows": items, "page": page, "pages": pages, "total": total}
