"""Upstream (non-distro) product vulnerability ranges for scanner layer L2.

Two sources feed the ``upstream_advisories`` table:

* CVE records: the CNA's ``affected[]`` versions for vendor/product pairs listed
  in ``rules/products/*.json`` (``identity.cve_affected``). Synced at ingest.
* The Node.js security working group database (``collector/adapters/nodejs.py``),
  because Node.js bundles dependencies (e.g. Brotli) whose CVEs are filed under
  another vendor and never name Node.js.

Ranges use upstream version strings; distro backports do not apply here.
Anything whose meaning is unclear is skipped rather than guessed.
"""

import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from apps.server.models import UpstreamAdvisory, Vulnerability
from collector.store import digest, upsert

RULES = Path(__file__).resolve().parents[1] / "rules" / "products"
# Upstream versions as the scanner compares them: no '-' (rpm release separator)
# and no '+' build metadata; pre-release and build suffixes are dropped.
VERSION = re.compile(r"[0-9][0-9A-Za-z.~_]{0,63}")
# GitHub's CNA writes ranges inside the version field: ">= 1.7.0, < 1.7.27".
GITHUB_PART = re.compile(r"(>=|<=|>|<|=)\s*(\S+)")
WILDCARD = re.compile(r"([0-9]+(?:\.[0-9]+)*)\.[*x]")
UNKNOWN = {"", "*", "0", "n/a", "unspecified", "all", "-"}


@lru_cache(maxsize=1)
def identities():
    """{(vendor.lower(), product.lower()): slug} from the product rules."""
    out = {}
    for path in sorted(RULES.glob("*.json")):
        rule = json.loads(path.read_text())
        for pair in rule.get("identity", {}).get("cve_affected", []):
            out[(pair["vendor"].strip().lower(), pair["product"].strip().lower())] = rule["slug"]
    return out


def _next_branch(prefix):
    """'8.2' -> '8.3.0' (exclusive upper bound of the 8.2.* branch)."""
    parts = [int(p) for p in prefix.split(".")]
    parts[-1] += 1
    return ".".join(str(p) for p in parts + [0] * max(0, 3 - len(parts)))


def clean(version):
    """'v2.0.0-beta.1+meta' -> '2.0.0'; None if it is not a plain version."""
    value = (version or "").strip()
    if value[:1] in "vV" and value[1:2].isdigit():
        value = value[1:]
    value = re.split(r"[-+]", value, maxsplit=1)[0]
    return value if VERSION.fullmatch(value) else None


def _start(version):
    """Normalise a CVE 'version' to an introduced value, or None if unusable."""
    value = (version or "").strip()
    if value.lower() in UNKNOWN:
        return "0", None
    wildcard = WILDCARD.fullmatch(value)
    if wildcard:
        prefix = wildcard.group(1)
        return prefix + ".0" * max(1, 3 - len(prefix.split("."))), _next_branch(prefix)
    cleaned = clean(value)
    if cleaned:
        return cleaned, None
    return None, None


def _github_events(value):
    """Events for a GitHub-style range string, or None if it is not one."""
    low = fixed = last = exact = None
    for part in [p.strip() for p in value.split(",") if p.strip()]:
        match = GITHUB_PART.fullmatch(part)
        if not match:
            return None
        op, version = match.group(1), clean(match.group(2))
        if version is None:
            return None
        if op in (">=", ">"):
            low = version
        elif op == "<":
            fixed = version
        elif op == "<=":
            last = version
        else:
            exact = version
    if exact:
        return [{"introduced": exact}, {"last_affected": exact}]
    events = [{"introduced": low or "0"}]
    if fixed:
        events.append({"fixed": fixed})
    elif last:
        events.append({"last_affected": last})
    elif not low:
        return None
    return events


# Older records describe ranges in prose. Only these unambiguous forms are read.
_V = r"v?([0-9][0-9A-Za-z.~_+-]*)"
TEXT_FORMS = [
    # "8.0.34 and prior", "2.4.48 and earlier", "1.1.1k or before"
    (
        re.compile(
            _V + r"\s+(?:and|or)\s+(?:prior|earlier|before|below|older|lower)(?:\s+versions?)?",
            re.I,
        ),
        "last_affected",
    ),
    # "before 2.4.49", "prior to 8.0.35", "versions before 3.0.7", "earlier than 1.2"
    (
        re.compile(
            r"(?:all\s+)?(?:versions?\s+)?(?:before|prior\s+to|earlier\s+than|lower\s+than|below)\s+"
            + _V,
            re.I,
        ),
        "fixed",
    ),
    # "through 3.0.7", "up to and including 8.0.34", "up to 1.2.3"
    (
        re.compile(r"(?:versions?\s+)?(?:through|up\s+to(?:\s+and\s+including)?)\s+" + _V, re.I),
        "last_affected",
    ),
]
TEXT_SPAN = re.compile(_V + r"\s+(?:-|to|through)\s+" + _V, re.I)
# "7.3.x below 7.3.17", "all 11.x before 11.5", "2.4.x through 2.4.27".
TEXT_BRANCH = re.compile(
    r"(?:all\s+)?([0-9]+(?:\.[0-9]+)*)\.x\s+"
    r"(?:(before|below|prior\s+to|earlier\s+than|lower\s+than|<)"
    r"|through|up\s+to(?:\s+and\s+including)?|<=)\s*" + _V,
    re.I,
)
# "Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c)".
FIXED_IN = re.compile(r"fixed\s+in\s+(.+?)\s*\(\s*affected\s+([^)]*)\)", re.I)
# Product names some CNAs put in front of the version. Only names of products
# we track; module paths whose versions are not the product's (moby/moby/v2)
# are deliberately absent.
PRODUCT_PREFIX = re.compile(
    r"(?:all\s+)?(?:apache\s+http\s+server|openssl|docker\s+engine|postgresql|php|redis"
    r"|mysql(?:\s+server)?|mariadb|nginx|openssh|containerd"
    r"|github\.com/docker/docker(?:/[\w./-]*)?)(?:\s+versions?)?(?:\s+|-(?=[0-9])|$)",
    re.I,
)
# Separators between the parts of a combined string:
# "7.3.x below 7.3.17 and 7.4.x below 7.4.5", "2.2.0 to 2.2.31, 2.4.1 to 2.4.23",
# "5.5.57 and earlier  5.6.37 and earlier".
TEXT_SPLIT = re.compile(r"\s*[,;]\s*(?:and\s+)?|\s+and\s+(?=v?[0-9])|\s{2,}")


def strip_product(value):
    """'Apache HTTP Server 2.4.49' -> '2.4.49'; 'openssl-1.1.0a' -> '1.1.0a'."""
    value = (value or "").strip()
    match = PRODUCT_PREFIX.match(value)
    return value[match.end() :].strip() if match else value


def _exact(version):
    """A single listed version, only if it is specific (at least x.y.z)."""
    version = clean(version)
    if version and len(re.findall(r"[0-9]+", version)) >= 3:
        return version
    return None


def _text_events(value):
    """Events for one prose range ("8.0.34 and prior", "2.4.0 - 2.4.48"), or None."""
    # "Apache HTTP Server 2.4 2.4.17 to 2.4.48": drop the leading branch label.
    value = re.sub(r"^([0-9]+\.[0-9]+)\s+(?=\1\.)", "", value)
    branch = TEXT_BRANCH.fullmatch(value)
    if branch:
        prefix, bound = branch.group(1), clean(branch.group(3))
        if not bound or not bound.startswith(prefix + "."):
            return None  # "7.2.x below 8.0.1" is not a branch statement
        kind = "fixed" if branch.group(2) else "last_affected"
        return [{"introduced": prefix + ".0"}, {kind: bound}]
    span = TEXT_SPAN.fullmatch(value)
    if span:
        low, high = clean(span.group(1)), clean(span.group(2))
        if re.search(r"\.[xX*]$", span.group(1)):
            return None
        return [{"introduced": low}, {"last_affected": high}] if low and high else None
    for pattern, kind in TEXT_FORMS:
        match = pattern.fullmatch(value)
        if match:
            version = clean(match.group(1))
            return [{"introduced": "0"}, {kind: version}] if version else None
    exact = _exact(value)
    if exact:
        return [{"introduced": exact}, {"last_affected": exact}]
    return None


def _text_ranges(value):
    """Event lists for a prose version string; None unless every part is understood."""
    fixed_in = FIXED_IN.fullmatch(value)
    if fixed_in:
        if not clean(strip_product(fixed_in.group(1))):
            return None
        out = []
        for part in fixed_in.group(2).split(","):
            low, dash, high = part.strip().partition("-")
            low, high = clean(low), clean(high) if dash else _exact(low)
            if not low or not high:
                return None
            out.append([{"introduced": low}, {"last_affected": high}])
        return out or None
    out = []
    for part in TEXT_SPLIT.split(value):
        events = _text_events(strip_product(part))
        if events is None:
            return None
        out.append(events)
    return out or None


def cve_ranges(versions, default_status="unaffected", unparsed=None):
    """Convert CVE 5 ``versions`` to OSV-style ranges.

    Returns (ranges, skipped) where skipped counts entries that were ambiguous.
    Each affected entry becomes its own range so branches never interact.
    If ``unparsed`` is a list, the raw version strings that were skipped are
    appended to it (used by the coverage diagnostics).
    """
    ranges, skipped = [], 0

    def skip(item):
        nonlocal skipped
        skipped += 1
        if unparsed is not None:
            unparsed.append((item.get("version") or "").strip()[:80])

    statuses = [(item.get("status") or "").lower() for item in versions or []]
    if (default_status or "unaffected").lower() == "affected" and "unaffected" in statuses:
        # "Everything is affected except ..." cannot be expressed safely. When
        # only affected entries are listed they are still read; versions the
        # record leaves unlisted are then missed, never wrongly reported.
        if unparsed is not None:
            unparsed.append("<defaultStatus: affected + unaffected>")
        return [], len(versions or []) or 1
    for item in versions or []:
        if (item.get("status") or "").lower() != "affected":
            continue
        if (item.get("versionType") or "").lower() == "git":
            skip(item)
            continue
        original = (item.get("version") or "").strip()
        raw = strip_product(original)
        bounded = item.get("lessThan") or item.get("lessThanOrEqual")
        if not bounded and re.search(r"[<>=]", raw) and not TEXT_BRANCH.fullmatch(raw):
            events = _github_events(raw)
            if events is None:
                skip(item)
            else:
                ranges.append({"type": "UPSTREAM", "events": events})
            continue
        if not bounded and (re.search(r"[\s,(]", raw) or raw != original):
            found = _text_ranges(raw)
            if found is None:
                skip(item)
            else:
                ranges.extend({"type": "UPSTREAM", "events": events} for events in found)
            continue
        start, branch_end = _start(raw)
        if start is None:
            skip(item)
            continue
        less = (item.get("lessThan") or "").strip()
        less_eq = (item.get("lessThanOrEqual") or "").strip()
        events = [{"introduced": start}]
        if less:
            if less == "*":
                pass  # affected from start onward, no fix in this branch
            elif clean(less):
                events.append({"fixed": clean(less)})
            else:
                skip(item)
                continue
        elif less_eq:
            if less_eq == "*":
                pass
            elif clean(less_eq):
                events.append({"last_affected": clean(less_eq)})
            else:
                skip(item)
                continue
        elif branch_end:
            events.append({"limit": branch_end})
        elif start == "0":
            skip(item)  # "all versions" with no bound says nothing useful
            continue
        else:
            events.append({"last_affected": start})  # a single exact version
        ranges.append({"type": "UPSTREAM", "events": events})
    return _cap_open_ranges(_branch_starts(ranges)), skipped


def _bound(rng):
    for event in rng["events"][1:]:
        for kind in ("fixed", "last_affected"):
            if kind in event:
                return event[kind]
    return None


def _branch(version):
    """Release branch of a version: '8.1.12' -> ('8', '1'); '13.1' -> ('13',).

    Two-part versions (PostgreSQL 10+: 13.1) are treated as major.patch.
    """
    parts = re.findall(r"[0-9]+", version)
    return tuple(parts[:1]) if len(parts) == 2 else tuple(parts[:2])


def _branch_starts(ranges):
    """Give per-branch lists a lower bound.

    Older records list one bound per branch with no start, e.g. PHP's
    "before 7.4.33 | before 8.0.25 | before 8.1.12". Read literally, "before
    8.1.12" would also cover the already-fixed 8.0.30. Every such range except
    the lowest therefore starts at its own branch (8.1.12 -> 8.1.0, 13.1 -> 13.0).
    """
    open_start = [r for r in ranges if r["events"][0].get("introduced") == "0" and _bound(r)]
    if len(open_start) < 2:
        return ranges
    open_start.sort(key=lambda r: _key(_bound(r)))
    for lower, rng in zip(open_start, open_start[1:], strict=False):
        branch = _branch(_bound(rng))
        if len(branch) >= 1 and branch != _branch(_bound(lower)):
            rng["events"][0] = {"introduced": ".".join(branch) + ".0"}
    return ranges


def _key(version):
    """Sort key for upstream versions; numbers before letters, never mixed."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.+~_-]", version)]


def _cap_open_ranges(ranges):
    """Bound open-ended ranges at the next listed branch.

    Vendors (e.g. F5 for nginx) write '1.30.0 <1.30.6', '1.31.0 <1.31.7' and
    '1.25.0 <*' meaning "1.25–1.29 are affected and will not be fixed"; read
    literally the last entry would also cover the fixed 1.30.6. An open range
    therefore ends where the next listed branch begins.
    """
    starts = sorted(
        (r["events"][0]["introduced"] for r in ranges if r["events"][0]["introduced"] != "0"),
        key=_key,
    )
    for r in ranges:
        if len(r["events"]) != 1:
            continue
        start = r["events"][0]["introduced"]
        later = [s for s in starts if _key(s) > _key(start)] if start != "0" else starts
        if later:
            r["events"].append({"limit": later[0]})
    return ranges


def cve_rows(record):
    """Upstream advisory rows derived from one CVE record (CNA container only)."""
    meta = record.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if meta.get("state") != "PUBLISHED" or not cve_id:
        return []
    ids = identities()
    found = {}
    for affected in record.get("containers", {}).get("cna", {}).get("affected", []) or []:
        key = (
            (affected.get("vendor") or "").strip().lower(),
            (affected.get("product") or "").strip().lower(),
        )
        slug = ids.get(key)
        if not slug:
            continue
        ranges, _skipped = cve_ranges(affected.get("versions"), affected.get("defaultStatus"))
        if ranges:
            found.setdefault(slug, []).extend(ranges)
    rows = []
    for slug, ranges in found.items():
        body = {"product": slug, "cve_ids": [cve_id], "ranges": ranges}
        rows.append(
            {
                "id": f"cve:{slug}:{cve_id}",
                "product": slug,
                "source": "cve",
                "vulnerability_id": cve_id,
                "cve_ids": [cve_id],
                "ranges": ranges,
                "severity": None,
                "ref": f"https://www.cve.org/CVERecord?id={cve_id}",
                "record_hash": digest(body),
                "updated_at": datetime.now(UTC),
            }
        )
    return rows


def sync_cve(session, records):
    """Refresh the CVE-derived rows for the given raw CVE records."""
    ids = [r.get("cveMetadata", {}).get("cveId") for r in records]
    ids = [i for i in ids if i]
    if not ids:
        return
    session.execute(
        delete(UpstreamAdvisory).where(
            UpstreamAdvisory.source == "cve", UpstreamAdvisory.vulnerability_id.in_(ids)
        )
    )
    rows = [row for record in records for row in cve_rows(record)]
    if rows:
        upsert(session, UpstreamAdvisory, rows, ["id"])


def backfill(engine, batch=1000):
    """Derive CVE-based rows for the whole corpus once (later updates arrive at ingest)."""
    last, total, matched = "", 0, 0
    while True:
        with Session(engine) as session, session.begin():
            records = session.execute(
                select(Vulnerability.id, Vulnerability.raw_record)
                .where(Vulnerability.id > last, Vulnerability.raw_record.is_not(None))
                .order_by(Vulnerability.id)
                .limit(batch)
            ).all()
            if not records:
                return {"records": total, "upstream_rows": matched}
            raws = [r.raw_record for r in records]
            sync_cve(session, raws)
            matched += sum(len(cve_rows(raw)) for raw in raws)
            total += len(records)
            last = records[-1].id


def coverage(engine, batch=2000, top=15):
    """Per product: CVEs naming it, CVEs converted, and the commonest version
    strings that could not be read. Read-only; for improving the converter."""
    from collections import Counter

    ids = identities()
    stats = {}
    last = ""
    while True:
        with Session(engine) as session:
            records = session.execute(
                select(Vulnerability.id, Vulnerability.raw_record)
                .where(
                    Vulnerability.id > last,
                    Vulnerability.status == "PUBLISHED",
                    Vulnerability.raw_record.is_not(None),
                )
                .order_by(Vulnerability.id)
                .limit(batch)
            ).all()
        if not records:
            break
        last = records[-1].id
        for rec in records:
            cna = rec.raw_record.get("containers", {}).get("cna", {})
            seen = {}
            for affected in cna.get("affected", []) or []:
                key = (
                    (affected.get("vendor") or "").strip().lower(),
                    (affected.get("product") or "").strip().lower(),
                )
                slug = ids.get(key)
                if not slug:
                    continue
                unparsed = []
                ranges, _ = cve_ranges(
                    affected.get("versions"), affected.get("defaultStatus"), unparsed
                )
                s = stats.setdefault(
                    slug, {"cves": set(), "converted": set(), "unparsed": Counter()}
                )
                s["cves"].add(rec.id)
                if ranges:
                    s["converted"].add(rec.id)
                seen.setdefault(slug, []).extend(unparsed)
            for slug, strings in seen.items():
                if rec.id not in stats[slug]["converted"]:
                    stats[slug]["unparsed"].update(strings or ["<no affected versions>"])
    return {
        slug: {
            "cves": len(s["cves"]),
            "converted": len(s["converted"]),
            "top_unparsed": s["unparsed"].most_common(top),
        }
        for slug, s in sorted(stats.items())
    }


# ---------------------------------------------------------------- Node.js semver

SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
MAJOR_X = re.compile(r"([0-9]+)(?:\.x|\.\*)?(?:\.x|\.\*)?")


def _clause_interval(clause):
    """One '||' clause of a node-semver range -> (low, high_exclusive, fix_is_high).

    Supports the forms used by the Node.js security WG: '22.x', '^22.1.0',
    '>=14.0.0 <14.17.6', '<12.22.6', '>=16.8.0', '22.1.0'. Returns None otherwise.
    """
    tokens = re.sub(r"(>=|<=|<|>)\s+", r"\1", clause).split()
    if len(tokens) == 1:
        t = tokens[0]
        if m := MAJOR_X.fullmatch(t):
            major = int(m.group(1))
            return f"{major}.0.0", f"{major + 1}.0.0", False
        if t.startswith("^") and SEMVER.fullmatch(t[1:]):
            major = int(t[1:].split(".")[0])
            return t[1:], f"{major + 1}.0.0", False
        if t.startswith("<") and not t.startswith("<=") and SEMVER.fullmatch(t[1:]):
            return "0", t[1:], True
        if t.startswith(">=") and SEMVER.fullmatch(t[2:]):
            return t[2:], None, False
        if SEMVER.fullmatch(t):
            return t, t, None
        return None
    if len(tokens) == 2 and tokens[0].startswith(">=") and tokens[1].startswith("<"):
        low, high = tokens[0][2:], tokens[1][1:]
        if SEMVER.fullmatch(low) and SEMVER.fullmatch(high) and not tokens[1].startswith("<="):
            return low, high, True
    return None


def _major(version):
    return int(version.split(".")[0])


def node_ranges(vulnerable, patched):
    """Convert a security-wg entry's 'vulnerable'/'patched' to ranges.

    Returns (ranges, ok). For each vulnerable interval the fix is the patched
    version in the same major line; a major with no patched release stays
    affected (typically an end-of-life line).
    """
    fixes = {}
    for clause in (patched or "").split("||"):
        clause = clause.strip()
        if not clause:
            continue
        interval = _clause_interval(clause)
        if interval is None:
            return [], False
        low = interval[0]
        if low != "0":
            fixes.setdefault(_major(low), low)
    ranges = []
    for clause in (vulnerable or "").split("||"):
        clause = clause.strip()
        if not clause:
            continue
        interval = _clause_interval(clause)
        if interval is None:
            return [], False
        low, high, high_is_fix = interval
        if high_is_fix is None:  # exact single version
            ranges.append(
                {"type": "UPSTREAM", "events": [{"introduced": low}, {"last_affected": low}]}
            )
            continue
        events = [{"introduced": low}]
        fix = fixes.get(_major(low)) if low != "0" else None
        if high_is_fix:
            events.append({"fixed": high})
        elif fix:
            events.append({"fixed": fix})
        elif high:
            events.append({"limit": high})
        ranges.append({"type": "UPSTREAM", "events": events})
    return ranges, bool(ranges)
