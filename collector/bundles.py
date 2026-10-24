"""Facts-only schema v1 bundles; publish content and signature before the manifest."""

import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import zstandard
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.server.models import (
    AffectedPackage,
    EPSSScore,
    GoAdvisory,
    IngestionState,
    KEVEntry,
    UpstreamAdvisory,
    Vulnerability,
)
from collector.distros import PACKAGE_KEYS, PACKAGE_NAME, RELEASES, VERSION

FILENAME = re.compile(
    r"(?:debian|ubuntu|rocky|alma|alpine|upstream|golang)-[\d.]+\.[a-f0-9]{12}\.json\.zst(?:\.minisig)?"
)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def public_key_id(path):
    data = base64.b64decode(Path(path).read_text().splitlines()[1], validate=True)
    if len(data) != 42 or data[:2] != b"Ed":
        raise ValueError("Invalid minisign public key")
    return data[2:10][::-1].hex().upper()


def run_minisign(arguments, binary="/usr/bin/minisign"):
    if not os.path.isabs(binary):
        raise ValueError("minisign must use an absolute path")
    return subprocess.run(
        [binary, *arguments], check=True, timeout=60, capture_output=True, text=True
    )


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o644)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def safe_ranges(ranges):
    result = []
    for item in ranges:
        if item["type"] != "ECOSYSTEM":
            raise ValueError("Distro ranges must be ECOSYSTEM")
        events = []
        for e in item["events"]:
            if (
                len(e) != 1
                or next(iter(e)) not in ("introduced", "fixed", "last_affected", "limit")
                or not VERSION.fullmatch(next(iter(e.values())))
            ):
                raise ValueError("Unsafe version event")
            events.append(e.copy())
        result.append({"type": "ECOSYSTEM", "events": events})
    return result


def urgency(metadata):
    value = ((metadata or {}).get("ecosystem_specific") or {}).get("urgency")
    if not isinstance(value, str):
        return None
    value = value.strip().strip("*").strip().lower()
    return value if re.fullmatch(r"[a-z][a-z -]{0,31}", value) else None


def enrichment_for(session, ids):
    """CVE facts (status, CVSS, EPSS, active KEV) keyed by CVE id."""
    enrichment = {}
    keys = sorted(ids)
    for offset in range(0, len(keys), 2000):
        found = session.execute(
            select(
                Vulnerability.id,
                Vulnerability.status,
                Vulnerability.cvss,
                Vulnerability.severity,
                EPSSScore.epss,
                KEVEntry.is_active,
                KEVEntry.ransomware,
            )
            .outerjoin(EPSSScore)
            .outerjoin(KEVEntry)
            .where(Vulnerability.id.in_(keys[offset : offset + 2000]))
        ).all()
        for r in found:
            enrichment[r.id] = r
    return enrichment


# Must match the scanner's upstream comparator: no '-' and no '+'.
UPSTREAM_EVENT = re.compile(r"[0-9][0-9A-Za-z.~_]{0,63}")
logger = logging.getLogger(__name__)


def ransomware(facts):
    """CISA marks the CVE as used in ransomware campaigns (active KEV entries only)."""
    return any(f.is_active is True and (f.ransomware or "").lower() == "known" for f in facts)


def upstream_entries(session):
    """Yield (product, entry) for scanner layer L2, in product order."""
    rows = session.scalars(
        select(UpstreamAdvisory).order_by(UpstreamAdvisory.product, UpstreamAdvisory.id)
    ).all()
    enrichment = enrichment_for(session, {c for r in rows for c in r.cve_ids})
    for row in rows:
        if not PACKAGE_NAME.fullmatch(row.product):
            raise ValueError("Unsafe product slug")
        parsed = urlsplit(row.ref)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Unsafe reference URL")
        ranges = []
        valid = True
        for r in row.ranges:
            events = []
            for e in r.get("events", []):
                ((kind, value),) = e.items()
                if kind not in ("introduced", "fixed", "last_affected", "limit") or not (
                    value == "0" or UPSTREAM_EVENT.fullmatch(value)
                ):
                    valid = False
                events.append({kind: value})
            valid = valid and r.get("type") == "UPSTREAM"
            ranges.append({"type": "UPSTREAM", "events": events})
        if not valid:
            # One malformed record must not block publishing every bundle.
            logger.warning("Skipping upstream advisory %s with invalid ranges", row.id)
            continue
        facts = [enrichment[c] for c in row.cve_ids if c in enrichment]
        if row.cve_ids and facts and all(f.status == "REJECTED" for f in facts):
            continue
        published = [f for f in facts if f.status == "PUBLISHED"]
        scores = [f.cvss for f in published if f.cvss is not None]
        selected = max(published, key=lambda f: f.cvss if f.cvss is not None else -1, default=None)
        severity = selected.severity if selected and selected.severity else None
        if not severity and row.severity:
            severity = row.severity.upper()
        fixes = [
            {"version": e["fixed"], "requires_subscription": False}
            for r in ranges
            for e in r["events"]
            if "fixed" in e
        ]
        yield (
            row.product,
            {
                "id": row.cve_ids[0] if len(row.cve_ids) == 1 else row.id,
                "advisory_id": row.id,
                "aliases": [],
                "cve_ids": list(row.cve_ids),
                "ecosystem": "upstream:" + row.product,
                "status": "fixed" if fixes else "unfixed",
                "fixed_version": None,
                "ranges": ranges,
                "requires_subscription": False,
                "fixes": fixes,
                "severity": severity,
                "cvss": max(scores) if scores else None,
                "kev": any(f.is_active is True for f in published),
                "ransomware": ransomware(published),
                "epss": max((float(f.epss) for f in published if f.epss is not None), default=None),
                "ref": row.ref,
                "urgency": None,
                "source": row.source,
            },
        )


def golang_entries(session):
    """Yield (module, entry) for Go-compiled programs, in module order."""
    from collector.adapters.golang import MODULE, SEMVER

    rows = session.scalars(select(GoAdvisory).order_by(GoAdvisory.module, GoAdvisory.id)).all()
    enrichment = enrichment_for(session, {c for r in rows for c in r.cve_ids})
    for row in rows:
        if not MODULE.fullmatch(row.module):
            raise ValueError("Unsafe Go module path")
        if not row.ref.startswith("https://pkg.go.dev/vuln/"):
            raise ValueError("Unexpected Go advisory reference")
        ranges = []
        for r in row.ranges:
            events = []
            for e in r["events"]:
                ((kind, value),) = e.items()
                if kind not in ("introduced", "fixed", "last_affected") or not SEMVER.fullmatch(
                    value
                ):
                    raise ValueError("Unsafe Go version event")
                events.append({kind: value})
            ranges.append({"type": "SEMVER", "events": events})
        facts = [enrichment[c] for c in row.cve_ids if c in enrichment]
        published = [f for f in facts if f.status == "PUBLISHED"]
        scores = [f.cvss for f in published if f.cvss is not None]
        selected = max(published, key=lambda f: f.cvss if f.cvss is not None else -1, default=None)
        fixes = [
            {"version": e["fixed"], "requires_subscription": False}
            for r in ranges
            for e in r["events"]
            if "fixed" in e
        ]
        yield (
            row.module,
            {
                "id": row.cve_ids[0] if len(row.cve_ids) == 1 else row.vuln_id,
                "advisory_id": row.vuln_id,
                "aliases": [],
                "cve_ids": list(row.cve_ids),
                "ecosystem": "Go",
                "status": "fixed" if fixes else "unfixed",
                "fixed_version": None,
                "ranges": ranges,
                "requires_subscription": False,
                "fixes": fixes,
                "severity": selected.severity if selected and selected.severity else None,
                "cvss": max(scores) if scores else None,
                "kev": any(f.is_active is True for f in published),
                "ransomware": ransomware(published),
                "epss": max((float(f.epss) for f in published if f.epss is not None), default=None),
                "ref": row.ref,
                "urgency": None,
            },
        )


def package_key(distro):
    return {"upstream": "product", "golang": "module"}.get(distro) or PACKAGE_KEYS[distro]


def bundle_entries(session, distro, release):
    """Yield validated entries in package order without retaining a bundle in memory."""
    # Explicit active-KEV JOIN: ADP flags never determine membership.
    ids = set()
    scope = (AffectedPackage.distro == distro, AffectedPackage.release == release)
    metadata = session.scalars(
        select(AffectedPackage.source_metadata).where(*scope).execution_options(yield_per=1000)
    )
    for value in metadata:
        ids.update(value.get("cve_ids", []))
    enrichment = enrichment_for(session, ids)
    rows = session.execute(
        select(
            AffectedPackage.vulnerability_id,
            AffectedPackage.advisory_id,
            AffectedPackage.ecosystem,
            AffectedPackage.package_name,
            AffectedPackage.package_key,
            AffectedPackage.status,
            AffectedPackage.fixed_version,
            AffectedPackage.ranges,
            AffectedPackage.requires_subscription,
            AffectedPackage.source_url,
            AffectedPackage.source_metadata,
        )
        .where(*scope)
        .order_by(AffectedPackage.package_name, AffectedPackage.entry_hash)
        .execution_options(yield_per=1000)
    ).mappings()
    for row in rows:
        if not PACKAGE_NAME.fullmatch(row.package_name):
            raise ValueError("Unsafe package name")
        if row.package_key != PACKAGE_KEYS[distro]:
            raise ValueError("Unverified package matching key")
        parsed = urlsplit(row.source_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Unsafe reference URL")
        cves = row.source_metadata.get("cve_ids", [])
        facts = [
            enrichment[v] for v in cves if v in enrichment and enrichment[v].status == "PUBLISHED"
        ]
        rejected = bool(cves) and all(
            v in enrichment and enrichment[v].status == "REJECTED" for v in cves
        )
        if rejected:
            continue
        scores = [f.cvss for f in facts if f.cvss is not None]
        selected = max(facts, key=lambda f: f.cvss if f.cvss is not None else -1, default=None)
        ranges = safe_ranges(row.ranges)
        fixes = [
            {"version": e["fixed"], "requires_subscription": row.requires_subscription}
            for r in ranges
            for e in r["events"]
            if "fixed" in e
        ]
        entry = {
            "id": row.vulnerability_id,
            "advisory_id": row.advisory_id,
            "aliases": sorted(set(row.source_metadata.get("aliases", []))),
            "cve_ids": cves,
            "ecosystem": row.ecosystem,
            "status": row.status,
            "fixed_version": row.fixed_version,
            "ranges": ranges,
            "requires_subscription": row.requires_subscription,
            "fixes": fixes,
            "severity": selected.severity if selected else None,
            "cvss": max(scores) if scores else None,
            "kev": any(f.is_active is True for f in facts),
            "ransomware": ransomware(facts),
            "epss": max((float(f.epss) for f in facts if f.epss is not None), default=None),
            "ref": row.source_url,
            # Debian tracker urgency (unimportant/low/medium/high/end-of-life);
            # lets the scanner hide issues the distro itself rates as negligible.
            "urgency": urgency(row.source_metadata),
        }
        # Retain RPM architecture/module channel facts; never infer one stream from another.
        if distro in ("rocky", "alma"):
            entry["purl"] = row.source_metadata.get("purl")
            entry["repositories"] = sorted(
                {
                    r.get("database_specific", {}).get("yum_repository")
                    for r in row.ranges
                    if r.get("database_specific", {}).get("yum_repository")
                }
            )
        yield row.package_name, entry


def fingerprint_update(hasher, value):
    value = canonical(value)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def write_payload(session, path, distro, release, generated_at, sources):
    """Stream deterministic JSON to the bundles volume and return facts about it."""
    count = 0
    first_package = True
    current_package = None
    first_entry = True
    fingerprint = hashlib.sha256()
    fingerprint_update(
        fingerprint,
        {"schema": 1, "distro": distro, "release": release, "package_key": package_key(distro)},
    )
    with path.open("wb") as output:
        os.fchmod(output.fileno(), 0o644)
        output.write(b'{"schema":1,"distro":')
        output.write(canonical(distro))
        output.write(b',"release":')
        output.write(canonical(release))
        output.write(b',"package_key":')
        output.write(canonical(package_key(distro)))
        output.write(b',"generated_at":')
        output.write(canonical(generated_at))
        output.write(b',"source_packages":{')
        if distro == "upstream":
            entries = upstream_entries(session)
        elif distro == "golang":
            entries = golang_entries(session)
        else:
            entries = bundle_entries(session, distro, release)
        for package_name, entry in entries:
            if package_name != current_package:
                if current_package is not None:
                    output.write(b"]")
                if not first_package:
                    output.write(b",")
                output.write(canonical(package_name))
                output.write(b":[")
                current_package = package_name
                first_package = False
                first_entry = True
                fingerprint_update(fingerprint, package_name)
            if not first_entry:
                output.write(b",")
            encoded = canonical(entry)
            output.write(encoded)
            fingerprint_update(fingerprint, entry)
            first_entry = False
            count += 1
        if current_package is not None:
            output.write(b"]")
        coverage = {
            "status": "available" if count else "unavailable",
            "missing_package_means": "unknown",
            "excluded_channels": ["livepatch", "fips", "realtime"] if distro == "ubuntu" else [],
        }
        fingerprint_update(fingerprint, coverage)
        output.write(b'},"sources":')
        output.write(canonical(sources))
        output.write(b',"coverage":')
        output.write(canonical(coverage))
        output.write(b"}")
        output.flush()
        os.fsync(output.fileno())
    return count, coverage, fingerprint.hexdigest(), path.stat().st_size


def compress_payload(source, destination):
    with source.open("rb") as incoming, destination.open("wb") as outgoing:
        os.fchmod(outgoing.fileno(), 0o644)
        compressed = zstandard.ZstdCompressor(level=9, write_checksum=True).compressobj(
            size=source.stat().st_size
        )
        while chunk := incoming.read(1024 * 1024):
            outgoing.write(compressed.compress(chunk))
        outgoing.write(compressed.flush())
        outgoing.flush()
        os.fsync(outgoing.fileno())
    hasher = hashlib.sha256()
    with destination.open("rb") as value:
        while chunk := value.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest(), destination.stat().st_size


def generate(
    engine, output=None, secret=None, public=None, *, binary="/usr/bin/minisign", now=None
):
    output = Path(output or os.environ.get("BUNDLES_DIR", "/bundles"))
    secret = Path(
        secret or os.environ.get("BUNDLE_SIGNING_KEY", "/run/secwatch-secrets/bundle-signing.key")
    )
    public = Path(
        public or os.environ.get("BUNDLE_SIGNING_PUBLIC_KEY", "/app/keys/bundle-signing.pub")
    )
    now = now or datetime.now(UTC)
    key_id = public_key_id(public)
    if secret.stat().st_mode & 0o077:
        raise ValueError("Signing key must not be group/world readable")
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_bytes())
        if manifest_path.exists()
        else {"schema": 1, "key_id": key_id, "bundles": {}}
    )
    updated = []
    with Session(engine) as session:
        source_states = list(session.scalars(select(IngestionState)))
        sources = {
            r.source: r.source_revision
            for r in source_states
            if r.completed and not r.source.startswith("cve:baseline")
        }
        # "upstream-1" carries layer-L2 product ranges; "golang-1" the Go
        # vulnerability database for Go-compiled programs. Schema version 1.
        for distro, releases in [*RELEASES.items(), ("upstream", ["1"]), ("golang", ["1"])]:
            for release in releases:
                slug = f"{distro}-{release}"
                payload_fd, payload_tmp = tempfile.mkstemp(prefix=".pending-payload-", dir=output)
                os.close(payload_fd)
                payload_path = Path(payload_tmp)
                count, coverage, fingerprint, uncompressed_bytes = write_payload(
                    session, payload_path, distro, release, now.isoformat(), sources
                )
                old = manifest["bundles"].get(slug)
                if (
                    old
                    and old.get("input_sha256") == fingerprint
                    and old.get("key_id") == key_id
                    and (output / old["file"]).exists()
                    and (output / old["signature"]).exists()
                ):
                    payload_path.unlink()
                    continue
                compressed_fd, compressed_tmp = tempfile.mkstemp(
                    prefix=".pending-compressed-", dir=output
                )
                os.close(compressed_fd)
                compressed_path = Path(compressed_tmp)
                try:
                    sha, compressed_bytes = compress_payload(payload_path, compressed_path)
                finally:
                    payload_path.unlink(missing_ok=True)
                name = f"{slug}.{sha[:12]}.json.zst"
                target = output / name
                os.replace(compressed_path, target)
                sync_directory(output)
                fd, sigtemp = tempfile.mkstemp(prefix=".pending-signature-", dir=output)
                os.close(fd)
                try:
                    run_minisign(
                        [
                            "-S",
                            "-W",
                            "-s",
                            str(secret),
                            "-m",
                            str(target),
                            "-x",
                            sigtemp,
                            "-t",
                            f"secwatch schema=1 key_id={key_id} file={name}",
                        ],
                        binary,
                    )
                    run_minisign(
                        ["-V", "-H", "-p", str(public), "-m", str(target), "-x", sigtemp], binary
                    )
                    atomic_write(output / (name + ".minisig"), Path(sigtemp).read_bytes())
                finally:
                    Path(sigtemp).unlink(missing_ok=True)
                manifest["bundles"][slug] = {
                    "file": name,
                    "signature": name + ".minisig",
                    "sha256": sha,
                    "input_sha256": fingerprint,
                    "key_id": key_id,
                    "entries": count,
                    "uncompressed_bytes": uncompressed_bytes,
                    "compressed_bytes": compressed_bytes,
                    "generated_at": now.isoformat(),
                    "coverage": coverage,
                }
                updated.append(slug)
    if updated:
        manifest.update({"key_id": key_id, "generated_at": now.isoformat()})
        # Publish the single mutable pointer only after every referenced file/signature exists.
        atomic_write(manifest_path, canonical(manifest))
    referenced = {
        item[key] for item in manifest["bundles"].values() for key in ("file", "signature")
    }
    cutoff = now.timestamp() - 7 * 86400
    for path in output.iterdir():
        if (
            FILENAME.fullmatch(path.name)
            and path.name not in referenced
            and path.stat().st_mtime < cutoff
        ):
            path.unlink()
    return {"rebuilt": updated, "bundles": len(manifest["bundles"])}
