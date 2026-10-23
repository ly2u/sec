import csv
import gzip
import io
import re
from datetime import date
from decimal import Decimal

from sqlalchemy import delete

from apps.server.models import EPSSScore
from collector.adapters.cvelist import CVE_ID
from collector.http import validate_url
from collector.ingestion import ingest
from collector.store import ensure_vulnerabilities, upsert

DOCUMENTATION = "https://www.first.org/epss/data.html"


class ChunkReader(io.RawIOBase):
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.buffer = b""

    def readable(self):
        return True

    def readinto(self, target):
        while not self.buffer:
            try:
                self.buffer = next(self.chunks)
            except StopIteration:
                return 0
        count = min(len(target), len(self.buffer))
        target[:count] = self.buffer[:count]
        self.buffer = self.buffer[count:]
        return count


def header_metadata(line):
    fields = dict(re.findall(r"(?:^#|,)([a-z_]+):([^,\s]+)", line))
    if "score_date" not in fields or "model_version" not in fields:
        raise ValueError("Missing EPSS score date/model metadata")
    return date.fromisoformat(fields["score_date"][:10]), fields["model_version"]


def parse_csv(lines):
    score_date, model = header_metadata(next(lines).strip())
    reader = csv.DictReader(lines)
    if reader.fieldnames != ["cve", "epss", "percentile"]:
        raise ValueError("Unexpected EPSS CSV schema")
    for row in reader:
        if not CVE_ID.fullmatch(row["cve"]):
            raise ValueError("Invalid CVE ID in EPSS")
        epss, percentile = Decimal(row["epss"]), Decimal(row["percentile"])
        if not all(value.is_finite() and 0 <= value <= 1 for value in (epss, percentile)):
            raise ValueError("Invalid EPSS probability")
        yield {
            "vulnerability_id": row["cve"],
            "score_date": score_date,
            "epss": epss,
            "percentile": percentile,
            "model_version": model,
        }


def apply_scores(session, records):
    if not records:
        return
    ensure_vulnerabilities(session, [row["vulnerability_id"] for row in records])
    upsert(
        session,
        EPSSScore,
        records,
        ["vulnerability_id"],
        update_where=lambda excluded: excluded.score_date >= EPSSScore.score_date,
    )


class EPSSAdapter:
    def __init__(self, http):
        self.http = http

    def discover_url(self):
        documentation = self.http.read(DOCUMENTATION, max_bytes=2 * 1024 * 1024).decode()
        links = re.findall(r'https://[^\s<>"`]+\.csv\.gz', documentation)
        current = next((url for url in links if url.endswith("/epss_scores-current.csv.gz")), None)
        if not current:
            raise ValueError(
                "FIRST documentation has no recognized current daily CSV link; configure --url"
            )
        validate_url(current)
        return current

    def lines(self, url):
        with self.http.stream(url) as chunks:
            with io.BufferedReader(ChunkReader(chunks)) as buffered:
                with gzip.GzipFile(fileobj=buffered) as uncompressed:
                    with io.TextIOWrapper(uncompressed, encoding="utf-8", newline="") as lines:
                        while line := lines.readline(1024 * 1024 + 1):
                            if len(line) > 1024 * 1024:
                                raise ValueError("Oversized EPSS CSV row")
                            yield line

    def run(self, engine, *, limit=1000, restart=False, url=None):
        url = url or self.discover_url()
        lines = self.lines(url)
        try:
            score_date, model = header_metadata(next(lines).strip())
        finally:
            lines.close()

        def records():
            for row in parse_csv(self.lines(url)):
                if row["score_date"] != score_date or row["model_version"] != model:
                    raise ValueError("EPSS daily snapshot changed during download")
                yield row

        def finish(session):
            # Only a complete daily snapshot may remove older scores; a sample may not.
            session.execute(delete(EPSSScore).where(EPSSScore.score_date < score_date))

        return ingest(
            engine,
            "epss",
            f"{score_date}:{model}",
            records,
            apply_scores,
            limit=limit,
            restart=restart,
            metadata={"url": url, "score_date": str(score_date), "model": model},
            http=self.http,
            finish=finish,
            restart_on_revision_change=True,
        )
