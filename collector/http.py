import json
import random
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

import httpx

ALLOWED_HOSTS = {
    "api.github.com",
    "github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "www.cisa.gov",
    "www.first.org",
    "api.first.org",
    "epss.empiricalsecurity.com",
    "epss.cyentia.com",
    "storage.googleapis.com",
}
RETRYABLE = {429, 500, 502, 503, 504}


def validate_url(url: str):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError("Unapproved public data-source URL")


class FeedHTTP:
    """Bounded public GETs; validates every redirect and never sends credentials."""

    def __init__(self, client=None, sleep=time.sleep, attempts=4):
        self.client = client or httpx.Client(
            timeout=30, headers={"User-Agent": "LY2U-SecWatch/0.1"}
        )
        self.owns_client = client is None
        self.sleep = sleep
        self.attempts = attempts
        self.retry_count = 0

    def close(self):
        if self.owns_client:
            self.client.close()

    def backoff(self, attempt, response=None):
        self.retry_count += 1
        retry_after = response.headers.get("Retry-After", "") if response is not None else ""
        try:
            seconds = float(retry_after)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(retry_after) - datetime.now(UTC)).total_seconds()
            except (ValueError, TypeError):
                seconds = 2**attempt + random.random()
        self.sleep(min(60, max(0, seconds)))

    def _open(self, url, method="GET"):
        for redirect in range(6):
            validate_url(url)
            request = self.client.build_request(method, url)
            response = self.client.send(request, stream=True, follow_redirects=False)
            if response.is_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location or redirect == 5:
                    raise ValueError("Invalid or excessive feed redirects")
                url = urljoin(url, location)
                continue
            return response
        raise ValueError("Excessive feed redirects")

    @contextmanager
    def stream(self, url):
        response = None
        for attempt in range(self.attempts):
            try:
                response = self._open(url)
                if response.status_code in RETRYABLE and attempt + 1 < self.attempts:
                    self.backoff(attempt, response)
                    response.close()
                    continue
                response.raise_for_status()
                break
            except httpx.TransportError:
                if response is not None:
                    response.close()
                if attempt + 1 == self.attempts:
                    raise
                self.backoff(attempt)
            except Exception:
                if response is not None:
                    response.close()
                raise
        try:
            yield response.iter_bytes(chunk_size=65536)
        finally:
            response.close()

    def read(self, url, max_bytes=32 * 1024 * 1024):
        for attempt in range(self.attempts):
            try:
                with self.stream(url) as chunks:
                    result = bytearray()
                    for chunk in chunks:
                        result.extend(chunk)
                        if len(result) > max_bytes:
                            raise ValueError("Feed exceeds permitted size")
                    return bytes(result)
            except httpx.TransportError:
                if attempt + 1 == self.attempts:
                    raise
                self.backoff(attempt)

    def json(self, url):
        return json.loads(self.read(url))

    def headers(self, url):
        for attempt in range(self.attempts):
            response = self._open(url, "HEAD")
            try:
                if response.status_code in RETRYABLE and attempt + 1 < self.attempts:
                    self.backoff(attempt, response)
                    continue
                response.raise_for_status()
                return response.headers
            finally:
                response.close()
