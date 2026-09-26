"""Build a reviewed Web-R Book CDN candidate from four read-only DB endpoints.

The JSON is public forever after a Git push. This tool never pushes. A consumer
must still check the current Book policy authority before serving an ISBN; the
static file is metadata, never an authorization or withdrawal decision.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Protocol


HOSTS = ("clickhouse-s1-r1", "clickhouse-s1-r2", "clickhouse-s2-r1", "clickhouse-s2-r2")
ENDPOINT_PORTS = dict(zip(HOSTS, (50005, 50006, 50007, 50008)))
TUNNEL_PORTS = dict(zip(HOSTS, (18081, 18082, 18083, 18084)))
MAX_ROWS = 2000
MAX_POLICY_ROWS = 10000
FRESHNESS_MS = 46_800_000
UINT64_MASK = (1 << 64) - 1
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ISBN = re.compile(r"[0-9Xx-]{10,17}\Z")
# Two source rows preserve the original dual-ISBN raw key; the canonical ISBN
# remains separately validated and consumers must keep this key byte-exact.
RAW_ISBN = re.compile(r"[0-9Xx-]{10,17}(?: [0-9Xx-]{10,17})?\Z")
URL_SPAN = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]{1,20}(?:://|%3a%2f%2f)[^\s<>()\"']*|"
    r"\b(?:https?|ftp|file|data|javascript|mailto):[^\s<>()\"']+|"
    r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,24}\b|"
    r"\bwww\.[^\s<>()\"']+|"
    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::[0-9]+)?[/?][^\s<>()\"']*|"
    r"\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?[/?][^\s<>()\"']*)"
)
URL_LIKE = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]{1,20}(?:://|%3a%2f%2f)|"
    r"\b(?:https?|ftp|file|data|javascript|mailto):[^\s<>()\"']|"
    r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,24}\b|\bwww\.|"
    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::[0-9]+)?[/?]|"
    r"\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?[/?]|(?<!\w)//[^\s])"
)
# The app has a separate bootstrap restriction for these exact ISBNs. A CDN
# candidate omits them even if a stale snapshot flag says otherwise.
BOOTSTRAP_RESTRICTED = frozenset(("9788931457834", "8931457839", "9791127287672", "9791127287689"))
REVIEWED_IMAGE_HOSTS = frozenset(("shopping-phinf.pstatic.net", "search1.kakaocdn.net"))
KAKAO_INNER_PATH = re.compile(r"/lbook/image/[0-9]+\Z")
KAKAO_TIMESTAMP = re.compile(r"[0-9]+\Z")
ROW_FIELDS = frozenset((
    "isbn", "canonical_isbn", "title", "author", "publisher", "pubdate", "image", "description",
    "source_updated_at", "source_collected_at", "search_mode", "search_query",
    "relevance_score", "relevance_reason", "source_kind", "language_code",
    "active", "list_visible", "detail_visible", "sitemap_visible", "visibility_revision",
    "row_fingerprint",
))
CERT_FIELDS = frozenset((
    "endpoint", "snapshot_uuid", "content_sha256", "policy_authority_revision", "visibility_revision",
    "cache_token", "activation_fence", "source_refresh_ms", "row_count",
    "identity_count", "fingerprint_sum", "fingerprint_xor", "server_now_ms",
))
POLICY_FIELDS = frozenset(("canonical_isbn", "discoverable", "indexable", "detail_accessible"))


class ExportError(RuntimeError):
    """A bounded public error category; server responses and row data stay private."""


def _positive_int(value: object, label: str) -> int:
    try:
        result = int(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else -1
    except ValueError:
        result = -1
    if result < 0:
        raise ExportError(label + " is invalid")
    return result


def _bit(value: object, label: str) -> int:
    result = _positive_int(value, label)
    if result not in (0, 1):
        raise ExportError(label + " differs")
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Reader(Protocol):
    def certificate(self, host: str) -> dict[str, object]: ...
    def snapshot(self, host: str, cert: dict[str, object]) -> list[dict[str, object]]: ...
    def policies(self, host: str) -> list[dict[str, object]]: ...


class ClickHouseReader:
    """Only fixed SELECT statements are sent; credentials never enter output."""

    def __init__(self, config_path: Path):
        if not config_path.is_absolute() or config_path.is_symlink():
            raise ExportError("private source config path differs")
        try:
            info = config_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ExportError("private source config ownership or mode differs")
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExportError("private source config is unavailable") from exc
        if (not isinstance(data, dict) or set(data) != {"schema", "endpoints"}
                or data["schema"] != "webr.book.cdn.source.v1"
                or not isinstance(data["endpoints"], dict)
                or set(data["endpoints"]) != set(HOSTS)):
            raise ExportError("private source config shape differs")
        self.endpoints: dict[str, tuple[str, str]] = {}
        for host in HOSTS:
            item = data["endpoints"][host]
            if not isinstance(item, dict) or set(item) != {"url", "user", "password"}:
                raise ExportError("private endpoint config shape differs")
            url, user, password = item["url"], item["user"], item["password"]
            if not all(isinstance(part, str) and part for part in (url, user, password)):
                raise ExportError("private endpoint config is incomplete")
            try:
                parsed = urllib.parse.urlsplit(url)
                endpoint_address = (parsed.hostname, parsed.port)
                allowed_addresses = (("192.168.0.15", ENDPOINT_PORTS[host]),
                                     ("127.0.0.1", TUNNEL_PORTS[host]))
                valid_url = (parsed.scheme == "http" and endpoint_address in allowed_addresses
                    and parsed.username is None and parsed.password is None
                    and not parsed.query and not parsed.fragment
                    and parsed.path in ("", "/"))
            except ValueError:
                valid_url = False
            if not valid_url or len(password) > 4096:
                raise ExportError("private endpoint URL differs")
            self.endpoints[host] = (url.rstrip("/") + "/", base64.b64encode((user + ":" + password).encode()).decode())

    def _rows(self, host: str, sql: str, limit_bytes: int) -> list[dict[str, object]]:
        if not re.match(r"\s*SELECT\b", sql, re.I) or ";" in sql:
            raise ExportError("unreviewed source query")
        endpoint, token = self.endpoints[host]
        params = urllib.parse.urlencode({
            "wait_end_of_query": "1", "skip_unavailable_shards": "0",
            "max_execution_time": "20", "max_threads": "2", "result_overflow_mode": "throw",
        })
        request = urllib.request.Request(
            endpoint + "?" + params, data=(sql + " FORMAT JSONEachRow").encode(),
            headers={"Authorization": "Basic " + token, "Content-Type": "text/plain; charset=utf-8"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(limit_bytes + 1)
                if len(raw) > limit_bytes or response.headers.get("X-ClickHouse-Exception-Code"):
                    raise ExportError("bounded Book source response differs")
            rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
        except (OSError, UnicodeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ExportError("bounded Book source query failed") from exc
        if not all(isinstance(row, dict) for row in rows):
            raise ExportError("bounded Book source rows differ")
        return rows

    def certificate(self, host: str) -> dict[str, object]:
        sql = """SELECT hostName() AS endpoint,
          toString(state.snapshot_uuid) AS snapshot_uuid,
          state.content_sha256 AS content_sha256,
          state.policy_authority_revision AS policy_authority_revision,
          state.visibility_revision AS visibility_revision,
          state.cache_token AS cache_token,
          state.activation_fence AS activation_fence,
          toUnixTimestamp64Milli(state.source_refresh_success_at) AS source_refresh_ms,
          complete.row_count AS row_count, complete.identity_count AS identity_count,
          toString(complete.fingerprint_sum) AS fingerprint_sum,
          toString(complete.fingerprint_xor) AS fingerprint_xor,
          toUnixTimestamp64Milli(now64(3,'Asia/Seoul')) AS server_now_ms
        FROM webr_book.v_book_serving_public_state AS state
        INNER JOIN webr_book.v_book_serving_generation_complete AS complete
          ON complete.snapshot_uuid=state.snapshot_uuid
          AND complete.content_sha256=state.content_sha256
          AND complete.policy_authority_revision=state.snapshot_policy_authority_revision
        WHERE state.policy_authority_revision=state.snapshot_policy_authority_revision
          AND complete.row_count>0 AND complete.row_count=complete.identity_count
          AND now64(3,'Asia/Seoul') BETWEEN state.source_refresh_success_at
              AND state.source_refresh_success_at + INTERVAL 46800 SECOND
        LIMIT 2"""
        rows = self._rows(host, sql, 16_384)
        if len(rows) != 1:
            raise ExportError("active complete Book certificate is unavailable")
        return rows[0]

    def snapshot(self, host: str, cert: dict[str, object]) -> list[dict[str, object]]:
        snapshot = cert["snapshot_uuid"]
        content = cert["content_sha256"]
        revision = cert["policy_authority_revision"]
        # All three values were strictly validated before interpolation.
        sql = f"""SELECT isbn,canonical_isbn,title,author,publisher,pubdate,image,description,
          formatDateTime(source_updated_at,'%Y-%m-%d %H:%i:%S','Asia/Seoul') AS source_updated_at,
          if(isNull(source_collected_at),'',formatDateTime(source_collected_at,'%Y-%m-%d %H:%i:%S','Asia/Seoul')) AS source_collected_at,
          search_mode,search_query,relevance_score,relevance_reason,source_kind,language_code,
          active,list_visible,detail_visible,sitemap_visible,visibility_revision,
          toString(row_fingerprint) AS row_fingerprint
        FROM webr_book.book_catalog_serving_snapshot_local
        PREWHERE snapshot_uuid=toUUID('{snapshot}')
          AND content_sha256='{content}' AND policy_authority_revision={revision}
        ORDER BY isbn ASC LIMIT {MAX_ROWS + 1}"""
        return self._rows(host, sql, 4_000_000)

    def policies(self, host: str) -> list[dict[str, object]]:
        sql = f"""SELECT canonical_isbn,
          min(toUInt8(active=1 AND discoverable=1)) AS discoverable,
          min(toUInt8(active=1 AND indexable=1)) AS indexable,
          min(toUInt8(active=1 AND detail_accessible=1)) AS detail_accessible
        FROM Data_Book_Service.v_book_visibility_current
        WHERE scope IN ('all','web-r')
          AND effective_at<=now64(3,'Asia/Seoul')
          AND (isNull(expires_at) OR expires_at>now64(3,'Asia/Seoul'))
        GROUP BY canonical_isbn ORDER BY canonical_isbn LIMIT {MAX_POLICY_ROWS + 1}"""
        return self._rows(host, sql, 2_000_000)


def _valid_cert(raw: dict[str, object]) -> dict[str, object]:
    if set(raw) != CERT_FIELDS:
        raise ExportError("Book certificate fields differ")
    cert = dict(raw)
    if not isinstance(cert["endpoint"], str) or cert["endpoint"] not in HOSTS:
        raise ExportError("Book certificate endpoint differs")
    try:
        snapshot = uuid.UUID(str(cert["snapshot_uuid"]))
    except ValueError as exc:
        raise ExportError("Book snapshot identity is invalid") from exc
    sha = str(cert["content_sha256"])
    revision = _positive_int(cert["policy_authority_revision"], "policy revision")
    fence = _positive_int(cert["activation_fence"], "activation fence")
    row_count = _positive_int(cert["row_count"], "Book row count")
    identity_count = _positive_int(cert["identity_count"], "Book identity count")
    refreshed = _positive_int(cert["source_refresh_ms"], "Book source refresh time")
    now = _positive_int(cert["server_now_ms"], "Book server time")
    fingerprint_sum = _positive_int(cert["fingerprint_sum"], "Book fingerprint sum")
    fingerprint_xor = _positive_int(cert["fingerprint_xor"], "Book fingerprint xor")
    if (snapshot.int == 0 or str(snapshot) != cert["snapshot_uuid"]
            or not SHA256.fullmatch(sha) or revision == 0 or fence == 0
            or not 1 <= row_count <= MAX_ROWS or identity_count != row_count
            or fingerprint_sum > UINT64_MASK or fingerprint_xor > UINT64_MASK
            or cert["visibility_revision"] != str(revision)
            or cert["cache_token"] != f"{sha}:{revision}:{fence}"
            or not refreshed <= now < refreshed + FRESHNESS_MS):
        raise ExportError("active complete Book certificate differs")
    cert["policy_authority_revision"] = revision
    cert["activation_fence"] = fence
    cert["row_count"] = row_count
    cert["identity_count"] = identity_count
    cert["source_refresh_ms"] = refreshed
    cert["server_now_ms"] = now
    cert["fingerprint_sum"] = fingerprint_sum
    cert["fingerprint_xor"] = fingerprint_xor
    return cert


def _safe_text(value: object, label: str, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value or URL_LIKE.search(value):
        raise ExportError("public Book " + label + " is invalid or contains a URL")
    cleaned = value.strip()
    if required and not cleaned:
        raise ExportError("public Book " + label + " is missing")
    if any(ord(char) < 32 and char not in "\t\n" for char in cleaned):
        raise ExportError("public Book " + label + " contains a control character")
    return cleaned


class _PlainText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.suppressed = 0

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self.suppressed += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self.suppressed:
            self.suppressed -= 1

    def handle_data(self, data: str) -> None:
        if not self.suppressed:
            self.parts.append(data)


def _description_without_urls(value: object) -> str:
    if not isinstance(value, str) or len(value) > 10000 or "\x00" in value:
        raise ExportError("public Book description differs")
    markup = value
    for _ in range(5):
        decoded = html.unescape(markup)
        if decoded == markup:
            break
        markup = decoded
    if html.unescape(markup) != markup:
        raise ExportError("public Book description encoding differs")
    plain = _PlainText()
    plain.feed(markup)
    plain.close()
    cleaned = " ".join(plain.parts).replace("<", " ").replace(">", " ")
    cleaned = URL_SPAN.sub(" ", cleaned)
    cleaned = " ".join(cleaned.split())
    return _safe_text(cleaned, "description", 10000)


def safe_image_url(value: object, allowed_hosts: frozenset[str]) -> str:
    """An image is opt-in only after its exact public host is reviewed."""
    if not isinstance(value, str) or len(value) > 2048:
        raise ExportError("public Book image URL differs")
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or ""
        safe_base = (parsed.scheme == "https" and host in allowed_hosts
            and parsed.username is None and parsed.password is None
            and parsed.port in (None, 443) and not parsed.fragment
            and parsed.path.startswith("/") and parsed.path != "/"
            and "\\" not in value and not any(ord(c) < 33 for c in value))
    except ValueError:
        safe_base = False
        host = ""
    if not safe_base:
        raise ExportError("public Book image URL is not on a reviewed HTTPS host")
    if host == "shopping-phinf.pstatic.net":
        if parsed.query:
            raise ExportError("public Book image URL query differs")
    elif host == "search1.kakaocdn.net":
        if parsed.path != "/thumb/R120x174.q85/":
            raise ExportError("public Book Kakao image path differs")
        try:
            items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            if len(items) != 1 or items[0][0] != "fname":
                raise ValueError("Kakao image query shape")
            inner = urllib.parse.urlsplit(items[0][1])
            inner_items = urllib.parse.parse_qsl(inner.query, keep_blank_values=True, strict_parsing=True)
            valid_inner = (inner.scheme == "http" and inner.hostname == "t1.daumcdn.net"
                and inner.username is None and inner.password is None and inner.port is None
                and KAKAO_INNER_PATH.fullmatch(inner.path) is not None
                and len(inner_items) == 1 and inner_items[0][0] == "timestamp"
                and KAKAO_TIMESTAMP.fullmatch(inner_items[0][1]) is not None
                and not inner.fragment)
        except ValueError:
            valid_inner = False
        if not valid_inner:
            raise ExportError("public Book Kakao image query differs")
    return value


def _policies(raw: list[dict[str, object]]) -> dict[str, tuple[int, int, int]]:
    if len(raw) > MAX_POLICY_ROWS:
        raise ExportError("Book visibility policy result exceeds its bound")
    result: dict[str, tuple[int, int, int]] = {}
    for row in raw:
        if set(row) != POLICY_FIELDS or not isinstance(row["canonical_isbn"], str):
            raise ExportError("Book visibility policy fields differ")
        isbn = row["canonical_isbn"]
        if not ISBN.fullmatch(isbn) or isbn in result:
            raise ExportError("Book visibility policy identity differs")
        result[isbn] = (
            _bit(row["discoverable"], "policy discoverability"),
            _bit(row["indexable"], "policy indexability"),
            _bit(row["detail_accessible"], "policy detail access"),
        )
    return result


def _snapshot(raw: list[dict[str, object]], cert: dict[str, object]) -> list[dict[str, object]]:
    if len(raw) != cert["row_count"]:
        raise ExportError("Book snapshot count differs from complete certificate")
    seen: set[str] = set()
    fingerprint_sum = fingerprint_xor = 0
    rows: list[dict[str, object]] = []
    for original in raw:
        if set(original) != ROW_FIELDS:
            raise ExportError("Book snapshot fields differ")
        row = dict(original)
        isbn, canonical = row["isbn"], row["canonical_isbn"]
        if (not isinstance(isbn, str) or not RAW_ISBN.fullmatch(isbn)
                or not isinstance(canonical, str) or not ISBN.fullmatch(canonical)
                or isbn in seen or row["visibility_revision"] != cert["visibility_revision"]):
            raise ExportError("Book snapshot identity or revision differs")
        seen.add(isbn)
        for flag in ("active", "list_visible", "detail_visible", "sitemap_visible"):
            row[flag] = _bit(row[flag], "snapshot " + flag)
        row["relevance_score"] = _positive_int(row["relevance_score"], "Book relevance score")
        if row["relevance_score"] > 65535:
            raise ExportError("Book relevance score exceeds UInt16")
        fingerprint = _positive_int(row["row_fingerprint"], "Book row fingerprint")
        if fingerprint > UINT64_MASK:
            raise ExportError("Book row fingerprint exceeds UInt64")
        fingerprint_sum = (fingerprint_sum + fingerprint) & UINT64_MASK
        fingerprint_xor ^= fingerprint
        row["row_fingerprint"] = fingerprint
        rows.append(row)
    if (len(seen) != cert["identity_count"] or fingerprint_sum != cert["fingerprint_sum"]
            or fingerprint_xor != cert["fingerprint_xor"]):
        raise ExportError("Book snapshot fingerprint differs from complete certificate")
    rows.sort(key=lambda item: str(item["isbn"]))
    return rows


def build_candidate(reader: Reader, *, image_hosts: frozenset[str] = frozenset()) -> tuple[bytes, dict[str, object]]:
    """Verify the active generation on all four nodes and return only public bytes."""
    certs = [_valid_cert(reader.certificate(host)) for host in HOSTS]
    if [cert["endpoint"] for cert in certs] != list(HOSTS):
        raise ExportError("Book source endpoints are misrouted")
    expected = {key: value for key, value in certs[0].items() if key not in ("server_now_ms", "endpoint")}
    if any({key: value for key, value in cert.items() if key not in ("server_now_ms", "endpoint")} != expected for cert in certs[1:]):
        raise ExportError("Book active complete certificate differs across four nodes")
    snapshots = [_snapshot(reader.snapshot(host, certs[0]), certs[0]) for host in HOSTS]
    if any(rows != snapshots[0] for rows in snapshots[1:]):
        raise ExportError("Book snapshot rows differ across four nodes")
    policy_maps = [_policies(reader.policies(host)) for host in HOSTS]
    if any(mapping != policy_maps[0] for mapping in policy_maps[1:]):
        raise ExportError("Book visibility policy differs across four nodes")
    books: list[dict[str, object]] = []
    for row in snapshots[0]:
        if (row["active"] != 1 or row["list_visible"] != 1
                or row["detail_visible"] != 1 or row["sitemap_visible"] != 1
                or row["canonical_isbn"] in BOOTSTRAP_RESTRICTED):
            continue
        allowed = policy_maps[0].get(str(row["canonical_isbn"]), (1, 1, 1))
        if allowed != (1, 1, 1):
            continue
        item: dict[str, object] = {
            "isbn": row["isbn"],
            "canonical_isbn": row["canonical_isbn"],
            "title": _safe_text(row["title"], "title", 512, required=True),
            "author": _safe_text(row["author"], "author", 1024),
            "publisher": _safe_text(row["publisher"], "publisher", 512),
            "pubdate": _safe_text(row["pubdate"], "publication date", 32),
            "source_updated_at": _safe_text(row["source_updated_at"], "source update time", 32, required=True),
            "source_collected_at": _safe_text(row["source_collected_at"], "source collection time", 32),
            "search_mode": _safe_text(row["search_mode"], "search mode", 64),
            "search_query": _safe_text(row["search_query"], "search query", 1024),
            "relevance_score": row["relevance_score"],
            "source_kind": _safe_text(row["source_kind"], "source kind", 64, required=True),
            "language_code": _safe_text(row["language_code"], "language code", 32, required=True),
            "list_visible": row["list_visible"],
            "detail_visible": row["detail_visible"],
            "sitemap_visible": row["sitemap_visible"],
        }
        description = _description_without_urls(row["description"])
        if description:
            item["description"] = description
        relevance_reason = _description_without_urls(row["relevance_reason"])
        if relevance_reason:
            item["relevance_reason"] = relevance_reason
        if image_hosts:
            image = safe_image_url(row["image"], image_hosts)
            if image:
                item["image"] = image
        books.append(item)
    if not books:
        raise ExportError("no currently public Book rows remain")
    # A policy or generation change during the bounded export closes admission.
    after_certs = [_valid_cert(reader.certificate(host)) for host in HOSTS]
    if ([cert["endpoint"] for cert in after_certs] != list(HOSTS)
            or any({k: v for k, v in cert.items() if k not in ("server_now_ms", "endpoint")} != expected
                   for cert in after_certs)):
        raise ExportError("Book certificate changed during CDN export")
    after_policies = [_policies(reader.policies(host)) for host in HOSTS]
    if any(mapping != policy_maps[0] for mapping in after_policies):
        raise ExportError("Book visibility policy changed during CDN export")
    data = {
        "schema": "webr.book.public-metadata.v1",
        "snapshot_uuid": certs[0]["snapshot_uuid"],
        "content_sha256": certs[0]["content_sha256"],
        "policy_authority_revision": certs[0]["policy_authority_revision"],
        "source_refresh_ms": certs[0]["source_refresh_ms"],
        "expires_at_ms": certs[0]["source_refresh_ms"] + FRESHNESS_MS,
        "requires_current_policy_check": True,
        "books": books,
    }
    payload = _canonical_json(data)
    manifest: dict[str, object] = {
        "schema": "webr.book.public-metadata-manifest.v1",
        "generation": "books/generations/" + _sha256(payload) + ".json",
        "sha256": _sha256(payload),
        "count": len(books),
        "snapshot_uuid": certs[0]["snapshot_uuid"],
        "policy_authority_revision": certs[0]["policy_authority_revision"],
        "expires_at_ms": certs[0]["source_refresh_ms"] + FRESHNESS_MS,
        "requires_current_policy_check": True,
    }
    return payload, manifest


def _plain_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ExportError("CDN output directory differs")


def store_candidate(repo_root: Path, payload: bytes, manifest: dict[str, object]) -> None:
    """Create immutable bytes, then replace only the local pointer atomically."""
    _plain_directory(repo_root)
    root = repo_root.resolve()
    _plain_directory(root)
    books = root / "books"
    generations = books / "generations"
    for directory in (books, generations):
        if not directory.exists():
            directory.mkdir(mode=0o755)
        _plain_directory(directory)
    digest = _sha256(payload)
    if manifest.get("sha256") != digest or manifest.get("generation") != f"books/generations/{digest}.json":
        raise ExportError("CDN generation pointer differs from immutable bytes")
    previous = books / "current.json"
    if previous.exists() or previous.is_symlink():
        if previous.is_symlink() or not previous.is_file():
            raise ExportError("CDN current pointer is not a regular file")
        try:
            old = json.loads(previous.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExportError("CDN current pointer is unreadable") from exc
        if (old.get("schema") != manifest["schema"]
                or _positive_int(old.get("policy_authority_revision"), "old policy revision")
                   > manifest["policy_authority_revision"]
                or _positive_int(old.get("expires_at_ms"), "old expiry") > manifest["expires_at_ms"]):
            raise ExportError("CDN pointer would roll back policy or source freshness")
    generation = generations / (digest + ".json")
    if generation.exists() or generation.is_symlink():
        if generation.is_symlink() or not generation.is_file() or generation.read_bytes() != payload:
            raise ExportError("existing CDN generation bytes differ")
    else:
        # A partial generation must never be visible under a content hash.
        descriptor, temporary = tempfile.mkstemp(prefix=".generation-", dir=generations)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
            try:
                os.link(temporary, generation, follow_symlinks=False)
            except FileExistsError:
                if generation.is_symlink() or not generation.is_file() or generation.read_bytes() != payload:
                    raise ExportError("existing CDN generation bytes differ")
        finally:
            os.unlink(temporary)
    tmp_descriptor, tmp_name = tempfile.mkstemp(prefix=".current-", dir=books)
    try:
        with os.fdopen(tmp_descriptor, "wb") as stream:
            stream.write(_canonical_json(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, previous)
        for directory in (generations, books):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--write-local-candidate", action="store_true")
    parser.add_argument("--source-config", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    try:
        payload, manifest = build_candidate(ClickHouseReader(args.source_config), image_hosts=REVIEWED_IMAGE_HOSTS)
        if args.write_local_candidate:
            store_candidate(args.repo_root, payload, manifest)
        print(json.dumps({
            "status": "local_candidate_written" if args.write_local_candidate else "preflight_ok",
            "database_writes": False, "repository_writes": bool(args.write_local_candidate),
            "count": manifest["count"], "sha256": manifest["sha256"],
            "requires_current_policy_check": True,
        }, sort_keys=True))
        return 0
    except ExportError as exc:
        print(json.dumps({"status": "blocked", "category": str(exc)[:160], "database_writes": False},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
