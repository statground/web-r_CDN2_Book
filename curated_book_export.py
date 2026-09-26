"""Build the eight reviewed Web-R featured-book records from private JSONL input.

The output contains metadata and pinned cover images only. It does not grant
visibility: consumers must check current per-book publication authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid

from book_metadata_export import ExportError, URL_LIKE, _description_without_urls, _safe_text


ARTIFACT = Path("curated/webr-featured-books.v1.json")
MANIFEST = Path("curated/webr-featured-books.v1.manifest.json")
COVER_COMMIT = "3a26bbf452f0bd4a0c2af9012a974d6536f90a11"
COVER_ROOT = f"https://cdn.jsdelivr.net/gh/statground/web-r_CDN2@{COVER_COMMIT}/images/book/"
OLD_COVER_ROOT = "https://cdn.jsdelivr.net/gh/statground/web-r_CDN/images/book/"
DISPLAY_ORDER = ("008", "004", "003", "006", "007", "005", "001", "002")
BOOK_IDENTITIES = {
    "001": ("35a965ac-ff31-438e-9d60-3cdc0868acb3", "9788955661798", "의학논문 작성을 위한 R통계와 그래프"),
    "002": ("9e13eb99-605a-4e06-8f16-261fb86569f8", "9788999719394", "R을 이용한 조건부과정분석"),
    "003": ("8dc1bf4b-0187-4233-829b-c12e3b4e15e4", "9788955661859", "웹에서 클릭만으로 하는 R통계분석"),
    "004": ("bf95f0ea-5cd4-45bf-959c-a56d66889567", "9783319530185", "Learning ggplot2 Using Shiny App"),
    "005": ("6b76d358-6b56-4a65-8de3-e27cf0df2254", "", "일반화가법모형 소개"),
    "006": ("f4bf3a41-4d82-42d6-a928-8a24c1076759", "", "밑바닥부터 시작하는 ROC 커브 분석"),
    "007": ("9128b66f-3156-4e95-833e-d4086952b149", "", "웹R을 이용한 통계분석"),
    "008": ("cc3a176e-8f57-4245-ad4c-767582c46e41", "9788955662948", "의료인을 위한 R 생존분석"),
}
BOOK_FIELDS = frozenset(("book_uuid", "sub", "title", "publisher", "published_at", "cover_url", "isbn", "page_cnt", "size"))
INFO_FIELDS = frozenset(("book_uuid", "introduction", "contents", "publisher_review", "info_uuid", "updated_at"))
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise ExportError("curated Book source is unavailable")
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExportError("curated Book source is invalid") from exc
    if len(rows) != 8 or not all(isinstance(row, dict) for row in rows):
        raise ExportError("curated Book source count differs")
    return rows


def build_artifact(books: list[dict[str, object]], info: list[dict[str, object]]) -> tuple[bytes, bytes]:
    if len(books) != 8 or len(info) != 8:
        raise ExportError("curated Book source count differs")
    by_sub: dict[str, dict[str, object]] = {}
    for row in books:
        if set(row) != BOOK_FIELDS:
            raise ExportError("curated Book source fields differ")
        sub = row["sub"]
        if not isinstance(sub, str) or sub not in BOOK_IDENTITIES or sub in by_sub:
            raise ExportError("curated Book sub differs")
        book_uuid, isbn, title = BOOK_IDENTITIES[sub]
        if (row["book_uuid"], row["isbn"], row["title"]) != (book_uuid, isbn, title):
            raise ExportError("curated Book identity differs")
        if row["cover_url"] != OLD_COVER_ROOT + f"book_{sub}.jpg":
            raise ExportError("curated Book source cover differs")
        by_sub[sub] = row
    if set(by_sub) != set(BOOK_IDENTITIES):
        raise ExportError("curated Book identities are incomplete")

    by_uuid: dict[str, dict[str, object]] = {}
    for row in info:
        if set(row) != INFO_FIELDS:
            raise ExportError("curated Book detail fields differ")
        book_uuid = row["book_uuid"]
        if not isinstance(book_uuid, str) or book_uuid in by_uuid:
            raise ExportError("curated Book detail identity differs")
        try:
            if str(uuid.UUID(book_uuid)) != book_uuid or str(uuid.UUID(str(row["info_uuid"]))) != row["info_uuid"]:
                raise ValueError("noncanonical UUID")
        except (ValueError, TypeError, AttributeError) as exc:
            raise ExportError("curated Book detail UUID differs") from exc
        by_uuid[book_uuid] = row
    if set(by_uuid) != {item[0] for item in BOOK_IDENTITIES.values()}:
        raise ExportError("curated Book details are incomplete")

    items = []
    for sub in DISPLAY_ORDER:
        book = by_sub[sub]
        detail = by_uuid[str(book["book_uuid"])]
        published_at = book["published_at"]
        page_cnt = book["page_cnt"]
        if (not isinstance(published_at, str) or not DATE.fullmatch(published_at)
                or not isinstance(page_cnt, int) or isinstance(page_cnt, bool) or not 0 <= page_cnt <= 100000):
            raise ExportError("curated Book date or page count differs")
        data = {
            "book_uuid": book["book_uuid"],
            "sub": sub,
            "isbn": book["isbn"],
            "title": _safe_text(book["title"], "title", 512, required=True),
            "cover_url": COVER_ROOT + f"book_{sub}.jpg",
            "publisher": _safe_text(book["publisher"], "publisher", 512),
            "published_at": published_at,
            "introduction": _description_without_urls(detail["introduction"]),
            "contents": _description_without_urls(detail["contents"]),
            "publisher_review": _description_without_urls(detail["publisher_review"]),
            "page_cnt": page_cnt,
            "size": _safe_text(book["size"], "size", 256),
        }
        if any(URL_LIKE.search(data[field]) for field in ("title", "publisher", "introduction", "contents", "publisher_review", "size")):
            raise ExportError("curated Book public text contains a URL")
        items.append({"metadata_sha256": _sha256(_json_bytes(data)), "data": data})

    payload = _json_bytes({"schema_version": 1, "service": "webr", "requires_current_policy_check": True, "items": items}) + b"\n"
    manifest = _json_bytes({
        "schema": "webr.book.curated-metadata-manifest.v1",
        "artifact": ARTIFACT.as_posix(),
        "count": 8,
        "sha256": _sha256(payload),
        "cover_commit_sha": COVER_COMMIT,
        "requires_current_policy_check": True,
    }) + b"\n"
    return payload, manifest


def _store_immutable(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise ExportError("curated Book immutable bytes differ")
        return
    path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--books-jsonl", type=Path, required=True)
    parser.add_argument("--info-jsonl", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        payload, manifest = build_artifact(_read_jsonl(args.books_jsonl), _read_jsonl(args.info_jsonl))
        _store_immutable(args.root / ARTIFACT, payload)
        _store_immutable(args.root / MANIFEST, manifest)
    except ExportError as exc:
        parser.exit(1, f"blocked: {exc}\n")
    print(json.dumps({"status": "candidate", "count": 8, "sha256": _sha256(payload)}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
