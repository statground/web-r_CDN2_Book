"""Guard the eight old carousel identities and public metadata integrity."""

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import curated_book_export as curated
from book_metadata_export import ExportError, URL_LIKE


ROOT = Path(__file__).resolve().parents[1]


class CuratedBookTests(unittest.TestCase):
    def test_artifact_preserves_old_carousel_with_only_pinned_cover_urls(self):
        raw = (ROOT / curated.ARTIFACT).read_bytes()
        manifest = json.loads((ROOT / curated.MANIFEST).read_bytes())
        payload = json.loads(raw)
        self.assertEqual(manifest, {
            "schema": "webr.book.curated-metadata-manifest.v1",
            "artifact": curated.ARTIFACT.as_posix(),
            "count": 8,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "cover_commit_sha": curated.COVER_COMMIT,
            "requires_current_policy_check": True,
        })
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["service"], "webr")
        self.assertIs(payload["requires_current_policy_check"], True)
        self.assertEqual(tuple(item["data"]["sub"] for item in payload["items"]), curated.DISPLAY_ORDER)
        self.assertEqual(len(payload["items"]), 8)
        for item in payload["items"]:
            data = item["data"]
            sub = data["sub"]
            self.assertEqual((data["book_uuid"], data["isbn"], data["title"]), curated.BOOK_IDENTITIES[sub])
            self.assertEqual(data["cover_url"], curated.COVER_ROOT + f"book_{sub}.jpg")
            encoded = curated._json_bytes(data)
            self.assertIn(encoded, raw)
            self.assertEqual(item["metadata_sha256"], hashlib.sha256(encoded).hexdigest())
            for field in ("title", "publisher", "introduction", "contents", "publisher_review", "size"):
                self.assertNotRegex(data[field], URL_LIKE)
                self.assertNotIn("<", data[field])
                self.assertNotIn(">", data[field])
            self.assertEqual(set(data), {
                "book_uuid", "sub", "isbn", "title", "cover_url", "publisher", "published_at",
                "introduction", "contents", "publisher_review", "page_cnt", "size",
            })

    def test_source_identity_change_fails_and_outbound_info_url_is_removed(self):
        books = []
        info = []
        for sub, (book_uuid, isbn, title) in curated.BOOK_IDENTITIES.items():
            books.append({
                "book_uuid": book_uuid, "sub": sub, "title": title,
                "publisher": "출판사", "published_at": "2020-01-01",
                "cover_url": curated.OLD_COVER_ROOT + f"book_{sub}.jpg",
                "isbn": isbn, "page_cnt": 100, "size": "",
            })
            info.append({
                "book_uuid": book_uuid,
                "introduction": "설명 <a href='https://shop.example/book'>구매</a>",
                "contents": "목차", "publisher_review": "",
                "info_uuid": book_uuid, "updated_at": "",
            })
        raw, _ = curated.build_artifact(books, info)
        self.assertNotIn(b"shop.example", raw)
        self.assertEqual(len(json.loads(raw)["items"]), 8)
        books[0]["title"] = "다른 책"
        with self.assertRaisesRegex(ExportError, "identity differs"):
            curated.build_artifact(books, info)
        books[0]["title"] = curated.BOOK_IDENTITIES["001"][2]
        books[0]["cover_url"] = "https://shop.example/book.jpg"
        with self.assertRaisesRegex(ExportError, "source cover differs"):
            curated.build_artifact(books, info)

    def test_description_export_removes_nested_markup_and_encoded_links(self):
        source = (
            "&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;"
            "<a href='https://store.example/book'>책 소개</a> "
            "&lt;img src=x onerror=alert(1)&gt; "
            "javascript:alert(1) 정상 문장"
        )
        cleaned = curated._description_without_urls(source)
        self.assertIn("책 소개", cleaned)
        self.assertIn("정상 문장", cleaned)
        self.assertNotIn("script", cleaned)
        self.assertNotIn("onerror", cleaned)
        self.assertNotIn("alert", cleaned)
        self.assertNotRegex(cleaned, URL_LIKE)
        self.assertNotIn("<", cleaned)
        self.assertNotIn(">", cleaned)


if __name__ == "__main__":
    unittest.main()
