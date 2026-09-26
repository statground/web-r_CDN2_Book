"""Public candidate must remain bounded, policy-gated and free of Book links."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import book_metadata_export as export


PSTATIC_IMAGE = "https://shopping-phinf.pstatic.net/main_1234567/12345678.jpg"
KAKAO_INNER = "http://t1.daumcdn.net/lbook/image/1234567?timestamp=12345"
KAKAO_IMAGE = "https://search1.kakaocdn.net/thumb/R120x174.q85/?fname=" + urllib.parse.quote(KAKAO_INNER, safe="")


def row(isbn, fingerprint, *, image=PSTATIC_IMAGE, canonical=None, **flags):
    data = {
        "isbn": isbn, "canonical_isbn": canonical or isbn,
        "title": "통계학 실습", "author": "홍길동", "publisher": "예제출판",
        "pubdate": "20260926", "image": image,
        "description": "기초 설명 <b>강조</b>과 https://seller.example/book/1 구매처",
        "source_updated_at": "2026-09-26 16:33:23", "source_collected_at": "2026-09-26 15:00:00",
        "search_mode": "keyword", "search_query": "R 통계", "relevance_score": 42,
        "relevance_reason": "R 학습 추천", "source_kind": "title", "language_code": "ko",
        "active": 1, "list_visible": 1, "detail_visible": 1,
        "sitemap_visible": 1, "visibility_revision": "7",
        "row_fingerprint": str(fingerprint),
    }
    data.update(flags)
    return data


class FakeReader:
    def __init__(self, rows=None, policies=None):
        self.rows = rows or [
            row("9781234567890", 17),
            row("9781234567891", 31, image=KAKAO_IMAGE),
            row("9781234567892", 41),
        ]
        self.policy_rows = policies or [
            {"canonical_isbn": "9781234567892", "discoverable": 0,
             "indexable": 0, "detail_accessible": 0},
        ]
        self.certificate_calls = 0
        self.revision_after_first_round = None
        self.route_override = None
        self.node_rows = None
        self.policy_calls = 0
        self.policy_after_first_round = None

    def certificate(self, host):
        self.certificate_calls += 1
        revision = (self.revision_after_first_round
                    if self.revision_after_first_round and self.certificate_calls > 4 else 7)
        return {
            "endpoint": self.route_override or host,
            "snapshot_uuid": "70fb166c-ec80-53c2-a7c5-cfd4cda94e65",
            "content_sha256": "a" * 64,
            "policy_authority_revision": str(revision),
            "visibility_revision": str(revision),
            "cache_token": "a" * 64 + f":{revision}:8",
            "activation_fence": "8", "source_refresh_ms": "1000",
            "row_count": len(self.rows), "identity_count": len(self.rows),
            "fingerprint_sum": str(sum(int(item["row_fingerprint"]) for item in self.rows)),
            "fingerprint_xor": str(_xor(int(item["row_fingerprint"]) for item in self.rows)),
            "server_now_ms": "1001",
        }

    def snapshot(self, host, _cert):
        if self.node_rows and host in self.node_rows:
            return copy.deepcopy(self.node_rows[host])
        return copy.deepcopy(self.rows)

    def policies(self, _host):
        self.policy_calls += 1
        if self.policy_after_first_round is not None and self.policy_calls > 4:
            return copy.deepcopy(self.policy_after_first_round)
        return copy.deepcopy(self.policy_rows)


def _xor(items):
    value = 0
    for item in items:
        value ^= item
    return value


class BookMetadataExportTests(unittest.TestCase):
    def test_public_candidate_includes_reviewed_cover_images_but_never_book_links(self):
        payload, manifest = export.build_candidate(
            FakeReader(), image_hosts=export.REVIEWED_IMAGE_HOSTS)
        data = json.loads(payload)
        self.assertEqual([book["isbn"] for book in data["books"]],
                         ["9781234567890", "9781234567891"])
        self.assertEqual([book["image"] for book in data["books"]],
                         [PSTATIC_IMAGE, KAKAO_IMAGE])
        self.assertNotIn('"link"', payload.decode())
        self.assertEqual(data["books"][0]["description"], "기초 설명 강조 과 구매처")
        self.assertEqual(data["books"][0]["search_query"], "R 통계")
        self.assertEqual(data["books"][0]["source_kind"], "title")
        self.assertEqual(data["books"][0]["relevance_score"], 42)
        self.assertNotIn("seller.example", payload.decode())
        self.assertNotIn("9781234567892", payload.decode())
        self.assertEqual(manifest["sha256"], export._sha256(payload))
        self.assertTrue(data["requires_current_policy_check"])

    def test_endpoint_misroute_and_mutated_policy_revision_fail_closed(self):
        routed = FakeReader()
        routed.route_override = export.HOSTS[0]
        with self.assertRaisesRegex(export.ExportError, "misrouted"):
            export.build_candidate(routed)
        changed = FakeReader()
        changed.revision_after_first_round = 8
        with self.assertRaisesRegex(export.ExportError, "changed during"):
            export.build_candidate(changed)
        withdrawn = FakeReader()
        withdrawn.policy_after_first_round = [
            {"canonical_isbn": "9781234567890", "discoverable": 0,
             "indexable": 0, "detail_accessible": 0},
        ]
        with self.assertRaisesRegex(export.ExportError, "policy changed during"):
            export.build_candidate(withdrawn)

    def test_row_disagreement_and_wrong_certificate_fingerprint_fail_closed(self):
        reader = FakeReader()
        altered = copy.deepcopy(reader.rows)
        altered[0]["title"] = "다른 책"
        reader.node_rows = {export.HOSTS[3]: altered}
        with self.assertRaisesRegex(export.ExportError, "rows differ"):
            export.build_candidate(reader)
        invalid = FakeReader()
        invalid.rows[0]["row_fingerprint"] = str(1 << 64)
        with self.assertRaisesRegex(export.ExportError, "certificate differs"):
            export.build_candidate(invalid)

    def test_public_text_rejects_embedded_url_and_bootstrap_restrictions(self):
        reader = FakeReader(rows=[row("9781234567890", 17, title="Go to https://example.com/book")])
        with self.assertRaisesRegex(export.ExportError, "markup or a URL"):
            export.build_candidate(reader)
        encoded = FakeReader(rows=[row("9781234567890", 17,
                                       title="Go to https&#58;//example.com/book")])
        with self.assertRaisesRegex(export.ExportError, "markup or a URL"):
            export.build_candidate(encoded)
        markup = FakeReader(rows=[row("9781234567890", 17,
                                      title="R &lt;script&gt;alert(1)&lt;/script&gt;")])
        with self.assertRaisesRegex(export.ExportError, "markup or a URL"):
            export.build_candidate(markup)
        bootstrap = FakeReader(rows=[row("9788931457834", 17), row("9781234567890", 19)])
        payload, _ = export.build_candidate(bootstrap)
        self.assertNotIn("9788931457834", payload.decode())

    def test_description_decodes_html_then_removes_url_and_rechecks(self):
        description = ('책 소개 &lt;b&gt;중요&lt;/b&gt; '
                       '&lt;a href="https://hidden.example/x"&gt;읽기&lt;/a&gt; '
                       'www.publisher.example and http://seller.example/book')
        cleaned = export._description_without_urls(description)
        self.assertIn("책 소개", cleaned)
        self.assertIn("읽기", cleaned)
        self.assertNotIn("hidden.example", cleaned)
        self.assertNotIn("publisher.example", cleaned)
        self.assertNotIn("seller.example", cleaned)
        self.assertNotIn("<", cleaned)

    def test_cover_host_and_nested_query_are_exact(self):
        for bad in (
            "http://shopping-phinf.pstatic.net/a.jpg",
            "https://shopping-phinf.pstatic.net/a.jpg?redirect=https://elsewhere.example/x",
            "https://search1.kakaocdn.net/a?fname=" + urllib.parse.quote(
                "https://evil.example/book/1?timestamp=1", safe=""),
            "https://search1.kakaocdn.net/a?fname=" + urllib.parse.quote(
                "http://t1.daumcdn.net/lbook/image/123?timestamp=1&redirect=evil", safe=""),
            KAKAO_IMAGE + "&unexpected=1",
            "https://search1.kakaocdn.net/a?fname=http://t1.daumcdn.net/lbook/image/1?timestamp=1#fragment",
        ):
            with self.subTest(bad=bad), self.assertRaises(export.ExportError):
                export.safe_image_url(bad, export.REVIEWED_IMAGE_HOSTS)
        self.assertEqual(export.safe_image_url(KAKAO_IMAGE, export.REVIEWED_IMAGE_HOSTS), KAKAO_IMAGE)

    def test_local_generation_is_immutable_and_pointer_rejects_rollback(self):
        payload, manifest = export.build_candidate(FakeReader())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            export.store_candidate(root, payload, manifest)
            generation = root / manifest["generation"]
            self.assertEqual(generation.read_bytes(), payload)
            self.assertEqual(json.loads((root / "books/current.json").read_text()), manifest)
            export.store_candidate(root, payload, manifest)
            generation.write_bytes(b"tampered")
            with self.assertRaisesRegex(export.ExportError, "generation bytes differ"):
                export.store_candidate(root, payload, manifest)
            generation.write_bytes(payload)
            older = dict(manifest)
            older["policy_authority_revision"] = 6
            with self.assertRaisesRegex(export.ExportError, "roll back"):
                export.store_candidate(root, payload, older)

    def test_private_transport_requires_exact_four_tunnel_ports(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "source.json"
            values = {"schema": "webr.book.cdn.source.v1", "endpoints": {
                host: {"url": f"http://127.0.0.1:{export.TUNNEL_PORTS[host]}/",
                       "user": "reader", "password": "local-test-only"}
                for host in export.HOSTS}}
            config.write_text(json.dumps(values))
            os.chmod(config, 0o600)
            export.ClickHouseReader(config)
            values["endpoints"][export.HOSTS[1]]["url"] = "http://127.0.0.1:18081/"
            config.write_text(json.dumps(values))
            with self.assertRaisesRegex(export.ExportError, "endpoint URL differs"):
                export.ClickHouseReader(config)


if __name__ == "__main__":
    unittest.main()
