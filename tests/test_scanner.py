import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scanner


class FakeResp:
    def __init__(self, headers=None, text="", status_code=200, cookies=None):
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()
        self.status_code = status_code
        self.raw = None
        self.cookies = cookies or []


class FakeCookie:
    def __init__(self, name):
        self.name = name


def test_html_report_escapes_injected_markup():
    results = {
        "target": "http://localhost:8080",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "pages_crawled": 1,
        "forms_discovered": 0,
        "findings": [{
            "check": "reflected_xss",
            "severity": "high",
            "url": "http://localhost/?q=<script>alert(1)</script>",
            "title": "<script>alert(1)</script>",
            "detail": "<img src=x onerror=alert(2)>",
        }],
    }
    with tempfile.TemporaryDirectory() as d:
        path = scanner.write_html_report(results, os.path.join(d, "r"))
        html = open(path).read()
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(2)>" not in html
    assert "&lt;script&gt;" in html


def test_json_report_roundtrip():
    results = {"target": "t", "scanned_at": "x", "pages_crawled": 0,
               "forms_discovered": 0, "findings": []}
    with tempfile.TemporaryDirectory() as d:
        path = scanner.write_json_report(results, os.path.join(d, "r"))
        assert json.load(open(path))["target"] == "t"


def test_version_tuple_parses_and_guards():
    assert scanner._version_tuple("3.4.1") == (3, 4, 1)
    assert scanner._version_tuple("1.x.3") == ()


def test_same_domain_rejects_non_web_schemes():
    c = scanner.Crawler("http://localhost:8080")
    assert c._same_domain("mailto:a@b.com") is False
    assert c._same_domain("javascript:alert(1)") is False
    assert c._same_domain("http://localhost:8080/x") is True


def test_check_headers_flags_missing_and_passes_present():
    missing = FakeResp(headers={})
    assert len(scanner.check_headers("u", missing)) == len(scanner.SECURITY_HEADERS)
    present = FakeResp(headers={h: "v" for h in scanner.SECURITY_HEADERS})
    assert scanner.check_headers("u", present) == []


def test_js_library_flags_old_ignores_new():
    old = FakeResp(headers={"Content-Type": "text/html"},
                   text='<script src="jquery-1.12.4.min.js"></script>')
    f = scanner.check_js_libraries("u", old)
    assert len(f) == 1 and f[0]["check"] == "outdated_js_library"
    new = FakeResp(headers={"Content-Type": "text/html"},
                   text='<script src="jquery-3.6.0.min.js"></script>')
    assert scanner.check_js_libraries("u", new) == []


def test_sql_error_regex():
    assert scanner.SQL_ERROR_RE.search("You have an error in your SQL syntax near")
    assert not scanner.SQL_ERROR_RE.search("everything is fine here")


def test_cookie_flags_detected():
    resp = FakeResp(cookies=[FakeCookie("SESSION")])
    f = scanner.check_cookies("u", resp)
    assert f and "Secure" in f[0]["title"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} tests passed")
