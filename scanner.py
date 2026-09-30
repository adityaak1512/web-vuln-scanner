#!/usr/bin/env python3

import argparse
import collections
import hashlib
import html
import json
import re
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "EduVulnScanner/1.0 (course project; authorized-target-only)"
CANARY = "scnrXSS7f3q<script>alert(1)</script>"


def dvwa_login(session, base_url, username="admin", password="password", timeout=8):
    login_url = f"{base_url.rstrip('/')}/login.php"
    try:
        resp = session.get(login_url, timeout=timeout, verify=False)
    except requests.RequestException as e:
        print(f"  [login] could not reach {login_url}: {e}")
        return False

    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }
    try:
        resp2 = session.post(login_url, data=data, timeout=timeout, verify=False)
    except requests.RequestException as e:
        print(f"  [login] login POST failed: {e}")
        return False

    session.cookies.set("security", "low")

    final_url = resp2.url.lower()

    if "setup.php" in final_url:
        print("  [login] redirected to setup.php -- initializing database automatically...")
        setup_url = f"{base_url.rstrip('/')}/setup.php"
        try:
            setup_resp = session.get(setup_url, timeout=timeout, verify=False)
            setup_soup = BeautifulSoup(setup_resp.text, "html.parser")
            setup_token_input = setup_soup.find("input", {"name": "user_token"})
            setup_token = setup_token_input["value"] if setup_token_input else ""
            session.post(
                setup_url,
                data={"create_db": "Create / Reset Database", "user_token": setup_token},
                timeout=timeout, verify=False,
            )
        except requests.RequestException as e:
            print(f"  [login] database setup step failed: {e}")

        resp3 = session.get(login_url, timeout=timeout, verify=False)
        soup3 = BeautifulSoup(resp3.text, "html.parser")
        token3_input = soup3.find("input", {"name": "user_token"})
        token3 = token3_input["value"] if token3_input else ""
        resp2 = session.post(
            login_url,
            data={"username": username, "password": password, "Login": "Login", "user_token": token3},
            timeout=timeout, verify=False,
        )
        final_url = resp2.url.lower()

    still_on_login = "login.php" in final_url or 'name="password"' in resp2.text.lower()
    success = not still_on_login and "setup.php" not in final_url

    print(f"  [login] token extracted: {token!r}")
    print(f"  [login] final URL after login attempt: {resp2.url}")
    print(f"  [login] DVWA login {'succeeded' if success else 'FAILED'}")
    return success


class Crawler:
    def __init__(self, base_url, max_pages=25, timeout=8, cookie=None):
        self.base_url = base_url.rstrip("/")
        self.domain = urllib.parse.urlparse(base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if cookie:
            self.session.headers.update({"Cookie": cookie})

        self.visited = set()
        self.pages = {}
        self.forms = []

    def _same_domain(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("", "http", "https"):
            return False
        return parsed.netloc in ("", self.domain)

    def _normalize(self, url):
        url = urllib.parse.urljoin(self.base_url, url)
        url, _frag = urllib.parse.urldefrag(url)
        return url

    def _seed_urls(self):
        """Discover extra entry points from robots.txt and sitemap.xml.

        A plain link-crawler misses most of a JavaScript-rendered app, whose
        navigation never appears as <a href> in the served HTML. robots.txt and
        sitemap.xml are the two places such an app still advertises real paths in
        plain text, so seeding from them widens coverage without executing JS.
        """
        seeds = []
        try:
            r = self.session.get(f"{self.base_url}/robots.txt",
                                 timeout=self.timeout, verify=False)
            if r.status_code == 200 and len(r.content) < 100000:
                for line in r.text.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if low.startswith(("allow:", "disallow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and "*" not in path:
                            seeds.append(path)
                    elif low.startswith("sitemap:"):
                        seeds.append(line.split(":", 1)[1].strip())
        except requests.RequestException:
            pass
        try:
            r = self.session.get(f"{self.base_url}/sitemap.xml",
                                 timeout=self.timeout, verify=False)
            if r.status_code == 200 and "<loc" in r.text:
                seeds += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)
        except requests.RequestException:
            pass

        discovered = []
        for u in seeds:
            nu = self._normalize(u)
            if self._same_domain(nu) and nu not in discovered:
                discovered.append(nu)
        if discovered:
            print(f"  [crawl] seeded {len(discovered)} extra path(s) "
                  "from robots.txt / sitemap.xml")
        return discovered

    def crawl(self):
        queue = [self.base_url] + self._seed_urls()
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
            except requests.RequestException as e:
                print(f"  [crawl] failed to fetch {url}: {e}")
                continue

            self.pages[url] = resp
            print(f"  [crawl] ({len(self.visited)}/{self.max_pages}) {resp.status_code} {url}")

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for a in soup.find_all("a", href=True):
                link = self._normalize(a["href"])
                if self._same_domain(link) and link not in self.visited:
                    queue.append(link)

            for form in soup.find_all("form"):
                action = self._normalize(form.get("action") or url)
                method = (form.get("method") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inputs.append(name)
                if inputs:
                    self.forms.append({
                        "page": url, "action": action,
                        "method": method, "inputs": inputs,
                    })

        return self.pages, self.forms


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Missing Content-Security-Policy header",
        "Allows a broader range of injected scripts/styles to execute if XSS exists.",
    ),
    "Strict-Transport-Security": (
        "Missing Strict-Transport-Security (HSTS) header",
        "Site can be downgraded to plain HTTP, enabling traffic interception.",
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options header",
        "Page can be embedded in an <iframe>, enabling clickjacking attacks.",
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options header",
        "Browser may MIME-sniff responses, enabling certain content-spoofing attacks.",
    ),
}


def check_headers(url, resp):
    findings = []
    for header, (title, why) in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "check": "security_headers",
                "severity": "medium",
                "url": url,
                "title": title,
                "detail": why,
            })
    return findings


def check_cookies(url, resp):
    findings = []
    set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if resp.raw and resp.raw.headers else []
    if not set_cookie_headers and resp.cookies:
        set_cookie_headers = [f"{c.name}=<value>" for c in resp.cookies]

    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0]
        lower = raw.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append({
                "check": "cookie_flags",
                "severity": "medium",
                "url": url,
                "title": f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                "detail": "Cookies without these flags are more exposed to theft via XSS "
                           "or transmission over insecure channels.",
            })
    return findings


SENSITIVE_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.local",
    "backup.zip",
    "backup.sql",
    "db_backup.sql",
    "config.php.bak",
    "wp-config.php.bak",
    ".DS_Store",
    "web.config.bak",
    "robots.txt",
]


def _get_baseline_404(base_url, session, timeout=8):
    probe_path = f"__scanner_probe_{uuid.uuid4().hex}__"
    url = f"{base_url.rstrip('/')}/{probe_path}"
    try:
        resp = session.get(url, timeout=timeout, verify=False)
    except requests.RequestException:
        return None

    return {
        "status_code": resp.status_code,
        "length": len(resp.content),
        "hash": hashlib.sha256(resp.content).hexdigest(),
    }


def check_sensitive_files(base_url, session, timeout=8):
    findings = []
    baseline = _get_baseline_404(base_url, session, timeout=timeout)

    for path in SENSITIVE_PATHS:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            resp = session.get(url, timeout=timeout, verify=False)
        except requests.RequestException:
            continue

        if path == "robots.txt" and resp.status_code == 200:
            interesting = [
                line for line in resp.text.splitlines()
                if line.strip().lower().startswith("disallow") and len(line.strip()) > len("disallow:")
            ]
            if interesting:
                findings.append({
                    "check": "sensitive_files",
                    "severity": "low",
                    "url": url,
                    "title": "robots.txt discloses internal paths",
                    "detail": "; ".join(interesting[:10]),
                })
            continue

        if resp.status_code != 200 or len(resp.content) == 0:
            continue

        if baseline and (
            resp.status_code == baseline["status_code"]
            and len(resp.content) == baseline["length"]
            and hashlib.sha256(resp.content).hexdigest() == baseline["hash"]
        ):
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type and not path.endswith((".html", ".php")):
            continue

        findings.append({
            "check": "sensitive_files",
            "severity": "high",
            "url": url,
            "title": f"Potentially exposed sensitive file: /{path}",
            "detail": f"Server returned HTTP 200 ({len(resp.content)} bytes, "
                       f"Content-Type: {content_type or 'unknown'}) for a path "
                       "that should normally be inaccessible.",
        })
    return findings


def check_xss_get_params(url, session, timeout=8):
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        test_params = {k: (CANARY if k == param else v[0]) for k, v in params.items()}
        test_query = urllib.parse.urlencode(test_params)
        test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

        try:
            resp = session.get(test_url, timeout=timeout, verify=False)
        except requests.RequestException:
            continue

        if "<script>alert(1)</script>" in resp.text:
            findings.append({
                "check": "reflected_xss",
                "severity": "high",
                "url": test_url,
                "title": f"Reflected XSS via parameter '{param}'",
                "detail": "Canary payload was reflected in the response without HTML-encoding.",
            })
    return findings


def check_xss_forms(forms, session, timeout=8):
    findings = []
    for form in forms:
        data = {name: CANARY for name in form["inputs"]}
        try:
            if form["method"] == "post":
                resp = session.post(form["action"], data=data, timeout=timeout, verify=False)
            else:
                resp = session.get(form["action"], params=data, timeout=timeout, verify=False)
        except requests.RequestException:
            continue

        if "<script>alert(1)</script>" in resp.text:
            findings.append({
                "check": "reflected_xss",
                "severity": "high",
                "url": form["action"],
                "title": f"Reflected XSS via form on {form['page']}",
                "detail": f"Form fields tested: {', '.join(form['inputs'])}",
            })
    return findings


SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='2", "') OR ('1'='1"]

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite3\.OperationalError",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"ORA-\d{5}",
    r"System\.Data\.SqlClient",
    r"mysqli_sql_exception",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)


def _try_sqli(url, session, timeout):
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: (payload if k == param else v[0]) for k, v in params.items()}
            test_query = urllib.parse.urlencode(test_params)
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
            try:
                resp = session.get(test_url, timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            if SQL_ERROR_RE.search(resp.text):
                findings.append({
                    "check": "sql_injection",
                    "severity": "critical",
                    "url": test_url,
                    "title": f"Possible SQL injection via parameter '{param}'",
                    "detail": f"Payload {payload!r} triggered a database error message in the response.",
                })
                break
    return findings


def check_sqli_get_params(url, session, timeout=8):
    return _try_sqli(url, session, timeout)


def check_sqli_forms(forms, session, timeout=8):
    findings = []
    for form in forms:
        for payload in SQLI_PAYLOADS:
            data = {name: payload for name in form["inputs"]}
            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=timeout, verify=False)
                else:
                    resp = session.get(form["action"], params=data, timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            if SQL_ERROR_RE.search(resp.text):
                findings.append({
                    "check": "sql_injection",
                    "severity": "critical",
                    "url": form["action"],
                    "title": f"Possible SQL injection via form on {form['page']}",
                    "detail": f"Payload {payload!r} in fields {', '.join(form['inputs'])} "
                               "triggered a database error message.",
                })
                break
    return findings


JS_LIBRARY_PATTERNS = [
    {
        "name": "jQuery",
        "regex": re.compile(r"jquery[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (3, 5, 0),
        "cve": "CVE-2020-11022 / CVE-2020-11023 (XSS in jQuery < 3.5.0)",
    },
    {
        "name": "AngularJS",
        "regex": re.compile(r"angular[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (1, 8, 0),
        "cve": "Multiple known XSS/sandbox-escape issues in AngularJS < 1.8.0",
    },
    {
        "name": "Bootstrap",
        "regex": re.compile(r"bootstrap[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (3, 4, 1),
        "cve": "CVE-2019-8331 (XSS in Bootstrap < 3.4.1)",
    },
    {
        "name": "Lodash",
        "regex": re.compile(r"lodash[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (4, 17, 21),
        "cve": "CVE-2021-23337 (command injection in Lodash < 4.17.21)",
    },
]


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def check_js_libraries(url, resp):
    findings = []
    if "text/html" not in resp.headers.get("Content-Type", ""):
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")
    script_srcs = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
    haystack = " ".join(script_srcs) + " " + resp.text[:20000]

    seen = set()
    for lib in JS_LIBRARY_PATTERNS:
        m = lib["regex"].search(haystack)
        if not m:
            continue
        version = m.group(1)
        key = (lib["name"], version)
        if key in seen:
            continue
        seen.add(key)

        parsed_version = _version_tuple(version)
        if parsed_version and parsed_version < lib["vulnerable_below"]:
            findings.append({
                "check": "outdated_js_library",
                "severity": "medium",
                "url": url,
                "title": f"Outdated {lib['name']} version {version} detected",
                "detail": lib["cve"],
            })
    return findings


def run_scan(target_url, max_pages, timeout, cookie=None, dvwa_auto_login=False):
    print(f"\n[+] Starting scan of {target_url}")
    print(f"[+] Ethics note: only run this against systems you own or are "
          f"authorized to test (e.g. Juice Shop, DVWA).\n")
    if cookie:
        print(f"[+] Using authenticated session (cookie supplied).\n")

    crawler = Crawler(target_url, max_pages=max_pages, timeout=timeout, cookie=cookie)

    if dvwa_auto_login:
        dvwa_login(crawler.session, target_url)
    pages, forms = crawler.crawl()
    print(f"\n[+] Crawl complete: {len(pages)} pages, {len(forms)} forms discovered.\n")

    all_findings = []
    session = crawler.session

    print("[+] Running per-page checks (headers, cookies, JS libs)...")
    for url, resp in pages.items():
        all_findings += check_headers(url, resp)
        all_findings += check_cookies(url, resp)
        all_findings += check_js_libraries(url, resp)

    print("[+] Running sensitive file checks...")
    all_findings += check_sensitive_files(target_url, session, timeout=timeout)

    print("[+] Running XSS canary injection checks...")
    for url in pages:
        all_findings += check_xss_get_params(url, session, timeout=timeout)
    all_findings += check_xss_forms(forms, session, timeout=timeout)

    print("[+] Running SQLi error-based checks...")
    for url in pages:
        all_findings += check_sqli_get_params(url, session, timeout=timeout)
    all_findings += check_sqli_forms(forms, session, timeout=timeout)

    print(f"\n[+] Scan complete. {len(all_findings)} findings.\n")
    return {
        "target": target_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": len(pages),
        "forms_discovered": len(forms),
        "findings": all_findings,
    }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c",
    "medium": "#b45309", "low": "#2563eb",
}


def write_json_report(results, out_prefix):
    path = f"{out_prefix}.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    return path


def write_html_report(results, out_prefix):
    findings = sorted(results["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    rows = ""
    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "#374151")
        sev = html.escape(str(f["severity"]))
        chk = html.escape(str(f["check"]))
        furl = html.escape(str(f["url"]))
        title = html.escape(str(f["title"]))
        detail = html.escape(str(f["detail"]))
        rows += f"""
        <tr>
          <td><span style="background:{color};color:white;padding:2px 8px;
              border-radius:4px;font-size:12px;font-weight:600;text-transform:uppercase;">
              {sev}</span></td>
          <td>{chk}</td>
          <td style="word-break:break-all;font-family:monospace;font-size:13px;">{furl}</td>
          <td>{title}</td>
          <td style="color:#555;font-size:13px;">{detail}</td>
        </tr>"""

    summary_badges = "".join(
        f'<span style="background:{SEVERITY_COLOR.get(sev,"#374151")};color:white;'
        f'padding:4px 12px;border-radius:6px;margin-right:8px;font-size:14px;">'
        f'{sev}: {count}</span>'
        for sev, count in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    )

    target = html.escape(str(results["target"]))
    scanned = html.escape(str(results["scanned_at"]))
    html_doc = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Scan Report - {target}</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 40px; color:#111; background:#fafafa; }}
  h1 {{ font-size: 22px; }}
  .meta {{ color:#555; font-size: 14px; margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; background: white; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  .ethics {{ background: #eef6ff; border-left: 4px solid #2563eb; padding: 10px 14px; margin: 20px 0; font-size: 14px; }}
</style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong><br>
    Scanned at: {scanned}<br>
    Pages crawled: {results['pages_crawled']} &nbsp;|&nbsp; Forms discovered: {results['forms_discovered']} &nbsp;|&nbsp; Total findings: {len(findings)}
  </div>
  <div>{summary_badges}</div>
  <div class="ethics">
    This scan was run against a target explicitly designed/authorized for security testing,
    as part of a course project. No unauthorized systems were accessed.
  </div>
  <table>
    <tr><th>Severity</th><th>Check</th><th>URL</th><th>Finding</th><th>Detail</th></tr>
    {rows}
  </table>
</body>
</html>"""

    path = f"{out_prefix}.html"
    with open(path, "w") as f:
        f.write(html_doc)
    return path


def main():
    parser = argparse.ArgumentParser(description="Lightweight educational web vulnerability scanner.")
    parser.add_argument("--url", required=True, help="Target base URL, e.g. http://localhost:3000")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl (default 25)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default 8)")
    parser.add_argument("--out", default="report", help="Output file prefix (default 'report')")
    parser.add_argument("--cookie", default=None,
                         help="Raw cookie string for authenticated crawling, e.g. 'PHPSESSID=abc123'")
    parser.add_argument("--dvwa-login", action="store_true",
                         help="Automatically log into DVWA (admin/password) before crawling")
    args = parser.parse_args()

    start = time.time()
    results = run_scan(args.url, args.max_pages, args.timeout, cookie=args.cookie,
                        dvwa_auto_login=args.dvwa_login)
    elapsed = time.time() - start

    json_path = write_json_report(results, args.out)
    html_path = write_html_report(results, args.out)

    counts = collections.Counter(f["severity"] for f in results["findings"])
    order = ["critical", "high", "medium", "low"]
    summary = "  ".join(f"{sev}={counts[sev]}" for sev in order if counts.get(sev))
    print("\n[+] Findings by severity: " + (summary if summary else "none"))
    print(f"[+] Scan took {elapsed:.1f}s")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")

    if not results["findings"]:
        print("[+] No findings -- nice, but double check your checks are actually reaching the target!")


if __name__ == "__main__":
    main()
