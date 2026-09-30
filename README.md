# Lightweight Web Vulnerability Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-9%20passing-2ea44f)
![Dependencies](https://img.shields.io/badge/dependencies-2-informational)
![License](https://img.shields.io/badge/license-MIT-blue)

An educational command-line scanner that crawls a target web application and
reports common web-security issues. Built as a course project to understand how
automated scanners work under the hood, using only `requests` and
`BeautifulSoup`.

> **Authorized targets only.** Run this against systems you own or have explicit
> permission to test, such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
> or [DVWA](https://github.com/digininja/DVWA). Do not point it at third-party
> sites you do not control.

## What it checks

| Check | Severity | What it looks for |
|-------|----------|-------------------|
| Security headers | medium | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Cookie flags | medium | Cookies set without `Secure` / `HttpOnly` / `SameSite` |
| Sensitive files | high | Exposed `.git/`, `.env`, backups; `robots.txt` path disclosure |
| Reflected XSS | high | Canary payload reflected into a response without encoding |
| SQL injection | critical | Error-based detection via database error signatures |
| Outdated JS libraries | medium | Known-vulnerable versions of jQuery, AngularJS, Bootstrap, Lodash |

## How it works

```
  target URL
      │
      ▼
  ┌─────────┐   seeds extra paths from robots.txt + sitemap.xml,
  │ Crawler │   then follows same-domain <a href> links and forms
  └────┬────┘
       │  pages + forms
       ▼
  ┌─────────┐   six independent checks run over the crawled pages,
  │ Checks  │   discovered forms, and the target root
  └────┬────┘
       │  findings
       ▼
  ┌─────────┐   JSON (machine-readable) + HTML (severity-sorted,
  │ Reports │   HTML-escaped) written to <prefix>.json / .html
  └─────────┘
```

Each finding is a small dict with a `check`, `severity`, `url`, `title` and
`detail`, so the JSON output is easy to diff between scans or feed into other
tooling.

## Setup

```bash
cd vulnscanner_project
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage

Against OWASP Juice Shop:

```bash
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
python3 scanner.py --url http://localhost:3000 --max-pages 30 --out juiceshop_report
```

Against DVWA (auto-handles the login and first-run database setup):

```bash
docker run -d -p 4280:80 --name dvwa vulnerables/web-dvwa
python3 scanner.py --url http://localhost:4280 --max-pages 30 --out dvwa_report --dvwa-login
```

Key options: `--max-pages` (crawl cap), `--timeout`, `--cookie` (raw cookie
string for authenticated crawling), `--dvwa-login` (log into DVWA as
admin/password before crawling).

## Output

Two files per scan: `<prefix>.json` (machine-readable) and `<prefix>.html` (a
severity-sorted report to open in a browser). All values written into the HTML
report are HTML-escaped, so a reflected payload captured during the scan is
displayed as text and never executes when the report is opened. Sample outputs
are included in this repo (`dvwa_report.html`, `juiceshop_report.html`).

## Running the tests

```bash
pip3 install pytest
python3 -m pytest -q
```

The suite is fully offline (no network or live target needed) and covers report
escaping, version parsing, the header / cookie / JS-library checks, the SQL
error signatures, the crawler scheme filter, and robots/sitemap seeding.

## Limitations and future work

This is a learning tool, and it is deliberately honest about what it does not do:

- **It does not execute JavaScript.** Single-page apps (Angular, React) render
  their navigation client-side, so a plain HTML crawl sees only the shell. The
  scanner mitigates this by seeding from `robots.txt` and `sitemap.xml`, but full
  coverage of a SPA would need a headless browser or its REST API map.
- **Detection is heuristic, not exhaustive.** The XSS and SQLi checks catch
  reflection and error-based cases; they are not a substitute for a full scanner
  like OWASP ZAP or Burp Suite. Blind, stored, and time-based cases are out of
  scope.
- **Library detection needs a version in the asset path.** Bundlers that emit
  hash-named files (`main.8f3a.js`) hide the version, so those go undetected.

## License

MIT — see [LICENSE](LICENSE).
