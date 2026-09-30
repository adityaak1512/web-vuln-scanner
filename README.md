# Lightweight Web Vulnerability Scanner

An educational CLI tool that crawls a target web app and checks for:

1. Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
2. Insecure cookie flags (Secure / HttpOnly / SameSite)
3. Exposed sensitive files (`.git/`, `.env`, backups, `robots.txt` leaks)
4. Reflected XSS (canary string injection)
5. SQL injection (error-based detection)
6. Outdated JS libraries (regex version matching against known-vulnerable ranges)

> **Only run this against targets you own or are explicitly authorized to test**,
> such as OWASP Juice Shop or DVWA. Do not point this at real/third-party sites.

## Setup

```bash
cd vulnscanner_project
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

`venv` creates an isolated Python environment just for this project, so the
packages we install don't clash with anything else on your system. You need
to run `source venv/bin/activate` every time you open a new terminal tab to
work on this project (you'll see `(venv)` appear in your prompt when it's active).

## Running against Juice Shop

```bash
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
python3 scanner.py --url http://localhost:3000 --max-pages 30 --out juiceshop_report
```

## Running against DVWA

```bash
docker run -d -p 4280:80 --name dvwa vulnerables/web-dvwa
python3 scanner.py --url http://localhost:4280 --max-pages 30 --out dvwa_report
```

DVWA requires logging in first (admin/password) and setting security level to
"Low" via the DVWA Security page in the UI before scanning, since most checks
need to reach pages that sit behind login.

## Output

Two files are generated: `<prefix>.json` (machine-readable, good for feeding
into further analysis/comparison scripts) and `<prefix>.html` (a readable
report you can screenshot or open in a browser for your demo).

## Running the tests

```bash
pip3 install pytest
python3 -m pytest -q
```

The tests are offline (no network or target needed) and cover the report
generation, version parsing, header/cookie/JS-library checks, and the SQL
error signatures.

## Stopping/removing containers when done

```bash
docker stop juiceshop dvwa
docker rm juiceshop dvwa
```
