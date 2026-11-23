"""Website / HTML analyzer (URL or local HTML file).

For URLs: fetches with stdlib urllib (timeout, size cap), reports status,
headers, TLS certificate info, cookies, and security-header hygiene.
For both URLs and local files: parses HTML with html.parser and reports
title, scripts (inline/external), iframes, forms, links, external hosts,
mixed content, and per-finding evidence.
"""

from __future__ import annotations

import html.parser
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .util import human_size

MAX_FETCH_BYTES = 5 * 1024 * 1024
FETCH_TIMEOUT = 15
UA = "GlassScopeStudio/1.0 (+local analysis only)"

SECURITY_HEADERS = [
    ("content-security-policy", "CSP missing — script sources are unrestricted"),
    ("strict-transport-security", "HSTS missing — downgrade attacks possible"),
    ("x-frame-options", "X-Frame-Options missing — clickjacking exposure"),
    ("x-content-type-options", "X-Content-Type-Options missing — MIME sniffing"),
    ("referrer-policy", "Referrer-Policy missing"),
]


class _HTMLInfo(html.parser.HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title = ""
        self.scripts: list[dict] = []       # {src|inline, host, size}
        self.iframes: list[dict] = []
        self.forms: list[dict] = []
        self.links: list[dict] = []         # a hrefs
        self.styles: list[str] = []
        self.images: list[str] = []
        self.metas: list[dict] = []
        self._in_title = False
        self._inline_buf: list[str] | None = None
        self._cur_form: dict | None = None

    # -- helpers -----------------------------------------------------------
    def _resolve(self, url: str) -> str:
        try:
            return urllib.parse.urljoin(self.base, url.strip())
        except ValueError:
            return url

    # -- parser callbacks ----------------------------------------------------
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            src = d.get("src")
            if src:
                self.scripts.append({"src": self._resolve(src), "inline": False})
            else:
                self._inline_buf = []
        elif tag == "iframe":
            self.iframes.append({"src": self._resolve(d.get("src", ""))})
        elif tag == "form":
            self._cur_form = {
                "action": self._resolve(d.get("action", self.base)),
                "method": (d.get("method") or "get").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            self._cur_form["inputs"].append(d.get("name") or d.get("type") or tag)
        elif tag == "a" and d.get("href"):
            self.links.append({"href": self._resolve(d["href"]),
                               "text": "", "external": False})
        elif tag == "link" and (d.get("rel") or "").lower().find("stylesheet") >= 0 and d.get("href"):
            self.styles.append(self._resolve(d["href"]))
        elif tag == "img" and d.get("src"):
            self.images.append(self._resolve(d["src"]))
        elif tag == "meta":
            self.metas.append({"name": d.get("name") or d.get("property") or "",
                               "content": d.get("content", ""),
                               "http_equiv": d.get("http-equiv", "")})

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._inline_buf is not None:
            self._inline_buf.append(data)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._inline_buf is not None:
            inline = "".join(self._inline_buf)
            self.scripts.append({"src": "", "inline": True, "size": len(inline)})
            self._inline_buf = None
        elif tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def _classify_hosts(items: list[str], page_host: str) -> list[str]:
    hosts: set[str] = set()
    for url in items:
        try:
            host = urllib.parse.urlsplit(url).netloc.lower()
        except ValueError:
            continue
        if host and host != page_host:
            hosts.add(host)
    return sorted(hosts)


def scan_website(target: str, fetch_robots: bool = False, on_progress=None) -> dict:
    """Analyze a URL (http/https) or a local HTML file path."""
    result: dict = {
        "ok": False, "kind": "Website", "target": target, "warnings": [],
        "response": {}, "tls": {}, "html": {}, "findings": [],
    }
    warnings = result["warnings"]
    findings = result["findings"]

    is_local = not re.match(r"^https?://", target.strip(), re.I)
    html_text = ""
    if is_local:
        path = os.path.expanduser(target.strip())
        if not os.path.isfile(path):
            warnings.append(f"Local file not found: {path}")
            return result
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                html_text = fh.read(MAX_FETCH_BYTES)
        except OSError as exc:
            warnings.append(f"Read failed: {exc}")
            return result
        result["response"] = {
            "status": "local file", "final_url": path,
            "headers": {}, "size": len(html_text.encode("utf-8")),
        }
        base_url = "file://" + os.path.abspath(path)
    else:
        url = target.strip()
        ctx = ssl.create_default_context()
        headers = {"User-Agent": UA, "Accept": "*/*"}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT, context=ctx) as resp:
                raw = resp.read(MAX_FETCH_BYTES)
                final_url = resp.geturl()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status
        except urllib.error.HTTPError as exc:
            warnings.append(f"HTTP error {exc.code}: {exc.reason}")
            result["response"] = {"status": exc.code, "final_url": url, "headers": {}, "size": 0}
            return result
        except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError) as exc:
            warnings.append(f"Fetch failed: {exc}")
            return result
        html_text = raw.decode("utf-8", "replace")
        result["response"] = {
            "status": status, "final_url": final_url, "headers": resp_headers,
            "size": len(raw), "size_human": human_size(len(raw)),
        }
        base_url = final_url
        if final_url.startswith("https://"):
            host = urllib.parse.urlsplit(final_url).hostname or ""
            try:
                with socket.create_connection((host, 443), timeout=FETCH_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                result["tls"] = {
                    "subject": dict(cert.get("subject", ())).get("commonName", ""),
                    "issuer": dict(cert.get("issuer", ())).get("organizationName", ""),
                    "not_after": cert.get("notAfter", ""),
                    "san": ", ".join(
                        v for k, v in cert.get("subjectAltName", ())[:8] if k == "DNS"),
                }
            except (OSError, ssl.SSLError, ValueError) as exc:
                warnings.append(f"TLS info unavailable: {exc}")

        # security headers + cookies
        for key, message in SECURITY_HEADERS:
            if key not in resp_headers:
                findings.append({"rule": f"missingHeader:{key}", "severity": "medium",
                                 "title": message, "evidence": ""})
        cookies = resp_headers.get("set-cookie", "")
        if cookies:
            result["response"]["cookies"] = [
                c.split(";")[0] for c in cookies.split(",\n") if c.strip()]
            if not re.search(r"secure", cookies, re.I):
                findings.append({"rule": "cookieNotSecure", "severity": "medium",
                                 "title": "Set-Cookie without Secure flag", "evidence": ""})
        if result["response"]["headers"].get("server"):
            findings.append({"rule": "serverBanner", "severity": "low",
                             "title": f"Server banner exposed: {result['response']['headers']['server']}",
                             "evidence": result["response"]["headers"]["server"]})

    # Parse HTML
    page_host = urllib.parse.urlsplit(base_url).netloc.lower()
    parser = _HTMLInfo(base_url)
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # html.parser raises on malformed entities rarely
        warnings.append(f"HTML parse issue: {exc}")

    script_urls = [s["src"] for s in parser.scripts if not s.get("inline")]
    asset_urls = script_urls + parser.styles + parser.images + [f["src"] for f in parser.iframes]
    external_hosts = _classify_hosts(asset_urls, page_host)

    result["html"] = {
        "title": parser.title.strip()[:200],
        "inline_scripts": sum(1 for s in parser.scripts if s.get("inline")),
        "external_scripts": len(script_urls),
        "iframes": parser.iframes,
        "forms": parser.forms,
        "external_links": len(parser.links),
        "stylesheets": len(parser.styles),
        "images": len(parser.images),
        "external_hosts": external_hosts,
        "metas": [m for m in parser.metas if m["name"] or m["http_equiv"]][:20],
    }

    # Mixed content: http:// subresources referenced from https page
    if base_url.startswith("https://"):
        for url in asset_urls:
            if url.startswith("http://"):
                findings.append({"rule": "mixedContent", "severity": "high",
                                 "title": f"Mixed content (insecure asset on HTTPS page): {url[:120]}",
                                 "evidence": url})
    if parser.scripts and all(s.get("inline") for s in parser.scripts) and parser.scripts:
        pass  # inline-only pages are common; no finding
    if len(parser.forms) and base_url.startswith("http://"):
        findings.append({"rule": "formOverHttp", "severity": "high",
                         "title": "Forms submitted over plain HTTP", "evidence": ""})
    for meta in parser.metas:
        if (meta.get("http_equiv") or "").lower() == "refresh":
            findings.append({"rule": "metaRefresh", "severity": "low",
                             "title": "Meta refresh redirect", "evidence": meta.get("content", "")[:120]})

    if fetch_robots and not is_local and base_url.startswith("http"):
        robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(robots_url, headers={"User-Agent": UA}),
                    timeout=FETCH_TIMEOUT) as resp:
                body = resp.read(64 * 1024).decode("utf-8", "replace")
            result["robots"] = {
                "found": True,
                "disallow_count": sum(1 for ln in body.splitlines()
                                      if ln.strip().lower().startswith("disallow:")),
                "sitemaps": [ln.split(":", 1)[1].strip() for ln in body.splitlines()
                             if ln.strip().lower().startswith("sitemap:")][:10],
            }
        except (urllib.error.URLError, OSError):
            result["robots"] = {"found": False}

    result["ok"] = True
    return result
