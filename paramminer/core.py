"""
Core HTTP engine with deep response diffing.
The entire tool is built on detecting subtle differences
between responses — size, structure, timing, DOM, headers.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import hashlib
import difflib
import re
import json
from typing import Optional

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
DIM  = "\033[90m"
BOLD = "\033[1m"
RST  = "\033[0m"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def http_get(url: str, headers: dict = None, cookies: str = None,
             timeout: int = 15, follow_redirects: bool = True) -> dict:
    """GET request returning rich response metadata."""
    req_headers = {
        "User-Agent":      DEFAULT_UA,
        "Accept":          "text/html,application/json,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
        "Cache-Control":   "no-cache",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers=req_headers, method="GET")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None

        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX)
            )
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                NoRedirect()
            )

        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            return _build_result(resp.status, resp_headers, body, elapsed, url)

    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        resp_headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return _build_result(e.code, resp_headers, body, elapsed, url)

    except Exception as e:
        elapsed = time.perf_counter() - start
        return _build_result(0, {}, "", elapsed, url, error=str(e))


def http_post(url: str, data: dict = None, json_body: dict = None,
              raw_body: str = None, headers: dict = None,
              cookies: str = None, timeout: int = 15) -> dict:
    """POST request."""
    req_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept":     "application/json, text/html, */*",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    if json_body is not None:
        body_bytes = json.dumps(json_body).encode()
        req_headers["Content-Type"] = "application/json"
    elif data is not None:
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw_body:
        body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body
    else:
        body_bytes = b""

    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, data=body_bytes,
                                      headers=req_headers, method="POST")
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX)
        )
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            return _build_result(resp.status, resp_headers, body, elapsed, url)
    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        resp_headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return _build_result(e.code, resp_headers, body, elapsed, url)
    except Exception as e:
        elapsed = time.perf_counter() - start
        return _build_result(0, {}, "", elapsed, url, error=str(e))


def _build_result(status, headers, body, elapsed, url, error=None):
    return {
        "status":      status,
        "headers":     headers,
        "body":        body,
        "body_length": len(body),
        "body_hash":   hashlib.md5(body.encode()).hexdigest(),
        "elapsed":     round(elapsed, 4),
        "url":         url,
        "error":       error,
        "content_type": headers.get("content-type", ""),
        "location":    headers.get("location", ""),
        "server":      headers.get("server", ""),
        "set_cookie":  headers.get("set-cookie", ""),
    }


# ── Deep Response Diffing ─────────────────────────────────────────────────────

def deep_diff(baseline: dict, candidate: dict) -> dict:
    """
    Exhaustive diff between baseline and candidate response.
    Returns structured diff with confidence score.
    """
    size_diff   = candidate["body_length"] - baseline["body_length"]
    size_pct    = abs(size_diff) / max(baseline["body_length"], 1) * 100
    same_hash   = baseline["body_hash"] == candidate["body_hash"]
    status_diff = baseline["status"] != candidate["status"]
    time_diff   = abs(candidate["elapsed"] - baseline["elapsed"])

    # Text similarity
    similarity = difflib.SequenceMatcher(
        None,
        baseline["body"][:8000],
        candidate["body"][:8000]
    ).ratio()

    # Word-level diff — what changed
    baseline_words   = set(re.findall(r'\b\w+\b', baseline["body"][:10000]))
    candidate_words  = set(re.findall(r'\b\w+\b', candidate["body"][:10000]))
    new_words        = candidate_words - baseline_words
    removed_words    = baseline_words - candidate_words

    # DOM structure diff
    def count_tags(html):
        return {t: html.lower().count(f"<{t}") for t in
                ["input", "form", "select", "option", "button",
                 "table", "tr", "td", "div", "span", "a",
                 "script", "style", "meta", "link"]}

    base_tags  = count_tags(baseline["body"])
    cand_tags  = count_tags(candidate["body"])
    tag_diffs  = {k: cand_tags[k] - base_tags[k]
                  for k in base_tags if cand_tags[k] != base_tags[k]}

    # Header diffs
    new_headers     = set(candidate["headers"].keys()) - set(baseline["headers"].keys())
    changed_headers = {k: (baseline["headers"].get(k), candidate["headers"].get(k))
                       for k in candidate["headers"]
                       if candidate["headers"].get(k) != baseline["headers"].get(k)}

    # Interesting content in response
    interesting_patterns = {
        "error":      bool(re.search(r'error|exception|warning|invalid|undefined', candidate["body"], re.I)),
        "debug":      bool(re.search(r'debug|trace|stack|internal server', candidate["body"], re.I)),
        "json_keys":  re.findall(r'"([a-z_][a-z0-9_]{2,30})":', candidate["body"][:5000]),
        "reflection": False,  # filled by caller
        "redirect":   bool(candidate.get("location")),
        "new_cookie": bool(candidate["set_cookie"] and candidate["set_cookie"] != baseline["set_cookie"]),
    }

    # Confidence score — how likely this is a real parameter
    confidence = 0
    if size_pct > 5:        confidence += 30
    if size_pct > 15:       confidence += 20
    if status_diff:         confidence += 40
    if similarity < 0.95:   confidence += 20
    if similarity < 0.80:   confidence += 20
    if tag_diffs:           confidence += 15
    if new_headers:         confidence += 10
    if interesting_patterns["error"]:   confidence += 15
    if interesting_patterns["debug"]:   confidence += 25
    if interesting_patterns["redirect"]:confidence += 20
    if interesting_patterns["new_cookie"]: confidence += 20
    if time_diff > 2.0:     confidence += 10

    return {
        "size_diff":    size_diff,
        "size_pct":     round(size_pct, 2),
        "same_hash":    same_hash,
        "status_diff":  status_diff,
        "time_diff":    round(time_diff, 3),
        "similarity":   round(similarity, 4),
        "new_words":    list(new_words)[:20],
        "removed_words":list(removed_words)[:10],
        "tag_diffs":    tag_diffs,
        "new_headers":  list(new_headers),
        "changed_headers": changed_headers,
        "interesting":  interesting_patterns,
        "confidence":   min(confidence, 100),
        "significant":  confidence >= 30,
    }


def build_probe_url(base_url: str, params: dict) -> str:
    """Add params to a URL, preserving existing query string."""
    parsed   = urllib.parse.urlparse(base_url)
    existing = dict(urllib.parse.parse_qsl(parsed.query))
    existing.update(params)
    new_qs   = urllib.parse.urlencode(existing)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))
