"""
Core HTTP engine with deep response diffing.
The entire tool depends on accurately detecting when a parameter
causes a meaningful response difference vs baseline noise.
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
import gzip
import zlib
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

# Parameters that are always reflected back — useful for confirming
CANARY_VALUE = "z33x7k9q"


def request(url: str, method: str = "GET",
            params: dict = None, data: dict = None,
            json_body: dict = None, headers: dict = None,
            cookies: str = None, raw_body: str = None,
            timeout: int = 15) -> dict:
    """
    Full HTTP request returning rich metadata for diffing.
    """
    req_headers = {
        "User-Agent":      DEFAULT_UA,
        "Accept":          "text/html,application/json,*/*;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control":   "no-cache",
        "Connection":      "keep-alive",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    target_url = url
    if params:
        qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        sep = "&" if "?" in url else "?"
        target_url = f"{url}{sep}{qs}"

    body_bytes = None
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode()
        req_headers["Content-Type"] = "application/json"
    elif data is not None:
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw_body:
        body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body

    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            target_url, data=body_bytes,
            headers=req_headers, method=method.upper()
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX)
        )
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}

            # Decompress if needed
            raw = resp.read(1024 * 512)
            encoding = resp_headers.get("content-encoding", "")
            if "gzip" in encoding:
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            elif "deflate" in encoding:
                try:
                    raw = zlib.decompress(raw)
                except Exception:
                    pass

            body = raw.decode("utf-8", errors="replace")
            return _build(resp.status, resp_headers, body, elapsed, target_url, None)

    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        resp_headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return _build(e.code, resp_headers, body, elapsed, target_url, str(e))

    except Exception as e:
        elapsed = time.perf_counter() - start
        return _build(0, {}, "", elapsed, target_url, str(e))


def _build(status, headers, body, elapsed, url, error):
    body_lower = body.lower()

    # Count structural elements
    tag_counts = {
        "input":    body_lower.count("<input"),
        "form":     body_lower.count("<form"),
        "table":    body_lower.count("<table"),
        "tr":       body_lower.count("<tr"),
        "div":      body_lower.count("<div"),
        "span":     body_lower.count("<span"),
        "script":   body_lower.count("<script"),
        "error":    body_lower.count("error"),
        "warning":  body_lower.count("warning"),
        "invalid":  body_lower.count("invalid"),
        "undefined":body_lower.count("undefined"),
        "null":     body_lower.count("null"),
        "debug":    body_lower.count("debug"),
    }

    # Check for interesting patterns in body
    interesting = {
        "has_canary":    CANARY_VALUE in body,
        "has_stack":     bool(re.search(r"at line \d+|stack trace|traceback", body_lower)),
        "has_debug":     bool(re.search(r"debug|verbose|dev.mode|development", body_lower)),
        "has_internal":  bool(re.search(r"internal server|10\.\d+|192\.168|172\.(1[6-9]|2[0-9]|3[01])\.", body)),
        "has_path":      bool(re.search(r"[/\\](?:var|usr|home|etc|opt|app|srv)[/\\]", body)),
        "has_json_key":  bool(re.search(r'"[a-z_]{3,30}":', body)),
    }

    # Word count for diff sensitivity
    words = len(body.split())

    return {
        "status":       status,
        "headers":      headers,
        "body":         body,
        "body_hash":    hashlib.md5(body.encode()).hexdigest(),
        "body_length":  len(body),
        "word_count":   words,
        "elapsed":      round(elapsed, 3),
        "url":          url,
        "error":        error,
        "content_type": headers.get("content-type", ""),
        "server":       headers.get("server", ""),
        "tag_counts":   tag_counts,
        "interesting":  interesting,
        "redirect_loc": headers.get("location", ""),
    }


class ResponseDiff:
    """
    Deep diff engine between baseline and test response.
    Calculates a confidence score that a parameter is real.
    """

    def __init__(self, baseline: dict, test: dict, canary: str = CANARY_VALUE):
        self.baseline = baseline
        self.test     = test
        self.canary   = canary

        # Core metrics
        self.status_changed  = baseline["status"] != test["status"]
        self.same_hash       = baseline["body_hash"] == test["body_hash"]
        self.size_diff       = test["body_length"] - baseline["body_length"]
        self.size_pct        = abs(self.size_diff) / max(baseline["body_length"], 1) * 100
        self.word_diff       = abs(test["word_count"] - baseline["word_count"])
        self.time_diff       = abs(test["elapsed"] - baseline["elapsed"])
        self.redirect_changed = baseline["redirect_loc"] != test["redirect_loc"]

        # Text similarity
        self.similarity = difflib.SequenceMatcher(
            None,
            baseline["body"][:8000],
            test["body"][:8000],
            autojunk=False
        ).ratio()

        # Tag count diffs
        self.tag_diffs = {
            k: test["tag_counts"].get(k, 0) - baseline["tag_counts"].get(k, 0)
            for k in baseline["tag_counts"]
            if test["tag_counts"].get(k, 0) != baseline["tag_counts"].get(k, 0)
        }

        # Canary reflection
        self.canary_reflected = canary in test["body"] and canary not in baseline["body"]

        # Interesting new content
        self.new_interesting = {
            k: v for k, v in test["interesting"].items()
            if v and not baseline["interesting"].get(k)
        }

    def score(self) -> int:
        """
        Calculate confidence score 0-100 that this parameter exists.
        Higher = more confident the param affects the response.
        """
        s = 0

        # Canary reflected = near certain
        if self.canary_reflected:
            s += 60

        # Status code changed
        if self.status_changed:
            s += 30

        # Redirect destination changed
        if self.redirect_changed:
            s += 25

        # Meaningful size difference (not noise)
        if self.size_pct > 5 and abs(self.size_diff) > 20:
            s += 20
        elif self.size_pct > 2 and abs(self.size_diff) > 10:
            s += 10

        # Similarity drop
        if self.similarity < 0.80:
            s += 25
        elif self.similarity < 0.90:
            s += 15
        elif self.similarity < 0.95:
            s += 8

        # Word count changed significantly
        if self.word_diff > 20:
            s += 10
        elif self.word_diff > 5:
            s += 5

        # Tag structure changed
        if self.tag_diffs:
            s += min(len(self.tag_diffs) * 5, 15)

        # New interesting content appeared
        if self.new_interesting:
            s += min(len(self.new_interesting) * 8, 20)

        # Error/debug content appeared
        if self.tag_diffs.get("error", 0) > 0:
            s += 15
        if self.tag_diffs.get("debug", 0) > 0:
            s += 10

        return min(s, 100)

    def is_significant(self, threshold: int = 25) -> bool:
        return self.score() >= threshold

    def summary(self) -> dict:
        return {
            "score":           self.score(),
            "status_changed":  self.status_changed,
            "same_hash":       self.same_hash,
            "size_diff":       self.size_diff,
            "size_pct":        round(self.size_pct, 1),
            "similarity":      round(self.similarity, 3),
            "word_diff":       self.word_diff,
            "canary_reflected":self.canary_reflected,
            "tag_diffs":       self.tag_diffs,
            "new_interesting": self.new_interesting,
            "redirect_changed":self.redirect_changed,
        }


def get_stable_baseline(url: str, method: str = "GET",
                          headers: dict = None, cookies: str = None,
                          data: dict = None, samples: int = 3) -> dict:
    """
    Take multiple baseline samples and return the most stable one.
    Helps eliminate transient differences.
    """
    responses = []
    for _ in range(samples):
        resp = request(url, method=method, headers=headers,
                        cookies=cookies, data=data)
        if resp["status"] > 0:
            responses.append(resp)
        time.sleep(0.1)

    if not responses:
        return request(url, method=method, headers=headers,
                        cookies=cookies, data=data)

    # Return the median-length response (most stable)
    responses.sort(key=lambda r: r["body_length"])
    return responses[len(responses) // 2]
