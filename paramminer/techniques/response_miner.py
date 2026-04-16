"""
Response Mining Engine
------------------------
Extracts parameter names from:
  - JavaScript source files (variables, objects, API calls)
  - HTML forms (input names, select names)
  - JSON API responses (key names)
  - Source code comments
  - GraphQL introspection
  - Swagger/OpenAPI specs
  - Sitemap / robots.txt links
  - Browser storage keys (localStorage patterns)

This is what makes us find params that no wordlist has.
"""

import re
import json
import urllib.request
import urllib.parse
import ssl

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


def _fetch(url: str, timeout: int = 10) -> str:
    """Fetch URL content."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX)
        )
        with opener.open(req, timeout=timeout) as resp:
            return resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_from_html(html: str) -> list:
    """Extract parameter names from HTML form inputs, links, data attributes."""
    params = set()

    # Form input names
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # Select names
    for m in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # Textarea names
    for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # Button names
    for m in re.finditer(r'<button[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # URL params in href/action/src
    for m in re.finditer(r'(?:href|action|src|data-url)=["\']([^"\']*\?[^"\']+)["\']', html, re.I):
        url_part = m.group(1)
        if "?" in url_part:
            qs = url_part.split("?", 1)[1].split("#")[0]
            for pair in qs.split("&"):
                if "=" in pair:
                    params.add(pair.split("=")[0])

    # data-* attributes
    for m in re.finditer(r'data-([a-z][a-z0-9-]{1,30})', html, re.I):
        params.add(m.group(1).replace("-", "_"))

    # Hidden inputs
    for m in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # Meta tags with params
    for m in re.finditer(r'<meta[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))

    # CSRF tokens
    for m in re.finditer(r'(?:csrf|token|nonce)[_-]?(?:token|key|value)=["\']([^"\']+)["\']', html, re.I):
        pass  # value not name, but note pattern

    return [p for p in params if 1 < len(p) < 60 and not p.startswith("_")]


def extract_from_javascript(js: str) -> list:
    """Extract parameter names from JavaScript source."""
    params = set()

    # Object key patterns: {param: ..., param2: ...}
    for m in re.finditer(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']:\s*["\'\d\[\{]', js):
        params.add(m.group(1))

    # Unquoted object keys: {param: value}
    for m in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*:', js):
        params.add(m.group(1))

    # fetch/axios/XMLHttpRequest params
    for m in re.finditer(
        r'(?:fetch|axios|get|post|put|patch|delete)\s*\(\s*["\'][^"\']*\?([^"\']+)["\']',
        js, re.I
    ):
        qs = m.group(1)
        for pair in qs.split("&"):
            if "=" in pair:
                params.add(pair.split("=")[0])

    # URLSearchParams
    for m in re.finditer(r'(?:append|set|get)\s*\(\s*["\']([^"\']{1,40})["\']', js):
        params.add(m.group(1))

    # formData.append
    for m in re.finditer(r'formData\.append\s*\(\s*["\']([^"\']{1,40})["\']', js):
        params.add(m.group(1))

    # $.ajax / jQuery params
    for m in re.finditer(r'data:\s*\{([^}]{0,500})\}', js):
        inner = m.group(1)
        for km in re.finditer(r'["\']?([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']?\s*:', inner):
            params.add(km.group(1))

    # Variable assignments that look like params
    for m in re.finditer(r'(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]{2,25})\s*=', js):
        params.add(m.group(1))

    # String literals that look like API parameters
    for m in re.finditer(r'["\']([a-z][a-z0-9_]{2,30})["\']', js):
        name = m.group(1)
        if "_" in name or name.islower():
            params.add(name)

    # API path placeholders: /api/users/{userId}
    for m in re.finditer(r'\{([a-zA-Z_][a-zA-Z0-9_]{1,30})\}', js):
        params.add(m.group(1))

    # Comments that mention params
    for m in re.finditer(r'//.*?@param\s+\{?\w+\}?\s+([a-zA-Z_]\w{1,30})', js):
        params.add(m.group(1))

    return [p for p in params if 2 < len(p) < 50
            and not p.startswith("_")
            and not p[0].isupper()  # skip class names
            and p not in {"function", "return", "const", "let", "var",
                          "true", "false", "null", "undefined", "typeof",
                          "instanceof", "this", "new", "class", "import",
                          "export", "from", "default", "extends"}]


def extract_from_json(json_str: str) -> list:
    """Extract key names from JSON response recursively."""
    params = set()

    def _walk(obj, depth=0):
        if depth > 5:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and 1 < len(k) < 60:
                    params.add(k)
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:10]:  # limit iteration
                _walk(item, depth + 1)

    try:
        data = json.loads(json_str)
        _walk(data)
    except Exception:
        # Try to extract keys from raw JSON-like text
        for m in re.finditer(r'"([a-zA-Z_][a-zA-Z0-9_]{1,40})":', json_str):
            params.add(m.group(1))

    return [p for p in params if 1 < len(p) < 60]


def extract_from_swagger(swagger_json: str) -> list:
    """Extract parameter names from Swagger/OpenAPI spec."""
    params = set()
    try:
        spec = json.loads(swagger_json)
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            # Extract path params
            for m in re.finditer(r'\{([^}]+)\}', path):
                params.add(m.group(1))

            for method, details in methods.items():
                if isinstance(details, dict):
                    # Query/header/path params
                    for param in details.get("parameters", []):
                        if isinstance(param, dict) and param.get("name"):
                            params.add(param["name"])

                    # Request body
                    body = details.get("requestBody", {})
                    content = body.get("content", {})
                    for ct, schema_wrap in content.items():
                        schema = schema_wrap.get("schema", {})
                        props = schema.get("properties", {})
                        params.update(props.keys())
    except Exception:
        pass
    return list(params)


def extract_from_graphql_schema(schema_str: str) -> list:
    """Extract field names from GraphQL schema."""
    params = set()
    # Field names
    for m in re.finditer(r'^\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*:', schema_str, re.M):
        params.add(m.group(1))
    # Argument names
    for m in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', schema_str):
        params.add(m.group(1))
    return [p for p in params if 1 < len(p) < 60]


def mine_js_files(base_url: str, html: str, verbose: bool = True) -> list:
    """Find and mine all JS files linked from the page."""
    params = set()

    # Extract JS file URLs
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        src = m.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            src = f"{parsed.scheme}://{parsed.netloc}{src}"
        elif not src.startswith("http"):
            src = base_url.rstrip("/") + "/" + src
        js_urls.add(src)

    if verbose and js_urls:
        print(f"  {C}[JS MINING]{RST} Found {len(js_urls)} JS files to analyze")

    for js_url in list(js_urls)[:15]:  # limit to 15 files
        content = _fetch(js_url)
        if content:
            extracted = extract_from_javascript(content)
            params.update(extracted)
            if verbose:
                print(f"  {DIM}  → {js_url[-60:]}: {len(extracted)} params{RST}")

    return list(params)


def mine_api_docs(base_url: str, verbose: bool = True) -> list:
    """Try common API doc endpoints for param extraction."""
    params = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    doc_paths = [
        "/swagger.json", "/swagger.yaml", "/api-docs",
        "/api/swagger.json", "/v1/swagger.json", "/v2/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/api/openapi.json",
        "/graphql",  # introspection
        "/.well-known/api",
    ]

    for path in doc_paths:
        content = _fetch(f"{origin}{path}")
        if not content:
            continue

        if "swagger" in content.lower() or "openapi" in content.lower() or '"paths"' in content:
            extracted = extract_from_swagger(content)
            if extracted:
                params.extend(extracted)
                if verbose:
                    print(f"  {G}[API DOCS]{RST} Found spec at {path} → {len(extracted)} params")

        if '"__schema"' in content or "types" in content.lower():
            extracted = extract_from_graphql_schema(content)
            if extracted:
                params.extend(extracted)
                if verbose:
                    print(f"  {G}[GRAPHQL]{RST} Schema at {path} → {len(extracted)} params")

    return list(set(params))


def mine_all(url: str, html: str, json_body: str = "",
             verbose: bool = True) -> list:
    """
    Full mining pipeline — HTML + JS files + JSON + API docs.
    Returns deduplicated param list.
    """
    all_params = set()

    if verbose:
        print(f"\n  {C}[RESPONSE MINING]{RST} Extracting params from page content...")

    # HTML
    html_params = extract_from_html(html)
    all_params.update(html_params)
    if verbose and html_params:
        print(f"  {DIM}  HTML forms/inputs: {len(html_params)} params{RST}")

    # JSON response
    if json_body:
        json_params = extract_from_json(json_body)
        all_params.update(json_params)
        if verbose and json_params:
            print(f"  {DIM}  JSON keys: {len(json_params)} params{RST}")

    # JS files
    js_params = mine_js_files(url, html, verbose)
    all_params.update(js_params)

    # API docs
    api_params = mine_api_docs(url, verbose)
    all_params.update(api_params)

    # Filter noise
    filtered = [p for p in all_params
                if 1 < len(p) < 60
                and re.match(r'^[a-zA-Z_][a-zA-Z0-9_.\-\[\]]*$', p)]

    if verbose:
        print(f"  {G}[+]{RST} Total mined from responses: {len(filtered)} unique params\n")

    return sorted(set(filtered))
