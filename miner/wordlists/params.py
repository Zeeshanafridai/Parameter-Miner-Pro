"""
Built-in parameter wordlist — curated from real bug bounty targets.
Organized by category for smart ordering (highest-value first).
"""

# ── Hidden / Debug Parameters (highest value) ────────────────────────────────
DEBUG_PARAMS = [
    "debug", "test", "dev", "development", "staging", "preview",
    "verbose", "trace", "log", "logging", "logger",
    "admin", "administrator", "superuser", "root", "su",
    "internal", "private", "secret", "hidden",
    "show_errors", "display_errors", "error_reporting",
    "show_debug", "debug_mode", "debug_level",
    "profiler", "profile", "benchmark",
    "cache", "cache_debug", "nocache", "no_cache", "cache_bypass",
    "bypass", "skip", "override", "force",
    "maintenance", "maint", "offline",
    "beta", "alpha", "canary", "experiment", "feature",
    "flag", "feature_flag", "toggle",
    "raw", "dump", "inspect", "show",
    "sql", "query", "db", "database",
    "pretty", "pretty_print", "format",
    "jsonp", "callback", "cb",
    "wsdl", "wadl", "swagger", "openapi",
    "env", "environment", "config", "configuration",
    "version", "api_version", "v", "ver",
    "_debug", "_test", "_dev", "_admin", "_internal",
    "__debug__", "__test__", "_profiler",
]

# ── Security / Auth Bypass Parameters ────────────────────────────────────────
AUTH_PARAMS = [
    "token", "access_token", "auth_token", "bearer_token",
    "api_key", "apikey", "api-key", "key",
    "secret", "secret_key", "app_secret",
    "password", "passwd", "pass", "pwd",
    "auth", "authenticate", "authorization",
    "session", "session_id", "sessionid", "sess",
    "cookie", "user_token", "refresh_token",
    "jwt", "id_token",
    "username", "user", "userid", "user_id", "uid",
    "email", "login", "account",
    "role", "roles", "permission", "permissions", "scope",
    "admin_key", "admin_token", "super_token",
    "signature", "sig", "sign", "hmac", "hash",
    "nonce", "timestamp", "expires", "expiry",
    "code", "otp", "pin", "verification_code",
    "invite", "invite_code", "referral", "referral_code",
]

# ── Redirect / URL Parameters (SSRF / Open Redirect) ─────────────────────────
URL_PARAMS = [
    "url", "uri", "href", "src", "link", "source",
    "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "returnto", "return_url",
    "next", "next_url", "forward", "forward_to",
    "target", "destination", "dest", "to",
    "location", "goto", "go",
    "back", "back_url", "backurl",
    "ref", "referrer", "referer",
    "continue", "cont",
    "from", "from_url",
    "open", "navigate",
    "callback", "cb", "webhook",
    "feed", "rss", "atom",
    "fetch", "load", "import", "include",
    "proxy", "endpoint", "service",
    "page", "view", "template",
    "file", "path", "dir", "folder",
    "image", "img", "avatar", "photo",
    "pdf", "doc", "document",
    "export", "download",
]

# ── Injection / SQLi Parameters ───────────────────────────────────────────────
INJECTION_PARAMS = [
    "id", "user_id", "userid", "uid", "pid",
    "item_id", "itemid", "product_id", "productid",
    "order_id", "orderid", "transaction_id",
    "account_id", "profile_id", "post_id", "comment_id",
    "parent_id", "category_id", "tag_id", "group_id",
    "type", "kind", "class", "mode",
    "action", "method", "cmd", "command", "exec",
    "run", "do", "task", "job", "function",
    "query", "search", "q", "s", "keyword", "term", "find",
    "filter", "where", "condition", "criteria",
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "dir", "direction", "asc", "desc",
    "field", "column", "col",
    "table", "from", "join",
    "limit", "offset", "page", "per_page", "pagesize", "count",
    "start", "end", "begin", "stop",
    "name", "title", "label", "slug",
    "value", "val", "data", "content", "body", "text", "message",
]

# ── Header Injection Parameters ───────────────────────────────────────────────
HEADER_PARAMS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "Referer",
    "Origin",
    "Host",
    "X-Host",
    "X-Forwarded-Proto",
    "X-Forwarded-Server",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Override",
    "Content-Type",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "User-Agent",
    "Authorization",
    "X-Api-Key",
    "X-Auth-Token",
    "X-CSRF-Token",
    "X-Requested-With",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-Debug",
    "X-Dev-Mode",
    "X-Internal",
    "X-Admin",
    "X-Role",
    "X-User-ID",
    "X-Tenant-ID",
    "X-Correlation-ID",
    "X-Request-ID",
    "X-Trace-ID",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "Via",
    "Forwarded",
    "Proxy-Authorization",
    "X-Proxy-Authorization",
]

# ── Cache Poisoning Parameters ─────────────────────────────────────────────────
CACHE_PARAMS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "Forwarded",
    "X-Forwarded-For",
    "X-Cache-Key",
    "X-Cache-Hash",
    "Pragma",
    "Cache-Control",
    "X-Cache-Control",
    "Surrogate-Control",
    "CDN-Loop",
    "X-Amz-Cf-Id",
    "X-Varnish",
    "X-Cache",
]

# ── Miscellaneous useful params ────────────────────────────────────────────────
MISC_PARAMS = [
    "lang", "language", "locale", "region", "country", "timezone",
    "currency", "unit", "metric",
    "theme", "skin", "style", "layout", "view",
    "mobile", "desktop", "responsive",
    "print", "pdf", "export",
    "width", "height", "size", "dimension",
    "quality", "compression", "thumbnail",
    "rotate", "crop", "resize", "convert",
    "color", "colour", "palette",
    "font", "charset", "encoding",
    "output", "render", "display",
    "expand", "collapse", "toggle",
    "show", "hide", "visible",
    "enable", "disable", "active",
    "new", "old", "current", "previous", "next",
    "first", "last", "latest", "recent",
    "hot", "trending", "popular", "featured",
    "related", "similar", "recommended",
    "tags", "tag", "category", "cat", "section",
    "year", "month", "day", "date", "time",
    "created", "updated", "modified",
    "status", "state", "phase",
    "priority", "weight", "score", "rank",
    "public", "private", "draft", "published",
    "approved", "pending", "rejected",
    "read", "unread", "seen", "unseen",
    "like", "vote", "rate", "rating",
    "follow", "subscribe", "notify",
    "share", "embed", "iframe",
    "width", "cols", "rows",
    "indent", "wrap", "newline",
    "_", "__", "undefined", "null", "true", "false",
    "0", "1", "-1",
]

# ── JSON body parameter names ──────────────────────────────────────────────────
JSON_PARAMS = [
    "adminMode", "debugMode", "isAdmin", "isDebug", "isDev",
    "showHidden", "includeInternal", "bypassCache",
    "forceRefresh", "skipValidation", "noLimit",
    "superUser", "elevated", "privileged",
    "rawOutput", "verbose", "trace",
    "userId", "accountId", "tenantId", "orgId",
    "overrideRole", "impersonate", "actAs",
    "testMode", "dryRun", "preview",
    "legacyMode", "compatMode", "v1Mode",
    "betaFeatures", "experimentalFeatures",
    "unlockAll", "fullAccess", "unrestricted",
    "internal", "_internal", "__internal",
    "sudo", "root", "superadmin",
]

# Combined and deduplicated
ALL_PARAMS = list(dict.fromkeys(
    DEBUG_PARAMS + AUTH_PARAMS + URL_PARAMS +
    INJECTION_PARAMS + MISC_PARAMS + JSON_PARAMS
))

# ── Extended wordlist from common web frameworks ───────────────────────────────
FRAMEWORK_PARAMS = {
    "rails": [
        "authenticity_token", "utf8", "_method",
        "commit", "controller", "action",
        "format", "locale", "page", "per_page",
    ],
    "django": [
        "csrfmiddlewaretoken", "next", "this_is_the_login_form",
        "_auth_user_id", "_auth_user_backend",
    ],
    "spring": [
        "_csrf", "_method", "X-CSRF-TOKEN",
        "org.springframework", "javax.faces",
    ],
    "laravel": [
        "_token", "_method", "remember_token",
        "api_token", "sanctum",
    ],
    "express": [
        "_csrf", "connect.sid", "__proto__",
        "constructor", "prototype",
    ],
    "wordpress": [
        "nonce", "wp_nonce", "action", "post_id",
        "comment_post_ID", "wp-json",
    ],
}

ALL_HEADERS = list(dict.fromkeys(HEADER_PARAMS + CACHE_PARAMS + [
    "X-Debug","X-Debug-Mode","X-Dev","X-Dev-Mode","X-Internal","X-Private",
    "X-Admin","X-Super-Admin","X-Role","X-User-Role","X-User-ID",
    "X-Authenticated-User","X-Bypass-Auth","X-Remote-User",
    "X-HTTP-Method-Override","X-Method-Override","X-HTTP-Method",
    "X-Api-Version","X-API-Version","API-Version","Accept-Version",
    "X-Tenant-ID","X-Organization-ID","X-Feature-Flag","X-Beta",
]))

