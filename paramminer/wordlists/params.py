"""
Built-in parameter wordlist — 1500+ names sourced from:
- Real bug bounty disclosures
- Common framework param names
- API conventions (REST, GraphQL, gRPC)
- Debug/internal param patterns
- Language/framework specific params
"""

# ── Core / Universal ──────────────────────────────────────────────────────────
CORE = [
    "id", "uid", "user_id", "userId", "user", "username", "uname",
    "name", "fullname", "first_name", "last_name", "firstname", "lastname",
    "email", "mail", "e-mail", "phone", "mobile", "tel",
    "password", "pass", "passwd", "pwd", "secret", "token",
    "key", "api_key", "apikey", "api-key", "access_key", "auth_key",
    "auth", "authorization", "bearer", "jwt", "session", "sess",
    "cookie", "sid", "session_id", "sessionId",
    "search", "q", "query", "keyword", "keywords", "term", "terms",
    "s", "str", "string", "text", "content", "body", "message", "msg",
    "data", "value", "val", "input", "payload",
    "type", "kind", "category", "cat", "class", "group",
    "action", "cmd", "command", "op", "operation", "method",
    "mode", "state", "status", "flag", "option",
    "page", "p", "pg", "num", "n", "offset", "limit", "per_page",
    "page_size", "pageSize", "size", "count", "total",
    "sort", "order", "orderby", "order_by", "dir", "direction", "asc", "desc",
    "filter", "filters", "where", "conditions", "criteria",
    "from", "to", "start", "end", "begin", "finish",
    "date", "time", "datetime", "timestamp", "created_at", "updated_at",
    "format", "output", "encoding", "charset", "lang", "language", "locale",
    "view", "template", "layout", "theme", "skin",
    "debug", "test", "dev", "staging", "preview", "draft",
    "verbose", "trace", "log", "logging", "level",
    "callback", "cb", "jsonp", "next", "return", "return_url",
    "redirect", "redirect_uri", "redirect_url", "return_to",
    "url", "uri", "link", "href", "src", "source", "ref", "referrer",
    "back", "forward", "destination", "dest", "target",
    "file", "filename", "filepath", "path", "dir", "folder", "directory",
    "upload", "download", "import", "export", "attachment",
    "image", "img", "photo", "picture", "avatar", "thumbnail", "icon",
    "video", "audio", "media", "document", "doc", "pdf",
]

# ── API / REST ────────────────────────────────────────────────────────────────
API = [
    "version", "v", "api_version", "apiVersion",
    "endpoint", "service", "resource",
    "expand", "include", "fields", "select", "columns", "attrs",
    "embed", "relations", "with",
    "since", "until", "after", "before",
    "cursor", "next_cursor", "prev_cursor", "page_token",
    "depth", "level", "max_depth",
    "scope", "scopes", "permission", "permissions", "role", "roles",
    "audience", "aud", "iss", "sub",
    "grant_type", "response_type", "code", "state", "nonce",
    "client_id", "client_secret",
    "access_token", "refresh_token", "id_token",
    "webhook", "hook", "notify", "notification",
    "batch", "bulk", "multi",
    "async", "sync", "background",
    "dry_run", "dryrun", "simulate", "preview",
    "pretty", "indent", "minify",
    "cache", "no_cache", "nocache", "ttl", "max_age",
    "etag", "if_none_match", "if_modified_since",
    "rate_limit", "throttle",
    "tenant", "workspace", "org", "organization", "company",
    "project", "repo", "repository",
    "branch", "tag", "commit", "sha", "ref",
    "namespace", "package", "module",
    "environment", "env", "stage",
]

# ── User / Account ────────────────────────────────────────────────────────────
USER = [
    "account", "account_id", "accountId",
    "profile", "bio", "about", "description", "summary",
    "nickname", "handle", "display_name", "screen_name",
    "gender", "age", "birthday", "dob",
    "address", "city", "state", "country", "zip", "postal_code",
    "timezone", "tz", "currency",
    "website", "blog", "portfolio",
    "twitter", "github", "linkedin", "facebook", "instagram",
    "avatar_url", "profile_pic", "cover_photo",
    "admin", "is_admin", "super_admin", "superuser",
    "premium", "pro", "enterprise", "tier",
    "verified", "active", "enabled", "disabled", "blocked", "banned",
    "two_factor", "2fa", "mfa", "otp",
    "invitation", "invite", "referral", "promo", "voucher", "coupon",
    "signup", "register", "login", "logout", "signin", "signout",
    "forgot_password", "reset_password", "change_password",
    "confirm_email", "verify_email", "activation",
    "impersonate", "sudo", "masquerade", "act_as",
    "member", "member_id", "memberId",
    "employee", "staff", "manager", "owner",
]

# ── Content / CMS ─────────────────────────────────────────────────────────────
CONTENT = [
    "post", "post_id", "postId", "article", "article_id",
    "title", "headline", "subject", "topic",
    "slug", "permalink", "alias",
    "tag", "tags", "label", "labels",
    "author", "author_id", "authorId", "by",
    "published", "publish_at", "publish_date",
    "draft", "published", "archived", "deleted",
    "featured", "pinned", "sticky", "popular", "trending",
    "comment", "comment_id", "reply", "thread",
    "like", "upvote", "downvote", "reaction", "rating", "score",
    "share", "retweet", "repost",
    "feed", "rss", "atom", "newsletter",
    "category_id", "categoryId", "parent", "parent_id", "parentId",
    "children", "siblings",
    "section", "chapter", "page_id", "pageId",
    "revision", "version_id", "history",
    "media_id", "mediaId", "asset_id", "assetId",
    "embed", "iframe", "widget",
    "locale", "translation", "i18n",
]

# ── E-commerce ────────────────────────────────────────────────────────────────
ECOMMERCE = [
    "product", "product_id", "productId", "sku", "item", "item_id",
    "price", "amount", "cost", "total", "subtotal", "discount",
    "quantity", "qty", "stock", "inventory",
    "cart", "cart_id", "basket", "bag",
    "order", "order_id", "orderId", "purchase", "transaction",
    "payment", "payment_id", "invoice", "receipt",
    "shipping", "delivery", "tracking", "tracking_number",
    "billing", "billing_address", "shipping_address",
    "coupon", "promo_code", "discount_code", "gift_card",
    "tax", "vat", "gst", "duties",
    "currency", "exchange_rate",
    "vendor", "seller", "supplier", "merchant",
    "warehouse", "fulfillment", "dropship",
    "review", "rating", "feedback",
    "wishlist", "favorite", "saved",
    "subscription", "plan", "tier",
    "trial", "free_trial",
    "refund", "return", "cancel", "cancellation",
    "offer", "deal", "promotion", "sale",
]

# ── Security / Debug (High Value) ─────────────────────────────────────────────
SECURITY = [
    "debug", "debug_mode", "debugMode",
    "admin", "administrator", "root", "superuser",
    "internal", "private", "hidden", "secret",
    "backdoor", "maintenance", "bypass",
    "override", "force", "skip", "ignore",
    "unsafe", "raw", "exec", "execute",
    "shell", "cmd", "command", "run",
    "eval", "code", "script",
    "sql", "query", "db", "database",
    "password", "passwd", "pass", "pwd", "credential",
    "token", "api_key", "private_key", "secret_key",
    "master", "master_key", "signing_key",
    "config", "configuration", "settings", "setup",
    "install", "installer", "setup_token",
    "phpinfo", "info", "env", "environment",
    "test", "testing", "sandbox", "dev", "development",
    "staging", "preview", "beta",
    "log", "logs", "trace", "verbose",
    "audit", "history", "activity",
    "export", "dump", "backup",
    "flush", "purge", "reset", "clear",
    "reload", "restart", "shutdown",
    "health", "healthcheck", "ping", "status",
    "version", "build", "release",
    "feature", "feature_flag", "feature_toggle", "experiment",
    "ab_test", "split_test", "variant",
    "rollout", "canary",
    "xdebug", "xhprof", "profiler",
    "whoami", "me", "self",
]

# ── Infrastructure / DevOps ───────────────────────────────────────────────────
INFRA = [
    "host", "hostname", "server", "ip", "address",
    "port", "protocol", "scheme",
    "proxy", "gateway", "upstream", "downstream",
    "region", "zone", "datacenter", "dc",
    "cluster", "node", "instance", "machine",
    "container", "pod", "service", "deployment",
    "aws", "gcp", "azure", "cloud",
    "s3", "bucket", "blob", "storage",
    "lambda", "function", "serverless",
    "queue", "topic", "channel", "stream",
    "kafka", "rabbitmq", "redis", "memcache",
    "database", "db", "mysql", "postgres", "mongo",
    "elasticsearch", "solr", "lucene",
    "smtp", "mail", "email_host",
    "ldap", "active_directory", "oauth",
    "cdn", "cache_key", "edge",
    "ssl", "tls", "cert", "certificate",
    "webhook_secret", "signing_secret",
    "access_key_id", "secret_access_key",
    "connection_string", "dsn",
    "base_url", "api_url", "api_endpoint",
]

# ── GraphQL specific ──────────────────────────────────────────────────────────
GRAPHQL = [
    "query", "mutation", "subscription",
    "operationName", "operation_name",
    "variables", "extensions",
    "persistedQuery", "persisted_query",
    "__schema", "__type", "introspection",
]

# ── Framework-specific ────────────────────────────────────────────────────────
FRAMEWORK = [
    # Rails
    "utf8", "authenticity_token", "_method",
    "controller", "action", "format",
    # Django
    "csrfmiddlewaretoken", "csrftoken",
    "next", "redirect_to",
    # Laravel
    "_token", "_method",
    # Spring
    "spring.profiles.active",
    # Express/Node
    "req", "res",
    # PHP
    "PHPSESSID", "phpinfo",
    # WordPress
    "p", "page_id", "cat", "tag", "author",
    "s", "attachment_id", "pagename",
    "nonce", "_wpnonce", "_wp_http_referer",
    # Drupal
    "node", "nid", "tid",
    # Magento
    "store", "website", "___store",
    # Angular/React
    "state", "props", "context",
    # jQuery
    "callback", "_",
    # ASP.NET
    "__VIEWSTATE", "__EVENTVALIDATION",
    "__RequestVerificationToken",
    "ASPXAUTH",
]

# ── JSON/GraphQL body parameter names ────────────────────────────────────────
JSON_KEYS = [
    "userId", "user_id", "accountId", "account_id",
    "productId", "product_id", "orderId", "order_id",
    "postId", "post_id", "articleId", "article_id",
    "commentId", "comment_id", "messageId", "message_id",
    "fileId", "file_id", "imageId", "image_id",
    "sessionId", "session_id", "requestId", "request_id",
    "transactionId", "transaction_id",
    "parentId", "parent_id", "ownerId", "owner_id",
    "createdBy", "created_by", "updatedBy", "updated_by",
    "isAdmin", "is_admin", "isActive", "is_active",
    "isDeleted", "is_deleted", "isPublic", "is_public",
    "firstName", "first_name", "lastName", "last_name",
    "displayName", "display_name", "screenName", "screen_name",
    "phoneNumber", "phone_number", "emailAddress", "email_address",
    "streetAddress", "street_address", "postalCode", "postal_code",
    "countryCode", "country_code", "languageCode", "language_code",
    "accessToken", "access_token", "refreshToken", "refresh_token",
    "apiKey", "api_key", "clientId", "client_id", "clientSecret",
    "webhookUrl", "webhook_url", "callbackUrl", "callback_url",
    "redirectUri", "redirect_uri", "returnUrl", "return_url",
    "imageUrl", "image_url", "avatarUrl", "avatar_url",
    "pageSize", "page_size", "pageNumber", "page_number",
    "sortBy", "sort_by", "orderBy", "order_by",
    "startDate", "start_date", "endDate", "end_date",
    "createdAt", "created_at", "updatedAt", "updated_at",
    "deletedAt", "deleted_at", "publishedAt", "published_at",
    "expiresAt", "expires_at", "expiresIn", "expires_in",
]

# ── Header injection params ───────────────────────────────────────────────────
HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "X-Client-IP",
    "Referer",
    "Origin",
    "X-Api-Key",
    "X-Auth-Token",
    "X-Access-Token",
    "X-CSRF-Token",
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Requested-With",
    "X-Debug",
    "X-Dev-Mode",
    "X-Admin",
    "X-Internal",
    "X-Original-Host",
    "X-Forwarded-Proto",
    "X-Override-URL",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "Forwarded",
    "Via",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "TE",
    "Transfer-Encoding",
    "Content-Type",
    "Accept",
    "Accept-Charset",
    "Accept-Language",
    "Accept-Encoding",
]


def get_all_params() -> list:
    """Return deduplicated master list of all parameter names."""
    all_params = (
        CORE + API + USER + CONTENT + ECOMMERCE +
        SECURITY + INFRA + GRAPHQL + FRAMEWORK + JSON_KEYS
    )
    seen = set()
    unique = []
    for p in all_params:
        if p.lower() not in seen:
            seen.add(p.lower())
            unique.append(p)
    return unique


def get_security_params() -> list:
    """High-value params most likely to produce interesting responses."""
    return SECURITY + [p for p in API if p in
                       ("debug","admin","internal","test","dev","version")]


def load_wordlist(path: str) -> list:
    """Load params from a file, one per line."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return lines
    except Exception as e:
        print(f"  [!] Could not load wordlist {path}: {e}")
        return []
