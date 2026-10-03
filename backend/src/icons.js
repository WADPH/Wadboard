import fetch from "node-fetch";
import { error as logError } from "./logger.js";

// Remote (Iconify) icons are fetched by the server and served same-origin, so
// the browser CSP can stay at img-src/connect-src 'self' instead of trusting a
// third-party origin. It also means clients without direct internet access
// (and private-mode dashboards) still get their icons.
const ICONIFY_API = "https://api.iconify.design";
const REQUEST_TIMEOUT_MS = 5000;
const MAX_SVG_BYTES = 64 * 1024;
const MAX_SEARCH_BYTES = 256 * 1024;
const SEARCH_LIMIT = 120;
const MAX_QUERY_LENGTH = 100;

const SVG_TTL_MS = 24 * 60 * 60 * 1000;
const SVG_MISS_TTL_MS = 60 * 60 * 1000;
const SEARCH_TTL_MS = 10 * 60 * 1000;
const MAX_SVG_CACHE = 1000;
const MAX_SEARCH_CACHE = 200;

// Iconify naming rules: lowercase alphanumeric segments joined by single dashes.
// Restricting to this set keeps the upstream URL fixed to api.iconify.design.
const ICON_PART_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// Served SVGs live on our origin, so lock them down in case one is ever opened
// directly as a document: no scripts, no external loads.
const SVG_RESPONSE_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

export function parseIconName(value) {
  const raw = String(value || "").trim();
  if (raw.length > 128) return null;
  const parts = raw.split(":");
  if (parts.length !== 2) return null;
  const [prefix, name] = parts;
  if (!ICON_PART_RE.test(prefix) || !ICON_PART_RE.test(name)) return null;
  return { prefix, name, key: `${prefix}:${name}` };
}

function createTtlCache(maxEntries) {
  const map = new Map();
  return {
    get(key) {
      const entry = map.get(key);
      if (!entry) return undefined;
      if (entry.expires < Date.now()) {
        map.delete(key);
        return undefined;
      }
      // Refresh insertion order so the oldest-used entry is evicted first.
      map.delete(key);
      map.set(key, entry);
      return entry.value;
    },
    set(key, value, ttlMs) {
      map.delete(key);
      map.set(key, { value, expires: Date.now() + ttlMs });
      while (map.size > maxEntries) {
        map.delete(map.keys().next().value);
      }
    }
  };
}

export function createIconsModule() {
  const svgCache = createTtlCache(MAX_SVG_CACHE);
  const searchCache = createTtlCache(MAX_SEARCH_CACHE);
  const inFlight = new Map();

  // Concurrent requests for the same key (e.g. a dashboard with several
  // buttons using one icon) share a single upstream fetch.
  function dedupe(key, task) {
    if (inFlight.has(key)) return inFlight.get(key);
    const promise = task().finally(() => inFlight.delete(key));
    inFlight.set(key, promise);
    return promise;
  }

  async function fetchUpstream(url, maxBytes) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: "error",
        size: maxBytes,
        headers: { "User-Agent": "Wadboard" }
      });
      const body = res.ok ? await res.text() : "";
      return { status: res.status, contentType: res.headers.get("content-type") || "", body };
    } finally {
      clearTimeout(timer);
    }
  }

  async function getIconSvg(icon) {
    const cached = svgCache.get(icon.key);
    if (cached !== undefined) return cached;

    return dedupe("svg:" + icon.key, async () => {
      const url = `${ICONIFY_API}/${icon.prefix}/${icon.name}.svg`;
      const upstream = await fetchUpstream(url, MAX_SVG_BYTES);
      if (upstream.status === 404) {
        svgCache.set(icon.key, null, SVG_MISS_TTL_MS);
        return null;
      }
      const looksLikeSvg = upstream.contentType.includes("image/svg+xml")
        && /^\s*<svg[\s>]/i.test(upstream.body);
      if (upstream.status !== 200 || !looksLikeSvg) {
        throw new Error("iconify_bad_response_" + upstream.status);
      }
      svgCache.set(icon.key, upstream.body, SVG_TTL_MS);
      return upstream.body;
    });
  }

  async function searchIcons(query) {
    const cacheKey = query.toLowerCase();
    const cached = searchCache.get(cacheKey);
    if (cached !== undefined) return cached;

    return dedupe("search:" + cacheKey, async () => {
      const params = new URLSearchParams({ query, limit: String(SEARCH_LIMIT) });
      const upstream = await fetchUpstream(`${ICONIFY_API}/search?${params.toString()}`, MAX_SEARCH_BYTES);
      if (upstream.status !== 200) {
        throw new Error("iconify_bad_response_" + upstream.status);
      }
      const data = JSON.parse(upstream.body);
      const icons = (Array.isArray(data?.icons) ? data.icons : [])
        .map(parseIconName)
        .filter(Boolean)
        .map(icon => icon.key)
        .slice(0, SEARCH_LIMIT);
      searchCache.set(cacheKey, icons, SEARCH_TTL_MS);
      return icons;
    });
  }

  function registerRoutes(app, { authApi }) {
    const { requireAdmin, requireViewAccess } = authApi;

    // Icons decorate service/link/action buttons, so anyone who can view the
    // dashboard can load them.
    app.get("/api/icons/svg/:icon", requireViewAccess, async (req, res) => {
      const icon = parseIconName(req.params.icon);
      if (!icon) return res.status(400).json({ error: "invalid_icon" });
      try {
        const svg = await getIconSvg(icon);
        if (svg === null) return res.status(404).json({ error: "icon_not_found" });
        res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
        res.setHeader("Content-Security-Policy", SVG_RESPONSE_CSP);
        res.setHeader("Cache-Control", "private, max-age=86400");
        res.send(svg);
      } catch (err) {
        logError("Icon proxy error", { icon: icon.key, error: err && err.message });
        res.status(502).json({ error: "icon_unavailable" });
      }
    });

    // Search is only used by the icon picker in the admin editors.
    app.get("/api/icons/search", requireAdmin, async (req, res) => {
      const query = String(req.query.query || "").trim();
      if (!query) return res.json({ icons: [] });
      if (query.length > MAX_QUERY_LENGTH) return res.status(400).json({ error: "query_too_long" });
      try {
        const icons = await searchIcons(query);
        res.json({ icons });
      } catch (err) {
        logError("Icon search proxy error", { error: err && err.message });
        res.status(502).json({ error: "search_unavailable" });
      }
    });
  }

  return { registerRoutes };
}
