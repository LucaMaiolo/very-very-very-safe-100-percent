"""Class-project link redirector for Vercel + Supabase: allowlist, notice page, geo/ISP lookup,
coarse browser telemetry, bot flagging, password-protected /admin dashboard with one tab per
device (nameable, own map) plus a separate reviewed-on-demand bot tab.
Local run: python3 app.py -> http://localhost:8000/r/demo (in-memory storage if Supabase isn't configured)."""
import hmac, html, ipaddress, json, os, re, secrets, sys, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from flask import Flask, Response, abort, redirect, request

# Default short links. The admin can add links or change destinations from /admin (stored in the
# links table, which wins over these). Visitors can never choose a destination: no ?url= redirects
# (open-redirect hole).
LINKS = {"demo": "https://example.com"}
LINK_NAME_RE = re.compile(r"[a-z0-9-]{1,32}")
# Telemetry is limited to these coarse fields; anything else the client sends is dropped.
TELEM_FIELDS = ["timezone", "language", "screen", "viewport", "pixel_ratio"]
# UA substrings of known link-preview/crawler bots (Discord, Slack, social previews, search crawlers).
# This only labels a visit for the dashboard; nothing is hidden from these bots or treated differently
# when serving the page -- a real visitor can't be blocked by claiming to be one of these.
BOT_UA_RE = re.compile(
    r"bot|crawl|spider|facebookexternalhit|discordbot|slackbot|telegrambot|whatsapp|"
    r"skypeuripreview|redditbot|vkshare|embedly|outbrain|w3c_validator|applebot|bingpreview",
    re.I)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")  # service_role key: server-side only, never commit
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # unset = /admin disabled
# Vercel's proxy sets X-Forwarded-For to the real client IP. Elsewhere set TRUST_PROXY=1 only behind a
# proxy you control, because clients can fake the header otherwise.
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1" or bool(os.environ.get("VERCEL"))

if os.environ.get("VERCEL") and not (SUPABASE_URL and SUPABASE_KEY):
    # Vercel has no persistent disk; refuse to start rather than silently lose the logs.
    raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_KEY in the Vercel project settings")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2048  # telemetry / label payloads are tiny

# ---- storage: Supabase REST API, or in memory for local dev/tests -------------------------------
_mem = {"visits": [], "telemetry": [], "devices": {}, "links": {}}

def _headers(extra=None):
    h = {"apikey": SUPABASE_KEY, "Content-Type": "application/json", **(extra or {})}
    if SUPABASE_KEY.startswith("eyJ"):  # legacy JWT keys also go in Authorization; sb_secret_ keys must not
        h["Authorization"] = f"Bearer {SUPABASE_KEY}"
    return h

def db_insert(table, row):
    if not SUPABASE_URL:
        _mem[table].append(row)
        return
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table}", data=json.dumps(row).encode(),
                                 method="POST", headers=_headers({"Prefer": "return=minimal"}))
    urllib.request.urlopen(req, timeout=5).close()

def db_upsert_device(device_id, ts, label=None):
    """Create the device on first sight, bump last_seen on every visit, never clobber an existing label
    unless one is explicitly given (PostgREST upsert only overwrites the columns sent)."""
    if not SUPABASE_URL:
        d = _mem["devices"].setdefault(device_id, {"device_id": device_id, "label": None,
                                                    "first_seen": ts, "last_seen": ts})
        d["last_seen"] = ts
        if label is not None:
            d["label"] = label
        return
    row = {"device_id": device_id, "last_seen": ts}
    if label is not None:
        row["label"] = label
    req = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_id", data=json.dumps(row).encode(),
        method="POST", headers=_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))
    urllib.request.urlopen(req, timeout=5).close()

def db_select(table):
    if not SUPABASE_URL:
        return list(_mem[table].values()) if table in ("devices", "links") else list(_mem[table])
    # shortcut: cap of 5000 rows is plenty for a class demo; paginate beyond that
    order = {"devices": "first_seen", "links": "name"}.get(table, "time_utc")  # only visits/telemetry have time_utc
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table}?select=*&order={order}.asc&limit=5000",
                                 headers=_headers())
    return json.load(urllib.request.urlopen(req, timeout=5))

def db_upsert_link(name, url):
    if not SUPABASE_URL:
        _mem["links"][name] = {"name": name, "url": url}
        return
    req = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/links?on_conflict=name", data=json.dumps({"name": name, "url": url}).encode(),
        method="POST", headers=_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))
    urllib.request.urlopen(req, timeout=5).close()

def all_links():
    """Defaults merged with admin-set links (admin-set wins)."""
    return {**LINKS, **{r["name"]: r["url"] for r in db_select("links")}}

def link_dest(name):
    if not LINK_NAME_RE.fullmatch(name):
        return None
    try:
        if SUPABASE_URL:  # name is regex-checked above, so it's safe in the query string
            req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/links?select=url&name=eq.{name}",
                                         headers=_headers())
            rows = json.load(urllib.request.urlopen(req, timeout=5))
            if rows:
                return rows[0]["url"]
        elif name in _mem["links"]:
            return _mem["links"][name]["url"]
    except OSError as err:  # fall back to the defaults rather than break every link
        print(f"link lookup failed: {why(err)}", file=sys.stderr)
    return LINKS.get(name)

def valid_dest(url):
    """Only plain http(s) URLs with a host; no javascript:, data:, or control characters."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.hostname) and len(url) <= 500 and url.isprintable() \
        and " " not in url

def why(err):
    """Error text plus Supabase's own reason (which column/table/key it rejected), for the logs."""
    body = err.read(300).decode(errors="replace") if isinstance(err, urllib.error.HTTPError) else ""
    return f"{err} {body}".strip()

def save(table, row):
    try:
        db_insert(table, row)
    except OSError as err:  # a logging failure must not break the visitor's page
        print(f"db insert into {table} failed: {why(err)}", file=sys.stderr)

def touch_device(device_id, ts, label=None):
    try:
        db_upsert_device(device_id, ts, label)
    except OSError as err:
        print(f"device upsert failed: {why(err)}", file=sys.stderr)

# ---- geo / ISP ----------------------------------------------------------------------------------
_geo_cache = {}

def geo(ip):
    """Approximate location + ISP via ip-api.com (sends the IP to that service; disclosed on the notice).
    shortcut: free tier is HTTP-only and ~45 req/min; swap for offline GeoLite2 if hosting for many users."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    out = dict(country="", region="", city="", isp="", lat=None, lon=None)
    try:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("private/loopback address")
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon"
        d = json.load(urllib.request.urlopen(url, timeout=2))
        if d.get("status") == "success":
            out = dict(country=d["country"], region=d["regionName"], city=d["city"],
                       isp=d["isp"], lat=d["lat"], lon=d["lon"])
    except (ValueError, OSError):
        pass  # lookup is best-effort; never block the redirect
    _geo_cache[ip] = out
    return out

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if TRUST_PROXY and xff:
        return xff.split(",")[-1].strip()  # rightmost = the one our proxy added
    return request.remote_addr

def clean_telemetry(raw):
    """Keep only expected fields, as short strings."""
    return {k: str(raw.get(k, ""))[:60] for k in TELEM_FIELDS} if isinstance(raw, dict) else None

def page(body):
    return Response(body, mimetype="text/html", headers={"Cache-Control": "no-store"})

# ---- notice page --------------------------------------------------------------------------------
# Literal { and } are doubled because render() fills this with str.format.
NOTICE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5;url={dest}">
<title>Security class demo</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
         background: #111; color: #e8e8ea; font: 15px/1.55 system-ui, -apple-system, sans-serif; }}
  .box {{ max-width: 540px; width: 100%; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .lead {{ color: #a9a9b2; margin: 0 0 18px; }}
  ul {{ margin: 0 0 18px; padding-left: 18px; }}
  li {{ margin: 3px 0; }}
  .k {{ color: #8c8c95; }}
  .note {{ color: #a9a9b2; font-size: 13px; }}
  a {{ color: #4ea1ff; }}
</style>
</head>
<body>
  <div class="box">
    <h1>Security class demo</h1>
    <p class="lead">This is a university class project. Before forwarding you, this visit records:</p>
    <ul>
      <li><span class="k">IP address:</span> {ip}</li>
      <li><span class="k">Approximate location:</span> {place}</li>
      <li><span class="k">Internet provider:</span> {isp}</li>
      <li><span class="k">Browser:</span> {ua}</li>
      <li><span class="k">Time (UTC):</span> {ts}</li>
      <li>From your browser: time zone, language, screen and window size, pixel ratio</li>
      <li>A cookie that tells repeat visits from this browser apart from new ones</li>
    </ul>
    <p class="note">Your IP is sent to ip-api.com to look up the location and provider.
       Data is used only for the class demo and deleted after grading.</p>
    <p>Redirecting in <span id="n">5</span> seconds. <a href="{dest}">Continue now</a></p>
    <noscript><a href="{dest}">Continue</a></noscript>
  </div>
<script>
fetch("/t", {{method: "POST", keepalive: true, headers: {{"Content-Type": "application/json"}},
  body: JSON.stringify({{id: "{vid}", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language, screen: screen.width + "x" + screen.height,
    viewport: innerWidth + "x" + innerHeight, pixel_ratio: devicePixelRatio}})}});  // keepalive: survives the redirect
let n = 5, el = document.getElementById("n");
setInterval(() => {{ if (n > 0) el.textContent = --n; }}, 1000);
setTimeout(() => location.replace("{dest}"), 5000);
</script>
</body>
</html>
"""

def render(vid, dest, ip, g, ua, ts):
    # escape: the User-Agent header is attacker-controlled
    e = html.escape
    place = ", ".join(x for x in (g["city"], g["region"], g["country"]) if x) or "unknown"
    return NOTICE.format(vid=vid, dest=e(dest), ip=e(ip), place=e(place),
                         isp=e(g["isp"] or "unknown"), ua=e(ua), ts=ts)

@app.get("/r/<name>")
def redirect_page(name):
    dest = link_dest(name)
    if not dest:
        abort(404)
    ip, ua = client_ip(), request.headers.get("User-Agent", "")
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    vid = secrets.token_hex(4)  # joins this visit to its telemetry row
    device_id = request.cookies.get("device_id") or secrets.token_hex(16)
    g = geo(ip)
    is_bot = bool(BOT_UA_RE.search(ua))
    touch_device(device_id, ts)
    save("visits", dict(id=vid, time_utc=ts, ip=ip, device_id=device_id, is_bot=is_bot,
                        user_agent=ua, link=name, **g))
    resp = page(render(vid, dest, ip, g, ua, ts))
    # httponly: the cookie identifies a browser, not a page script's business; 400 days is Chrome's cap
    resp.set_cookie("device_id", device_id, max_age=400 * 24 * 3600, httponly=True, samesite="Lax")
    return resp

@app.post("/t")
def telemetry():
    raw = request.get_json(silent=True)
    t = clean_telemetry(raw)
    if t is None or not re.fullmatch(r"[0-9a-f]{8}", str(raw.get("id", ""))):
        abort(400)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save("telemetry", dict(visit_id=raw["id"], time_utc=ts, **t))
    return "", 204

# ---- admin: one tab per device (nameable, own map), plus a separate bot tab ----------------------
# Design notes (dashboard-design skill): screen question = "who opened my links, and which visits need
# a look?". KPI cards only report (no chart they drive). Explanations live in title= tooltips, not prose.
# Warn hue is used only for the bot review; everything healthy is ink/grey + one accent.
ADMIN = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Link visits</title>
<link rel=stylesheet href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css">
<style>
:root{--page:#f8f8f6;--card:#fff;--soft:#f1f1ef;--ink:#17171a;--ink2:#48484d;--muted:#66666d;
--line:rgb(0 0 0/.075);--line2:rgb(0 0 0/.14);--accent:#3e63dd;--warn:#c98a00;--live:#12a150;
--shadow:0 1px 2px rgb(0 0 0/.04),0 1px 1px rgb(0 0 0/.02);color-scheme:light dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--page:#0b0b0d;--card:#141417;--soft:#1c1c20;
--ink:#f3f3f5;--ink2:#c4c4ca;--muted:#8c8c95;--line:rgb(255 255 255/.08);--line2:rgb(255 255 255/.16);
--accent:#7b96ff;--warn:#f6b100}}
:root[data-theme=dark]{--page:#0b0b0d;--card:#141417;--soft:#1c1c20;--ink:#f3f3f5;--ink2:#c4c4ca;--muted:#8c8c95;
--line:rgb(255 255 255/.08);--line2:rgb(255 255 255/.16);--accent:#7b96ff;--warn:#f6b100}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,sans-serif}
.wrap{max-width:1640px;margin:0 auto;padding:24px}
.num{font-variant-numeric:tabular-nums}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:20px;font-weight:600;margin:0;letter-spacing:-.01em}
.pill{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 12px;border:1px solid var(--line);
border-radius:999px;background:var(--card);color:var(--ink2);font-size:13px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--live)}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:16px}
.kpi{padding:18px 20px}
.kpi .lbl{color:var(--ink2);font-size:13px}
.kpi .val{font-size:30px;font-weight:600;letter-spacing:-.03em;margin:4px 0 2px}
.kpi .sub{color:var(--muted);font-size:13px}
.kpi.warn .val{color:var(--warn)}
.main{display:grid;grid-template-columns:300px minmax(0,1fr);gap:16px;align-items:start}
.list{padding:8px}
.list h2,.panel h2{font-size:13px;font-weight:500;color:var(--muted);margin:8px 10px}
.item{all:unset;box-sizing:border-box;display:flex;align-items:center;gap:10px;width:100%;padding:8px 10px;
border-radius:12px;cursor:pointer}
.item:hover{background:var(--soft)}
.item:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.item.active{background:color-mix(in srgb,var(--accent) 7%,transparent);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--accent) 22%,transparent)}
.av{flex:none;width:30px;height:30px;border-radius:9px;display:grid;place-items:center;font-size:12px;font-weight:500;
background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent)}
.item.bot .av{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.it{min-width:0;flex:1}
.it .nm{display:block;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.it .ds{display:block;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ago{color:var(--muted);font-size:12px;flex:none}
.chip{flex:none;font-size:12px;font-weight:500;padding:1px 8px;border-radius:999px;
background:color-mix(in srgb,var(--warn) 22%,transparent);color:var(--ink)}
.sep{height:1px;background:var(--line);margin:6px 10px}
.side{display:grid;gap:16px}
.lf{display:flex;flex-wrap:wrap;gap:6px;padding:8px 10px}
.lf input{flex:1 1 100%;min-width:0;font:13px system-ui,sans-serif;height:32px;padding:0 10px;border:1px solid var(--line2);
border-radius:8px;background:var(--card);color:var(--ink)}
.lf input[name=slug]{flex:1 1 100px}
.lf input:focus{outline:2px solid var(--accent);outline-offset:-1px}
.panel{display:none;padding:20px}
.panel.active{display:block}
.ph{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.ph input{font:600 18px system-ui,sans-serif;color:var(--ink);background:transparent;border:1px solid transparent;
border-radius:8px;padding:4px 8px;margin-left:-8px;min-width:0;width:22ch}
.ph input:hover,.ph input:focus{border-color:var(--line2);outline:none}
.ph .ttl{font-size:18px;font-weight:600}
.btn{font:500 13px system-ui,sans-serif;height:30px;padding:0 12px;border-radius:8px;border:1px solid var(--line2);
background:var(--card);color:var(--ink);cursor:pointer}
.btn:hover{background:var(--soft)}
.saved{color:var(--muted);font-size:12px}
.facts{color:var(--muted);font-size:13px;margin:6px 0 14px}
.facts b{color:var(--ink2);font-weight:500}
.map{height:300px;border-radius:12px;border:1px solid var(--line);margin-bottom:16px;z-index:0}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font-weight:500;color:var(--muted);padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap;color:var(--ink2)}
td.t{color:var(--muted)}
td.ua{max-width:240px;overflow:hidden;text-overflow:ellipsis}
tr:last-child td{border-bottom:0}
.empty{padding:48px 24px;text-align:center;color:var(--muted)}
.empty code{color:var(--ink);background:var(--soft);padding:2px 6px;border-radius:6px}
@media (max-width:1100px){.kpis{grid-template-columns:repeat(2,1fr)}.main{grid-template-columns:minmax(0,1fr)}
.list{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:2px}.list h2,.sep,.lf{grid-column:1/-1}}
@media (max-width:480px){.wrap{padding:16px}.kpi{padding:14px 16px}.kpi .val{font-size:24px}.panel{padding:16px}
.ago{display:none}.map{height:220px}}
</style>
<div class=wrap>
<header><h1>Link visits</h1>
<span class=pill title="Rendered when this page loaded. Reload for new visits."><span class=dot></span>Updated __NOW__ UTC</span></header>
__BODY__
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
<script>
const maps = __MAPS__;
function showTab(id) {
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + id));
  document.querySelectorAll(".item[data-id]").forEach(b => {
    b.classList.toggle("active", b.dataset.id === id);
    b.setAttribute("aria-selected", b.dataset.id === id);
  });
  const pins = maps[id];
  if (pins && pins.length && !pins._map) {
    const m = L.map("map-" + id).setView([pins[0].lat, pins[0].lon], 10);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      {attribution: "&copy; OpenStreetMap contributors", maxZoom: 18}).addTo(m);
    pins.forEach(p => {
      const s = document.createElement("span");
      s.textContent = p.label;  // textContent: labels contain attacker-influenced strings
      L.circleMarker([p.lat, p.lon], {radius: 7, weight: 2, color: "#3e63dd", fillOpacity: .35}).addTo(m).bindPopup(s);
    });
    if (pins.length > 1) m.fitBounds(pins.map(p => [p.lat, p.lon]), {maxZoom: 12, padding: [24, 24]});
    pins._map = m;
  } else if (pins && pins._map) {
    pins._map.invalidateSize();
  }
}
async function rename(id) {
  const label = document.getElementById("label-" + id).value.trim();
  const note = document.getElementById("saved-" + id);
  const r = await fetch("/admin/label", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_id: id, label})});
  note.textContent = r.ok ? "Saved" : "Not saved";
  if (r.ok) document.querySelector("#tabbtn-" + id + " .nm").textContent = label || "Device " + id.slice(0, 8);
}
document.querySelectorAll(".item[data-id]").forEach(b => b.addEventListener("click", () => showTab(b.dataset.id)));
document.querySelectorAll(".ph input").forEach(i => i.addEventListener("keydown", ev => {
  if (ev.key === "Enter") rename(i.dataset.id);
}));
function pickLink(b) {
  const f = document.querySelector(".lf");
  f.slug.value = b.dataset.name; f.dest.value = b.dataset.url; f.dest.focus();
}
async function saveLink(ev) {
  ev.preventDefault();
  const f = ev.target;
  const r = await fetch("/admin/link", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name: f.slug.value.trim().toLowerCase(), url: f.dest.value.trim()})});
  if (r.ok) location.reload(); else document.getElementById("link-note").textContent = "Not saved";
}
const first = document.querySelector(".item[data-id]");
if (first) showTab(first.dataset.id);
</script>"""

def _device_label(dev, device_id):
    return dev.get("label") or f"Device {device_id[:8]}"

def _ts(s):
    return datetime.fromisoformat(s)

def _ago(s, now):
    secs = int((now - _ts(s)).total_seconds())
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            return f"{secs // n}{unit} ago"
    return "just now"

def _short_time(s):
    return _ts(s).strftime("%b %d %H:%M")

def _place(v):
    return ", ".join(x for x in (v.get("city"), v.get("country")) if x)

def _panel(title, device_id, visits, telem, now, raw_label=""):
    """One device's (or the bot group's) detail panel: name, facts line, map, visit table.
    raw_label=None means not renamable (the bot group)."""
    e = html.escape
    visits = sorted(visits, key=lambda v: v["time_utc"], reverse=True)
    heads = ["Time (UTC)", "IP", "Place", "Provider", "Link", "Browser", "Time zone", "Language", "Screen",
             "Window", "Ratio"]
    rows, pins, seen = "", [], set()
    for v in visits:
        t = telem.get(v["id"], {})
        cells = [f'<td class=t title="{e(v["time_utc"])}">{e(_short_time(v["time_utc"]))}</td>',
                 f'<td>{e(v["ip"])}</td>', f'<td>{e(_place(v) or "—")}</td>', f'<td>{e(v.get("isp") or "—")}</td>',
                 f'<td>{e(v["link"])}</td>', f'<td class=ua title="{e(v["user_agent"])}">{e(v["user_agent"] or "—")}</td>']
        cells += [f"<td>{e(str(t.get(k) or '—'))}</td>" for k in TELEM_FIELDS]  # — = page script never reported
        rows += "<tr>" + "".join(cells) + "</tr>"
        if v.get("lat") is not None and (v["lat"], v["lon"]) not in seen:
            seen.add((v["lat"], v["lon"]))
            place = ", ".join(x for x in (v["city"], v["region"], v["country"]) if x) or "unknown location"
            pins.append({"lat": v["lat"], "lon": v["lon"], "label": f"{v['ip']} - {place}"})
    did = e(device_id)
    if raw_label is not None:
        head = (f'<input id="label-{did}" data-id="{did}" value="{e(raw_label)}" placeholder="{e(title)}" '
                f'aria-label="Device name" maxlength=60 title="Name this device">'
                f'<button class=btn onclick="rename(\'{did}\')">Save name</button><span class=saved id="saved-{did}"></span>')
    else:
        head = (f'<span class=ttl>{e(title)}</span><span class=chip title="Flagged by User-Agent string '
                f'(Discord/Slack/search-crawler style). A hint, not proof: a real visitor could send a matching '
                f'header and a bot a non-matching one. Nothing here is auto-trusted or discarded.">review</span>')
    places = {_place(v) for v in visits if _place(v)}
    ips = {v["ip"] for v in visits}
    n = len(visits)
    facts = (f'<b class=num>{n}</b> visit{"s" if n != 1 else ""} · <b class=num>{len(ips)}</b> IP{"s" if len(ips) != 1 else ""}'
             f' · <b class=num>{len(places)}</b> place{"s" if len(places) != 1 else ""}'
             f' · first <span title="{e(visits[-1]["time_utc"])}">{e(_short_time(visits[-1]["time_utc"]))}</span>'
             f' · last <span title="{e(visits[0]["time_utc"])}">{e(_ago(visits[0]["time_utc"], now))}</span>')
    map_div = (f'<div id="map-{did}" class="map" title="Approximate (city level), from IP address"></div>'
               if pins else "")
    th = "".join(f"<th>{h}</th>" for h in heads)
    html_out = (f'<div class=ph>{head}</div><div class=facts>{facts}</div>{map_div}'
                f'<div class=tw><table><tr>{th}</tr>{rows}</table></div>')
    return html_out, pins

def _item(item_id, title, sub, ago, bot=False, count=0):
    e = html.escape
    initials = "".join(w[0] for w in title.split()[:2]).upper() or "?"
    right = f'<span class=chip>{count}</span>' if bot else f'<span class=ago>{e(ago)}</span>'
    return (f'<button class="item{" bot" if bot else ""}" role=tab id="tabbtn-{e(item_id)}" data-id="{e(item_id)}">'
            f'<span class=av>{"!" if bot else e(initials)}</span>'
            f'<span class=it><span class=nm>{e(title)}</span><span class=ds>{e(sub)}</span></span>{right}</button>')

def _links_card(links):
    e = html.escape
    rows = "".join(f'<button type=button class=item onclick="pickLink(this)" data-name="{e(n)}" data-url="{e(u)}" '
                   f'title="Edit"><span class=it><span class=nm>/r/{e(n)}</span>'
                   f'<span class=ds title="{e(u)}">{e(u)}</span></span></button>' for n, u in sorted(links.items()))
    return (f'<div class="card list"><h2 title="Pick a link to change where it goes, or type a new name to add one">'
            f'Links</h2>{rows}<form class=lf onsubmit="saveLink(event)">'
            '<input name=slug placeholder="name" required pattern="[a-z0-9\\-]{1,32}" maxlength=32 '
            'title="Lowercase letters, digits and dashes" aria-label="Link name">'
            '<button class=btn>Save</button>'
            '<input name=dest type=url placeholder="https://destination" required maxlength=500 aria-label="Destination URL">'
            '<span class=saved id=link-note></span></form></div>')

def admin_html(devices, visits, telem_rows, now=None, links=None):
    now = now or datetime.now(timezone.utc)
    links = LINKS if links is None else links
    telem = {r["visit_id"]: r for r in telem_rows}
    by_device, bots = {}, []
    for v in visits:
        (bots if v.get("is_bot") else by_device.setdefault(v.get("device_id") or "unknown", [])).append(v)
    dev_by_id = {d["device_id"]: d for d in devices}
    e = html.escape
    head = ADMIN.replace("__NOW__", now.strftime("%H:%M"))

    if not visits:
        names = " ".join(f"<code>/r/{e(k)}</code>" for k in links)
        body = (f'<section class=main><div class=side>{_links_card(links)}</div>'
                f'<div class="card empty">No visits yet. Open a link to log the first one: {names}</div></section>')
        return head.replace("__BODY__", body).replace("__MAPS__", "{}")

    # order real devices by their most recent visit, newest first
    last = {d: max(v["time_utc"] for v in vs) for d, vs in by_device.items()}
    order = sorted(by_device, key=last.get, reverse=True)
    items, panels, maps = [], [], {}
    for device_id in order:
        dev, vs = dev_by_id.get(device_id, {}), by_device[device_id]
        title = _device_label(dev, device_id)
        panel_html, pins = _panel(title, device_id, vs, telem, now, raw_label=dev.get("label") or "")
        place = _place(max(vs, key=lambda v: v["time_utc"]))
        sub = f"{len(vs)} visit{'s' if len(vs) != 1 else ''}" + (f" · {place}" if place else "")
        items.append(_item(device_id, title, sub, _ago(last[device_id], now)))
        panels.append(f'<div class="card panel" role=tabpanel id="panel-{e(device_id)}">{panel_html}</div>')
        maps[device_id] = pins
    if bots:
        panel_html, pins = _panel("Possible bots", "bots", bots, telem, now, raw_label=None)
        items.append('<div class=sep></div>' + _item("bots", f"Possible bots ({len(bots)})", "flagged by browser string",
                                                    "", bot=True, count=len(bots)))
        panels.append(f'<div class="card panel" role=tabpanel id="panel-bots">{panel_html}</div>')
        maps["bots"] = pins

    named = sum(1 for d in by_device if dev_by_id.get(d, {}).get("label"))
    human = len(visits) - len(bots)
    newest = max(v["time_utc"] for v in visits)
    today = sum(1 for v in visits if _ts(v["time_utc"]).date() == now.date())
    kpis = [
        ("Visits", len(visits), f"{today} today", "", "All logged visits, bots included"),
        ("Devices", len(by_device), f"{named} named", "", "Distinct browsers, by device cookie; bot visits excluded"),
        ("Possible bots", len(bots), f"of {len(visits)} visits", "warn" if bots else "",
         "Visits whose User-Agent matches a known link-preview or crawler bot. Review them in their tab."),
        ("Last visit", _ago(newest, now), _short_time(newest) + " UTC", "", f"{human} visits from real devices"),
    ]
    kpi_html = "".join(f'<div class="card kpi {cls}" title="{e(tip)}"><div class=lbl>{lbl}</div>'
                       f'<div class="val num">{e(str(val))}</div><div class=sub>{e(sub)}</div></div>'
                       for lbl, val, sub, cls, tip in kpis)
    body = (f'<section class=kpis>{kpi_html}</section><section class=main>'
            f'<div class=side><nav class="card list" role=tablist aria-label=Devices><h2>Devices</h2>{"".join(items)}</nav>'
            f'{_links_card(links)}</div>'
            f'<div>{"".join(panels)}</div></section>')
    maps_js = json.dumps(maps).replace("<", "\\u003c")  # "<" escaped so a value can't close the script tag
    return head.replace("__BODY__", body).replace("__MAPS__", maps_js)

def admin_auth_ok():
    if not ADMIN_PASSWORD:
        return False
    auth = request.authorization  # HTTP Basic; any username, password from ADMIN_PASSWORD
    return bool(auth) and hmac.compare_digest((auth.password or "").encode(), ADMIN_PASSWORD.encode())

@app.get("/admin")
def admin():
    if not ADMIN_PASSWORD:
        abort(404)
    if not admin_auth_ok():
        return Response(status=401, headers={"WWW-Authenticate": 'Basic realm="admin"'})
    try:
        return page(admin_html(db_select("devices"), db_select("visits"), db_select("telemetry"),
                               links=all_links()))
    except OSError as err:
        print(f"db select failed: {why(err)}", file=sys.stderr)
        abort(502)

@app.post("/admin/link")
def admin_link():
    """Add a short link or change where one goes. Admin-only, so the allowlist still holds."""
    if not admin_auth_ok():
        abort(401)
    data = request.get_json(silent=True) or {}
    name, url = str(data.get("name", "")).strip().lower(), str(data.get("url", "")).strip()
    if not LINK_NAME_RE.fullmatch(name) or not valid_dest(url):
        abort(400)
    try:
        db_upsert_link(name, url)
    except OSError as err:
        print(f"link upsert failed: {why(err)}", file=sys.stderr)
        abort(502)
    return "", 204

@app.post("/admin/label")
def admin_label():
    if not admin_auth_ok():
        abort(401)
    data = request.get_json(silent=True) or {}
    device_id, label = str(data.get("device_id", "")), str(data.get("label", ""))[:60]
    if not re.fullmatch(r"[0-9a-f]{32}", device_id):
        abort(400)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    touch_device(device_id, ts, label=label or None)
    return "", 204

if __name__ == "__main__":
    app.run(port=8000)
