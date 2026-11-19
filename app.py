"""Class-project link redirector for Vercel + Supabase: allowlist, notice page, geo/ISP lookup,
coarse browser telemetry, bot flagging, password-protected /admin dashboard with one tab per
device (nameable, own map) plus a separate reviewed-on-demand bot tab.
Local run: python3 app.py -> http://localhost:8000/r/demo (in-memory storage if Supabase isn't configured)."""
import hmac, html, ipaddress, json, os, re, secrets, sys, urllib.request
from datetime import datetime, timezone
from flask import Flask, Response, abort, redirect, request

# Only these destinations are reachable; no ?url= redirects (open-redirect hole).
LINKS = {"demo": "https://example.com"}
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
_mem = {"visits": [], "telemetry": [], "devices": {}}

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
        return list(_mem[table].values()) if table == "devices" else list(_mem[table])
    # shortcut: cap of 5000 rows is plenty for a class demo; paginate beyond that
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table}?select=*&order=time_utc.asc&limit=5000",
                                 headers=_headers())
    return json.load(urllib.request.urlopen(req, timeout=5))

def save(table, row):
    try:
        db_insert(table, row)
    except OSError as err:  # a logging failure must not break the visitor's page
        print(f"db insert into {table} failed: {err}", file=sys.stderr)

def touch_device(device_id, ts, label=None):
    try:
        db_upsert_device(device_id, ts, label)
    except OSError as err:
        print(f"device upsert failed: {err}", file=sys.stderr)

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
NOTICE = """<!doctype html><meta charset=utf-8>
<meta http-equiv="refresh" content="5;url={dest}">
<title>Security class demo</title>
<h1>Security class demo</h1>
<p>This is a university class project. This visit records:</p>
<ul>
<li>IP: {ip}</li>
<li>Approximate location: {place}</li>
<li>Internet provider: {isp}</li>
<li>Browser: {ua}</li>
<li>Time (UTC): {ts}</li>
<li>From your browser: time zone, language, screen and window size, pixel ratio</li>
<li>A cookie that lets us tell repeat visits from this browser apart from new ones</li>
</ul>
<p>Your IP is sent to ip-api.com to look up the location and provider. Data is used only for the class demo and deleted after grading.</p>
<p>Redirecting in 5 seconds. <a href="{dest}">Go now</a></p>
<script>
fetch("/t", {{method: "POST", keepalive: true, headers: {{"Content-Type": "application/json"}},
  body: JSON.stringify({{id: "{vid}", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language, screen: screen.width + "x" + screen.height,
    viewport: innerWidth + "x" + innerHeight, pixel_ratio: devicePixelRatio}})}});
</script>"""

def render(vid, dest, ip, g, ua, ts):
    # escape: the User-Agent header is attacker-controlled
    e = html.escape
    place = ", ".join(x for x in (g["city"], g["region"], g["country"]) if x) or "unknown"
    return NOTICE.format(vid=vid, dest=e(dest), ip=e(ip), place=e(place),
                         isp=e(g["isp"] or "unknown"), ua=e(ua), ts=ts)

@app.get("/r/<name>")
def redirect_page(name):
    dest = LINKS.get(name)
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
ADMIN = """<!doctype html><meta charset=utf-8><title>Admin</title>
<link rel=stylesheet href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css">
<style>
body{font-family:system-ui,sans-serif;margin:1.5rem}
.tabs{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:1rem}
.tabs button{padding:.4rem .8rem;cursor:pointer}
.tabs button.active{font-weight:bold;background:#222;color:#fff}
.tabs button.bot{border-color:#b33}
.panel{display:none}
.panel.active{display:block}
.map{height:280px;margin:.5rem 0}
table{border-collapse:collapse;margin-top:.5rem}
td,th{border:1px solid #ccc;padding:.25rem .5rem;font-size:.9rem}
</style>
<h1>Admin</h1>
<p>Each tab is one device (by browser cookie). Map pins are approximate (city level), from IP address.
The "Possible bots" tab holds visits whose browser string matches a known link-preview/crawler bot --
review it yourself; nothing there is auto-trusted or auto-discarded.</p>
<div class="tabs">__TABS__</div>
__PANELS__
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
<script>
const maps = __MAPS__;
function showTab(id) {
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + id));
  document.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("active", b.dataset.id === id));
  const pins = maps[id];
  if (pins && pins.length && !pins._map) {
    const m = L.map("map-" + id).setView([pins[0].lat, pins[0].lon], 10);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      {attribution: "&copy; OpenStreetMap contributors", maxZoom: 18}).addTo(m);
    pins.forEach(p => {
      const s = document.createElement("span");
      s.textContent = p.label;  // textContent: labels contain attacker-influenced strings
      L.marker([p.lat, p.lon]).addTo(m).bindPopup(s);
    });
    if (pins.length > 1) m.fitBounds(pins.map(p => [p.lat, p.lon]), {maxZoom: 12});
    pins._map = m;
  } else if (pins && pins._map) {
    pins._map.invalidateSize();
  }
}
async function rename(id) {
  const label = document.getElementById("label-" + id).value;
  await fetch("/admin/label", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_id: id, label})});
  document.getElementById("tabbtn-" + id).textContent = label || id;
}
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.id)));
const first = document.querySelector(".tabs button");
if (first) showTab(first.dataset.id);
</script>"""

def _device_label(dev, device_id):
    return dev.get("label") or f"Device {device_id[:8]}"

def _panel(title, device_id, visits, telem, extra_note="", raw_label=""):
    e = html.escape
    heads = ["time_utc", "ip", "link", "user_agent"] + TELEM_FIELDS
    th = "".join(f"<th>{h}</th>" for h in heads)
    rows = ""
    pins, seen = [], set()
    for v in sorted(visits, key=lambda v: v["time_utc"], reverse=True):
        t = telem.get(v["id"], {})
        cells = [v["time_utc"], v["ip"], v["link"], v["user_agent"]] + [t.get(k, "") for k in TELEM_FIELDS]
        rows += "<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in cells) + "</tr>"
        if v.get("lat") is not None and (v["lat"], v["lon"]) not in seen:
            seen.add((v["lat"], v["lon"]))
            place = ", ".join(x for x in (v["city"], v["region"], v["country"]) if x) or "unknown location"
            pins.append({"lat": v["lat"], "lon": v["lon"], "label": f"{v['ip']} - {place}"})
    rename_box = (f'<p><input id="label-{e(device_id)}" placeholder="name this device" '
                 f'value="{e(raw_label)}">'
                 f' <button onclick="rename(\'{e(device_id)}\')">Save name</button></p>') if raw_label is not None else ""
    map_div = f'<div id="map-{e(device_id or "bots")}" class="map"></div>' if pins else "<p>No located visits.</p>"
    html_out = (f"<h2>{e(title)}</h2>{extra_note}{rename_box}{map_div}"
               f"<table><tr>{th}</tr>{rows}</table>")
    return html_out, pins

def admin_html(devices, visits, telem_rows):
    telem = {r["visit_id"]: r for r in telem_rows}
    by_device, bots = {}, []
    for v in visits:
        (bots if v.get("is_bot") else by_device.setdefault(v.get("device_id") or "unknown", [])).append(v)
    dev_by_id = {d["device_id"]: d for d in devices}
    e = html.escape

    # order real devices by their most recent visit, newest first
    order = sorted(by_device, key=lambda d: max(v["time_utc"] for v in by_device[d]), reverse=True)
    tabs, panels, maps = [], [], {}
    for device_id in order:
        dev = dev_by_id.get(device_id, {})
        title = _device_label(dev, device_id)
        panel_html, pins = _panel(title, device_id, by_device[device_id], telem, raw_label=dev.get("label") or "")
        tabs.append(f'<button id="tabbtn-{e(device_id)}" data-id="{e(device_id)}">{e(title)}</button>')
        panels.append(f'<div class="panel" id="panel-{e(device_id)}">{panel_html}</div>')
        maps[device_id] = pins

    if bots:
        panel_html, pins = _panel("Possible bots", "bots", bots, telem, raw_label=None,
                                  extra_note="<p>Flagged by User-Agent string (Discord/Slack/search-crawler "
                                  "style). Check before trusting -- a real visitor could in theory send a "
                                  "matching header, and a bot could send a non-matching one.</p>")
        tabs.append('<button id="tabbtn-bots" class="bot" data-id="bots">&#9888; Possible bots '
                    f'({len(bots)})</button>')
        panels.append(f'<div class="panel" id="panel-bots">{panel_html}</div>')
        maps["bots"] = pins

    if not tabs:
        return ADMIN.replace("__TABS__", "").replace("__PANELS__", "<p>No visits yet.</p>").replace("__MAPS__", "{}")
    maps_js = json.dumps(maps).replace("<", "\\u003c")  # "<" escaped so a value can't close the script tag
    return (ADMIN.replace("__TABS__", "".join(tabs))
                 .replace("__PANELS__", "".join(panels))
                 .replace("__MAPS__", maps_js))

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
        return page(admin_html(db_select("devices"), db_select("visits"), db_select("telemetry")))
    except OSError as err:
        print(f"db select failed: {err}", file=sys.stderr)
        abort(502)

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
