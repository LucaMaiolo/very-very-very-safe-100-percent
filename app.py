"""Class-project link redirector for Vercel + Supabase: allowlist, notice page, geo/ISP lookup,
coarse browser telemetry, password-protected /admin with per-visitor grouping and a map.
Local run: python3 app.py -> http://localhost:8000/r/demo (in-memory storage if Supabase isn't configured)."""
import hmac, html, ipaddress, json, os, re, secrets, sys, urllib.request
from datetime import datetime, timezone
from flask import Flask, Response, abort, request

# Only these destinations are reachable; no ?url= redirects (open-redirect hole).
LINKS = {"demo": "https://example.com"}
# Telemetry is limited to these coarse fields; anything else the client sends is dropped.
TELEM_FIELDS = ["timezone", "language", "screen", "viewport", "pixel_ratio"]

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
app.config["MAX_CONTENT_LENGTH"] = 2048  # telemetry payloads are tiny

# ---- storage: Supabase REST API, or in memory for local dev/tests -------------------------------
_mem = {"visits": [], "telemetry": []}

def _headers(extra=None):
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json", **(extra or {})}

def db_insert(table, row):
    if not SUPABASE_URL:
        _mem[table].append(row)
        return
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table}", data=json.dumps(row).encode(),
                                 method="POST", headers=_headers({"Prefer": "return=minimal"}))
    urllib.request.urlopen(req, timeout=5).close()

def db_select(table):
    if not SUPABASE_URL:
        return list(_mem[table])
    # shortcut: newest-agnostic cap of 5000 rows is plenty for a class demo; paginate beyond that
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{table}?select=*&order=time_utc.asc&limit=5000",
                                 headers=_headers())
    return json.load(urllib.request.urlopen(req, timeout=5))

def save(table, row):
    try:
        db_insert(table, row)
    except OSError as err:  # a logging failure must not break the visitor's page
        print(f"db insert into {table} failed: {err}", file=sys.stderr)

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
    g = geo(ip)
    save("visits", dict(id=vid, time_utc=ts, ip=ip, user_agent=ua, link=name, **g))
    return page(render(vid, dest, ip, g, ua, ts))

@app.post("/t")
def telemetry():
    raw = request.get_json(silent=True)
    t = clean_telemetry(raw)
    if t is None or not re.fullmatch(r"[0-9a-f]{8}", str(raw.get("id", ""))):
        abort(400)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save("telemetry", dict(visit_id=raw["id"], time_utc=ts, **t))
    return "", 204

# ---- admin: visits grouped by IP, telemetry joined, map -----------------------------------------
ADMIN = """<!doctype html><meta charset=utf-8><title>Admin</title>
<link rel=stylesheet href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css">
<h1>Admin</h1>
<p>Map pins are approximate (city level), based on IP address.</p>
<div id=map style="height:400px"></div>
__SECTIONS__
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
<script>
const pins = __PINS__;
const map = L.map("map").setView([20, 0], 2);
L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
  {attribution: "&copy; OpenStreetMap contributors", maxZoom: 18}).addTo(map);
pins.forEach(p => {
  const s = document.createElement("span");
  s.textContent = p.label;  // textContent: labels contain attacker-influenced strings
  L.marker([p.lat, p.lon]).addTo(map).bindPopup(s);
});
if (pins.length) map.fitBounds(pins.map(p => [p.lat, p.lon]), {maxZoom: 10});
</script>"""

def admin_html(visits, telem_rows):
    """One section per visitor IP: its visits joined with their telemetry, plus a map pin."""
    telem = {r["visit_id"]: r for r in telem_rows}
    groups = {}
    for v in visits:
        groups.setdefault(v["ip"], []).append(v)
    e = html.escape
    heads = ["time_utc", "link", "user_agent"] + TELEM_FIELDS
    pins, sections = [], []
    for ip, vs in sorted(groups.items()):
        v0 = vs[0]
        place = ", ".join(x for x in (v0["city"], v0["region"], v0["country"]) if x) or "unknown location"
        label = f"{ip} - {place} - {v0['isp'] or 'unknown ISP'} - {len(vs)} visit(s)"
        if v0["lat"] is not None:
            pins.append({"lat": v0["lat"], "lon": v0["lon"], "label": label})
        rows = ""
        for v in vs:
            t = telem.get(v["id"], {})
            cells = [v["time_utc"], v["link"], v["user_agent"]] + [t.get(k, "") for k in TELEM_FIELDS]
            rows += "<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in cells) + "</tr>"
        th = "".join(f"<th>{h}</th>" for h in heads)
        sections.append(f"<h3>{e(label)}</h3><table border=1><tr>{th}</tr>{rows}</table>")
    # "<" escaped so a value can't close the script tag
    pins_js = json.dumps(pins).replace("<", "\\u003c")
    return (ADMIN.replace("__SECTIONS__", "".join(sections) or "<p>No visits yet.</p>")
                 .replace("__PINS__", pins_js))

@app.get("/admin")
def admin():
    if not ADMIN_PASSWORD:
        abort(404)
    auth = request.authorization  # HTTP Basic; any username, password from ADMIN_PASSWORD
    if not auth or not hmac.compare_digest((auth.password or "").encode(), ADMIN_PASSWORD.encode()):
        return Response(status=401, headers={"WWW-Authenticate": 'Basic realm="admin"'})
    try:
        return page(admin_html(db_select("visits"), db_select("telemetry")))
    except OSError as err:
        print(f"db select failed: {err}", file=sys.stderr)
        abort(502)

if __name__ == "__main__":
    app.run(port=8000)
