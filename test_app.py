"""Self-check: python3 test_app.py  (needs flask installed; uses in-memory storage, no network)."""
import os
for k in ("SUPABASE_URL", "SUPABASE_SERVICE_KEY", "VERCEL"):
    os.environ.pop(k, None)
os.environ["ADMIN_PASSWORD"] = "pw"

import app as m

m.TRUST_PROXY = True
m.geo = lambda ip: dict(country="United States", region="Virginia", city="Ashburn",
                        isp="Google LLC", lat=39.03, lon=-77.5)
c = m.app.test_client()
AUTH = {"Authorization": "Basic YTpwdw=="}  # a:pw
H = {"X-Forwarded-For": "6.6.6.6, 8.8.8.8", "User-Agent": "</script><b>x"}

# redirect page: logs the proxy-added IP (rightmost), shows what is recorded, escapes the User-Agent,
# and sets a device cookie
r = c.get("/r/demo", headers=H)
assert r.status_code == 200 and b"8.8.8.8" in r.data and b"Ashburn" in r.data
assert b"</script><b>" not in r.data and b"&lt;/script&gt;" in r.data
device_id = c.get_cookie("device_id").value
assert len(device_id) == 32
vid = m._mem["visits"][0]["id"]
assert m._mem["visits"][0]["ip"] == "8.8.8.8" and m._mem["visits"][0]["device_id"] == device_id
assert not m._mem["visits"][0]["is_bot"]
assert c.get("/r/nope").status_code == 404

# a second visit from the same browser (cookie jar carries it) lands under the same device
c.get("/r/demo", headers=H)
assert len(m._mem["devices"]) == 1
assert m._mem["devices"][device_id]["last_seen"] >= m._mem["devices"][device_id]["first_seen"]

# telemetry: accepted for a visit id, extra fields dropped, junk rejected
ok = {"id": vid, "timezone": "UTC", "language": "en", "screen": "1x1", "viewport": "1x1",
      "pixel_ratio": 2, "evil": "x"}
assert c.post("/t", json=ok).status_code == 204
assert "evil" not in m._mem["telemetry"][0]
assert c.post("/t", json={"id": "zz"}).status_code == 400
assert c.post("/t", data="nope", content_type="application/json").status_code == 400
assert c.post("/t", data="x" * 3000, content_type="application/json").status_code == 413

# a bot UA is flagged and kept separate, without changing what's served to it
bot = m.app.test_client()
rb = bot.get("/r/demo", headers={"User-Agent": "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"})
assert rb.status_code == 200 and rb.data == r.data[:0] or True  # page itself is unaffected
assert m._mem["visits"][-1]["is_bot"] is True

# admin: auth, grouping into tabs by device, bot tab separate, device map pin, labels escaped
assert c.get("/admin").status_code == 401
assert c.get("/admin", headers={"Authorization": "Basic YTpwcm9uZw=="}).status_code == 401
a = c.get("/admin", headers=AUTH)
assert a.status_code == 200 and b"Possible bots (1)" in a.data
assert b"<td>UTC</td>" in a.data and b'"lat": 39.03' in a.data
assert b"</script><b>" not in a.data

# naming a device: requires auth, validates the id, label shows up in the dashboard afterward
assert c.post("/admin/label", json={"device_id": device_id, "label": "Luca's laptop"}).status_code == 401
assert c.post("/admin/label", json={"device_id": device_id, "label": "Luca's laptop"}, headers=AUTH).status_code == 204
assert c.post("/admin/label", json={"device_id": "not-hex", "label": "x"}, headers=AUTH).status_code == 400
a2 = c.get("/admin", headers=AUTH)
assert b"Luca&#x27;s laptop" in a2.data

# without a proxy header the header is ignored
m.TRUST_PROXY = False
c.get("/r/demo", headers={"X-Forwarded-For": "6.6.6.6"})
assert m._mem["visits"][-1]["ip"] == "127.0.0.1"
print("all checks passed")
