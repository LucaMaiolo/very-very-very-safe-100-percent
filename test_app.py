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
H = {"X-Forwarded-For": "6.6.6.6, 8.8.8.8", "User-Agent": "</script><b>x"}

# redirect page: logs the proxy-added IP (rightmost), shows what is recorded, escapes the User-Agent
r = c.get("/r/demo", headers=H)
assert r.status_code == 200 and b"8.8.8.8" in r.data and b"Ashburn" in r.data
assert b"</script><b>" not in r.data and b"&lt;/script&gt;" in r.data
vid = m._mem["visits"][0]["id"]
assert m._mem["visits"][0]["ip"] == "8.8.8.8"
assert c.get("/r/nope").status_code == 404

# telemetry: accepted for a visit id, extra fields dropped, junk rejected
ok = {"id": vid, "timezone": "UTC", "language": "en", "screen": "1x1", "viewport": "1x1",
      "pixel_ratio": 2, "evil": "x"}
assert c.post("/t", json=ok).status_code == 204
assert "evil" not in m._mem["telemetry"][0]
assert c.post("/t", json={"id": "zz"}).status_code == 400
assert c.post("/t", data="nope", content_type="application/json").status_code == 400
assert c.post("/t", data="x" * 3000, content_type="application/json").status_code == 413

# admin: auth, grouping by IP, telemetry joined, map pin, no raw script-close from the User-Agent
c.get("/r/demo", headers=H)
assert c.get("/admin").status_code == 401
assert c.get("/admin", headers={"Authorization": "Basic YTp3cm9uZw=="}).status_code == 401
a = c.get("/admin", headers={"Authorization": "Basic YTpwdw=="})  # a:pw
assert a.status_code == 200 and b"2 visit(s)" in a.data and b"Ashburn" in a.data
assert b"<td>UTC</td>" in a.data and b'"lat": 39.03' in a.data
assert b"</script><b>" not in a.data

# without a proxy header the header is ignored
m.TRUST_PROXY = False
c.get("/r/demo", headers={"X-Forwarded-For": "6.6.6.6"})
assert m._mem["visits"][-1]["ip"] == "127.0.0.1"
print("all checks passed")
