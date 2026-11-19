"""Class-project link redirector, steps 1-2: allowlist + notice page.
Run: python3 app.py -> http://localhost:8000/r/demo"""
import base64, csv, hmac, html, os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# Only these destinations are reachable; no ?url= redirects (open-redirect hole).
LINKS = {"demo": "https://example.com"}
LOG = "visits.csv"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # unset = /admin disabled
# Set TRUST_PROXY=1 only behind a tunnel/host that sets X-Forwarded-For; otherwise clients can fake it.
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"

def admin_ok(auth_header):
    """HTTP Basic auth; any username, password from ADMIN_PASSWORD."""
    if not ADMIN_PASSWORD or not auth_header.startswith("Basic "):
        return False
    try:
        pw = base64.b64decode(auth_header[6:]).decode().partition(":")[2]
    except ValueError:
        return False
    return hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())

def admin_page():
    if not os.path.exists(LOG):
        return b"<h1>Visits</h1><p>No visits yet.</p>"
    with open(LOG, newline="") as f:
        rows = list(csv.reader(f))
    tr = "".join("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<!doctype html><meta charset=utf-8><h1>Visits</h1><table border=1>{tr}</table>".encode()

NOTICE = """<!doctype html><meta charset=utf-8>
<meta http-equiv="refresh" content="5;url={dest}">
<title>Security class demo</title>
<h1>Security class demo</h1>
<p>This is a university class project. This visit records:</p>
<ul><li>IP: {ip}</li><li>Browser: {ua}</li><li>Time (UTC): {ts}</li></ul>
<p>Redirecting in 5 seconds. <a href="{dest}">Go now</a></p>"""

def log_visit(ts, ip, ua, name):
    new = not os.path.exists(LOG)
    with open(LOG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["time_utc", "ip", "user_agent", "link"])
        w.writerow([ts, ip, ua, name])

def render(dest, ip, ua, ts):
    # escape: the User-Agent header is attacker-controlled
    return NOTICE.format(dest=html.escape(dest), ip=html.escape(ip),
                         ua=html.escape(ua), ts=ts).encode()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            if not ADMIN_PASSWORD:
                self.send_error(404)
            elif not admin_ok(self.headers.get("Authorization", "")):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="admin"')
                self.end_headers()
            else:
                body = admin_page()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return
        name = self.path.removeprefix("/r/") if self.path.startswith("/r/") else None
        dest = LINKS.get(name)
        if not dest:
            self.send_error(404)
            return
        ip, ua = self.client_address[0], self.headers.get("User-Agent", "")
        xff = self.headers.get("X-Forwarded-For", "")
        if TRUST_PROXY and xff:
            ip = xff.split(",")[-1].strip()  # rightmost = the one our proxy added
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        log_visit(ts, ip, ua, name)
        body = render(dest, ip, ua, ts)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    # test: injection in User-Agent must be escaped
    assert b"<script>" not in render("https://x.test", "1.2.3.4", "<script>alert(1)</script>", "t")
    HTTPServer(("127.0.0.1", 8000), H).serve_forever()
