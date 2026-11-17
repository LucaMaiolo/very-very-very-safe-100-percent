# IP Logger (Security Class Final Project)

A small web app for our security class. It works as a link redirector: a short link such as `/r/demo` records the visitor's IP address, browser (User-Agent) and time, then forwards them to a destination page. It demonstrates what any web server can see about a client.

**Authors:** Luca Maiolo, Jaden Mayoff

**Purpose:** Educational only. Not for use outside this class.

## Ground rules

- Hosted temporarily for the class demo, then taken down after grading.
- Every visitor may see a notice before the redirect saying what is recorded (IP, User-Agent, time). No silent tracking (option in dashboard).
- Links are shared only with our instructor and classmates who agreed to take part.
- Logs are deleted after the project is graded.

## Features (planned)

- Short links (`/r/<name>`) mapped to allowlisted destinations
- Notice page with a short countdown, then a redirect (HTTP 302)
- Logging of each visit to `visits.csv` (time, IP, User-Agent, link name)
- Escaping of logged values so headers can't inject into the page
- Password-protected `/admin` page to view the log (password from an environment variable, never committed)

## Stack (planned)

- Python 3 standard library (`http.server`), no dependencies
- Single file: `app.py`

## Run locally (once built)

```bash
python3 app.py
```

Then open http://localhost:8000/r/demo.

## Hosting for class

Pick one when we get there:

- **Temporary tunnel (easiest):** run locally and expose it with `ngrok http 8000` or `cloudflared tunnel`. The link dies when we stop it.
- **Small cloud host:** Render, Fly.io or a small VPS. Set the admin password as an environment variable, and delete the service after grading.

Behind a tunnel or proxy the server sees the proxy's IP, so the app must read `X-Forwarded-For`. That header is client-controlled, so we should only trust it when the proxy sets it.

## What we'll cover in the write-up

- What an IP address does and doesn't reveal (rough location, ISP, not identity)
- Why proxies, VPNs, NAT and tunnels change what the server sees (`X-Forwarded-For`)
- Privacy and legal concerns: consent, GDPR-style rules, misuse of IP loggers
- Why open redirects are a vulnerability, and why we use an allowlist
- Defenses: VPNs, Tor, link previews, blocking tracking requests

## Status

- [x] README
- [ ] Server (`app.py`)
- [ ] Hosting
- [ ] Testing
- [ ] Write-up
