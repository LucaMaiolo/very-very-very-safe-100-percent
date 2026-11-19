# IP Logger (Security Class Final Project)

A small web app for our security class. It works as a link redirector: a short link such as `/r/demo` shows a notice, records what the server and browser reveal about the visitor, then forwards them to a destination page. It demonstrates what any web server can learn about a client.

**Authors:** Luca Maiolo, Jaden Mayoff

**Purpose:** Educational only. Not for use outside this class.

## Ground rules

- Hosted temporarily for the class demo, then taken down after grading.
- Every visitor may see a notice before the redirect saying what is recorded (IP, location, provider, User-Agent, time, browser telemetry). No silent tracking. The notice is currently always shown; a dashboard option to turn it off is only an idea and is not built.
- Links are shared only with our instructor and classmates who agreed to take part.
- Logs are deleted after the project is graded.

## What it collects

| Data | Source |
|------|--------|
| IP address | Network connection (or `X-Forwarded-For` behind a proxy) |
| Approximate location (city, region, country, lat/lon) and internet provider | Looked up from the IP via [ip-api.com](https://ip-api.com) (the IP is sent to that service) |
| Browser (User-Agent) and time | Request header and server clock |
| Time zone, language, screen size, window size, pixel ratio | Small script on the notice page, sent to `/t` |
| A device identifier, so repeat visits from the same browser group together | An httponly cookie, set on first visit |

Telemetry is deliberately coarse: no canvas, font or other fingerprinting. The server drops any field outside that list.

## Features

- Short links (`/r/<name>`) mapped to an allowlist of destinations (no `?url=` redirects, which would be an open-redirect hole)
- Notice page with a 5-second countdown, then a redirect
- Each visit gets a random ID, so its telemetry is joined to it; each browser gets a cookie ID, so its visits are joined to each other
- Logging to a Supabase Postgres database (`devices`, `visits`, `telemetry` tables, see `schema.sql`)
- Escaping of logged values so headers can't inject into pages
- Visits whose User-Agent matches a known link-preview/crawler bot (Discord, Slack, search engines, ...) are flagged, not hidden or treated differently when served
- Password-protected `/admin` dashboard:
  - one tab per device, newest activity first, each visit sorted by time within it
  - name a device from its tab (stored, shown from then on instead of the raw ID)
  - each device's own small map of its approximate visit locations (Leaflet and OpenStreetMap tiles, loaded in the admin's browser)
  - flagged bot visits sit in their own tab, separate from real devices, reviewed by opening that tab rather than being deleted or hidden from the data

## Stack

- Python 3 + Flask (`app.py`, one file)
- Hosting: Vercel (serverless)
- Storage: Supabase Postgres, called over its REST API with the standard library (no extra packages)

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SUPABASE_URL` | Project URL, like `https://abcd.supabase.co` |
| `SUPABASE_SERVICE_KEY` | The `service_role` key. Server-side only. Never commit it or expose it in the browser. |
| `ADMIN_PASSWORD` | Password for `/admin` (any username). If unset, `/admin` is disabled (404). |
| `TRUST_PROXY=1` | Use the client IP from `X-Forwarded-For`. Turned on automatically on Vercel. Elsewhere set it only behind a proxy you control, because clients can fake the header. |

Edit the `LINKS` dict at the top of `app.py` to change destinations.

## Run locally

```bash
pip install -r requirements.txt
ADMIN_PASSWORD=choose-a-password python3 app.py
```

- Visit http://localhost:8000/r/demo
- View the log and map at http://localhost:8000/admin
- Without the Supabase variables, visits are kept in memory and vanish when you stop the server. That's fine for local testing.
- From your own machine you appear as `127.0.0.1`, which has no location. Test on the deployed site to see a real public IP.
- Self-check: `python3 test_app.py`

## Deploy to Vercel + Supabase

1. **Supabase:** create a free project at supabase.com. Open SQL Editor, paste `schema.sql`, and run it. Under Project Settings, then API, copy the project URL and the `service_role` key.
2. **GitHub:** push this repo.
3. **Vercel:** import the repo as a new project. Under Settings, then Environment Variables, add `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` and `ADMIN_PASSWORD`, then deploy.
4. Open `https://<project>.vercel.app/r/demo`, then `/admin` to check the visit, its device tab and its map pin appear.
5. **After grading:** delete the Vercel project and the Supabase project, which also removes the logs.

The app refuses to start on Vercel if the Supabase variables are missing, rather than silently losing logs.

## What we'll cover in the write-up

- What an IP address does and doesn't reveal (rough location, ISP, not identity)
- Why proxies, VPNs, NAT and tunnels change what the server sees (`X-Forwarded-For`)
- What a page's script can add on top of an IP (time zone, language, screen)
- Privacy and legal concerns: consent, GDPR-style rules, misuse of IP loggers
- Why open redirects are a vulnerability, and why we use an allowlist
- How link-preview bots (Discord, Slack, ...) identify themselves, and why that's only a hint, not proof
- Defenses: VPNs, Tor, link previews, blocking tracking requests

## Status

- [x] README
- [x] Server (`app.py`)
- [x] Rewrite for Vercel + Supabase
- [ ] Supabase project + schema
- [ ] Deployed and tested on Vercel
- [ ] Write-up
