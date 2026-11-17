# IP Logger (Security Class Final Project)

A small web app for our security class that records the IP address, browser (User-Agent) and time of each visitor, to demonstrate what any web server can see about a client.

**Authors:** Luca Maiolo, Jaden Mayoff

**Purpose:** Educational only. Not for use outside this class.

## Ground rules


## Planned features



## Planned stack

- Python 3 standard library (`http.server`), no dependencies
- Single file: `app.py`

## How to run (once built)

```bash
python3 app.py
```

Then open http://localhost:8000.

## What we'll cover in the write-up

- What an IP address does and doesn't reveal (rough location, ISP, not identity)
- Why proxies, VPNs and NAT change what the server sees (`X-Forwarded-For`)
- Privacy and legal concerns: consent, GDPR-style rules, misuse of IP loggers
- Defenses: VPNs, Tor, link previews, blocking tracking requests

## Status

- [x] README
- [ ] Server (`app.py`)
- [ ] Testing
- [ ] Write-up
