# UnKeycloak

<p align="center">
  <img src="./static/logo_unkeycloak.png" alt="Logo" width="620">
</p>

> UnKeycloak is a security tool designed to fingerprint and audit Keycloak instances (and the applications behind them) to identify misconfigurations, known CVEs and exploitable attack chains.

<div align="center">
<img src="https://img.shields.io/github/v/release/c0dejump/UnKeycloak" alt="release version">
<img alt="Python3.8" src="https://img.shields.io/badge/Python-3.8+-informational">
</div>

<br>

<p align="center">
  <a href="https://github.com/c0dejump/UnKeycloak/#installation">⚙️ Installation</a> |
  <a href="https://github.com/c0dejump/UnKeycloak/#usage">💻 Usage</a> |
  <a href="https://github.com/c0dejump/UnKeycloak/#examples">🧩 Examples</a> |
  <a href="https://github.com/c0dejump/UnKeycloak/#features">🚀 Features</a> |
  <a href="https://github.com/c0dejump/UnKeycloak/#todo">🧠 TODO</a>
</p>


## Installation

Follow these steps to install **UnKeycloak**:

1. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/c0dejump/UnKeycloak.git
   ```
2. **Change Directory**
   ```bash
   cd UnKeycloak
   ```
3. **Install** the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. **Ensure UnKeycloak** is running correctly:
   ```bash
   ./unkeycloak.py -h
      # OR
   python3 unkeycloak.py -h
   ```

## Usage

```bash
usage: unkeycloak.py [-h] [-u URL] [-f URL_FILE] [-o OUTPUT] [-v] [-H CUSTOM_HEADER] [-r CUSTOM_REALMS] [-x PROXY]
                     [-t TIMEOUT] [--no-brute] [--no-enum] [-w WORDLIST] [--rate-limit RATE_LIMIT]
                     [--reset-user RESET_USER] [--no-reset-test]

options:
  -h, --help            show this help message and exit

> General:
  -u URL, --url URL     URL to test [required] if no -f/--file provided
  -f URL_FILE, --file URL_FILE
                        File of URLs (one per line)
  -o OUTPUT, --output OUTPUT
                        Save results to JSON file
  -v, --verbose         Verbose output

> Request Settings:
  -H CUSTOM_HEADER, --header CUSTOM_HEADER
                        Add a custom HTTP header (format: 'Name: Value')
  -r CUSTOM_REALMS, --realms CUSTOM_REALMS
                        Add custom realm(s) to test
  -x PROXY, --proxy PROXY
                        Proxy URL (e.g. http://127.0.0.1:8080)
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)

> Modules:
  --no-brute            Skip credential brute-force
  --no-enum             Skip user enumeration
  -w WORDLIST, --wordlist WORDLIST
                        Custom credential wordlist (user:pass per line)
  --rate-limit RATE_LIMIT
                        Delay between brute-force requests in seconds (default: 0.1)

> CVE-2026-18963 (reset-credentials bypass):
  --reset-user RESET_USER
                        Username(s) to actively test for the unauth reset-credentials
                        bypass (repeatable). Enumerated valid users are also tested.
  --no-reset-test       Skip the active CVE-2026-18963 test (it sends a password-reset
                        email to each tested user)
```

### Arguments

```bash
# Scan only one Keycloak instance
» ./unkeycloak.py -u 'https://sso.target.tld/'

# Scan a list of instances
» ./unkeycloak.py -f keycloak_list.txt

# Passive-ish scan: no user enumeration, no credential brute-force
» ./unkeycloak.py -u 'https://sso.target.tld/' --no-enum --no-brute

# Test realms that are not auto-discovered
» ./unkeycloak.py -u 'https://sso.target.tld/' -r internal -r partners

# Custom credential wordlist with a slower rate to stay under the WAF/lockout radar
» ./unkeycloak.py -u 'https://sso.target.tld/' -w creds.txt --rate-limit 1.5

# Add a custom header (session, bypass, tracking...)
» ./unkeycloak.py -u 'https://sso.target.tld/' -H 'Cookie: KEYCLOAK_SESSION=...' -H 'X-Bug-Bounty: codejump'

# Route everything through Burp and export the findings as JSON
» ./unkeycloak.py -u 'https://sso.target.tld/' -x http://127.0.0.1:8080 -o results.json
```

## Examples

*(coming soon)*

## Features

### Fingerprinting
- Realm discovery (unauthenticated admin API + wordlist fallback, `-r` for custom realms)
- Keycloak version detection (feature-based + endpoint fingerprinting)
- Client ID enumeration
- Identity Provider (IdP) discovery

### Misconfigurations
- CVE checking against the detected version (~30 CVEs, from 2018 to 2026), with active PoC where it is safe to do so — destructive CVEs and those requiring a valid bearer token are reported for manual testing only
- CVE-2026-18963 active unauthenticated reset-credentials bypass test: drives the reset flow via *Try Another Way* → email selection → `username`, then re-requests the reset URL to detect the update-password form served **without** consuming the email action-token (account takeover on Keycloak 26.0.0–26.7.1). Non-destructive — it never sets a new password — but it does send one reset email per tested user. Targets are enumerated valid users plus any `--reset-user` you pass; disable with `--no-reset-test`.
- Self-registration endpoints exposed
- Dynamic client registration open to anonymous users
- PAR (Pushed Authorization Requests) misconfiguration
- CORS analysis on sensitive endpoints (credentialed cross-origin)
- Dangerous grant types (Implicit flow, ROPC/Direct Access Grants, algorithm confusion surface)
- Scope enumeration (dangerous / privileged scopes)
- Security headers (clickjacking, framing of login pages...)
- Open redirect via `redirect_uri` validation weaknesses
- Brute-force protection detection (lockout & rate-limiting behavior)
- Session security (CSRF on `/login-actions/restart`, `AUTH_SESSION_ID` cookie flags)

### Fuzzing
- Potentially sensitive endpoints (client-registration installs leaking secrets, config exposure...)
- User enumeration — multiple oracles, most-to-least reliable:
  - **Admin Users API dump** (`/admin/realms/{realm}/users`): the only vector that actually *lists* users instead of guessing. Tried unauthenticated first (a broken reverse-proxy exposing it is flagged critical), then dumped (paginated) with any access token recovered by the credential module — an `admin-cli` token on `master` lists every realm's users.
  - **Self-registration oracle**: when registration is open, submits the form with a target username and mismatched passwords (so no account is ever created) and reads Keycloak's *"Username already exists"* response.
  - **Token endpoint response differential** (valid vs invalid account messages) + **timing analysis** (bcrypt comparison on valid users).
  - All confirmed users feed the CVE-2026-18963 reset-credentials test automatically.
- Default / weak credential testing on the token endpoint (`--no-brute` to skip, `-w` for a custom wordlist); a recovered access token is reused to enumerate real users via the Admin API

### Reporting
- Colored terminal summary grouped by severity (critical → info)
- **Attack chain correlation**: dangerous combinations are flagged automatically, e.g.
  - ROPC enabled + no brute-force protection → direct credential brute-force viable
  - Implicit flow + CORS on `userinfo` → cross-origin token theft
  - Algorithm confusion → forge a JWT using the RSA public key from `/certs` as the HMAC secret
- JSON export with `-o` for pipelines and reporting


### Based on

- [Keycloak Security Advisories](https://github.com/keycloak/keycloak/security/advisories)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://datatracker.ietf.org/doc/rfc9700/)
- [OAuth 2.0 Threat Model (RFC 6819)](https://datatracker.ietf.org/doc/html/rfc6819)
- [PortSwigger — OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth)
- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)

## Disclaimer

This tool is intended for **authorized security testing only**. Some modules are active (credential testing, user enumeration, client registration, CVE PoCs) and will generate noticeable traffic and log entries on the target. Make sure you have explicit written permission before scanning anything you do not own.

## Contributing

Pull requests are welcome. Feel free to contribute to this tool and make improvements!
