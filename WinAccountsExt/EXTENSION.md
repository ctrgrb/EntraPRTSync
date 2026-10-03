# ssoproxy — Chromium Extension (Edge / Chrome)

Ports the Firefox SSO Proxy extension to Chromium-based browsers (Edge, Chrome). Relays EntraID PRT cookies from an EntraID-joined machine to authenticate silently to Microsoft services (Teams, SharePoint, Outlook, Azure Portal, etc.) without being on the EntraID machine.

---

## Files

```
ssoproxy-chrome/
├── manifest.json          Extension manifest (MV2)
├── background.js          Persistent background page — core logic
├── content.js             Content script — AAD channel bridge (unchanged from Firefox)
├── settings.js            Settings popup logic
├── settings_popup.html    Settings popup UI
├── settings_popup.css     Settings popup styles
├── nmh_manifest.json      Native Messaging Host registration manifest
├── rules/
│   └── ua_spoof.json      DeclarativeNetRequest rules (UA spoof + Client Hints strip)
├── keyinfo.txt            RSA key info (used to generate the deterministic extension ID)
└── extension.pem          RSA private key (for signing)
```

---

## Extension ID

**`fjkjhjgmiiakphncnigpgongngidebmp`** — deterministic, derived from the RSA public key embedded in the manifest's `key` field. This ID is stable across installs and profiles, which is required for the Native Messaging Host's `allowed_origins` to match.

---

## Architecture

```
Microsoft Service (Teams, SharePoint, etc.)
        │
        │ page navigates to login.microsoftonline.com
        ▼
  content.js (injected into every page at document_start)
        │ listens on AAD channel GUID 53ee284d-920a-4b59-9d30-a60315b26836
        │ window.postMessage ↕ page
        │ chrome.runtime.sendMessage → background page
        ▼
  background.js (persistent background page)
        │ chrome.runtime.sendNativeMessage("ssoproxy", ...)
        ▼
  BrowserNativeMessagingClient_NET4.7.2.exe  (stdio)
        │ TCP → localhost:8889
        ▼
  RequestAADRefreshTokenBroker_NET4.7.2.exe  (on EntraID machine)
        │ fetches PRT from Windows WAM/interactive session
        └─ returns x-ms-RefreshTokenCredential JWT
```

The JWT is sent back up the chain as a cookie on `login.microsoftonline.com`, completing the silent OAuth2 flow without user interaction.

---

## Settings

Stored in `localStorage` of the background page (MV2 persistent page — same origin across restarts).

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Master on/off switch. Extension does nothing if `false`. |
| `host` | `localhost` | Hostname of the token broker (TCP). |
| `port` | `8889` | Port of the token broker (TCP). |

Set via the settings popup (toolbar icon → popup) or programmatically via CDP:

```javascript
localStorage.setItem('enabled', 'true');
localStorage.setItem('host', 'localhost');
localStorage.setItem('port', '8889');
```

---

## Components

### `manifest.json`

- **Manifest Version**: 2 (MV2). MV3 is not used — service workers cannot hold persistent `webRequest` blocking listeners, which are required for synchronous header modification.
- **`persistent: true`**: background page never unloads, ensuring `_lastAadAuth` state and `setInterval` timers survive across navigations.
- **`key` field**: RSA public key that pins the extension ID to `fjkjhjgmiiakphncnigpgongngidebmp` regardless of install path.
- **Permissions**:
  - `nativeMessaging` — communicate with the NMH exe
  - `webRequest` + `webRequestBlocking` — synchronously modify/cancel HTTP requests
  - `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` — network-layer header rules
  - `cookies` — write PRT cookie to `login.microsoftonline.com` cookie store
  - `tabs` — redirect tabs during ADFS interception
  - `webNavigation` — detect navigation events for ADFS interception
  - `storage` — not actively used (settings use localStorage)
  - `<all_urls>` — required for `onBeforeRequest` ADFS cancellation on federated domains
  - `https://login.microsoftonline.com/*` — required for `webRequest` header modification

---

### `background.js`

Four distinct responsibilities:

#### 1. Native Messaging relay (`chrome.runtime.onMessage`)
Receives `GetCookies` requests from `content.js`, forwards them to the NMH as a JSON message, and returns the `x-ms-RefreshTokenCredential` JWT cookie back to the content script.

Message format sent to NMH:
```json
{
  "method": "GetCookies",
  "uri": "<AAD authorize URL>",
  "sender": "<same URL>",
  "token_broker_host": "localhost",
  "token_broker_port": 8889
}
```

#### 2. UA spoof (`chrome.webRequest.onBeforeSendHeaders`)
Intercepts all requests to `https://login.microsoftonline.com/*` and:
- Sets `User-Agent` to `Chrome/71.0.3578.98` — the version MSoft's AAD WAM extension channel expects
- Strips all `Sec-Ch-Ua*` Client Hint headers — Chromium sends these automatically and they reveal the real browser version (Edge 141), which would override the UA spoof at AAD's HRD logic

Uses `["blocking", "requestHeaders", "extraHeaders"]` — the `extraHeaders` flag is required in Chromium to intercept `User-Agent` (a "sensitive" header) and Client Hint headers.

#### 3. Proactive PRT cookie injection (`injectPrtCookie`)
**Why needed**: For interactive OAuth2 flows (no `sso_nonce`), AAD performs Home Realm Discovery server-side. If it detects a federated domain and finds no PRT cookie, it redirects to ADFS before the extension channel is ever invoked.

**How it works**:
- On startup (after 2s delay to allow settings to load) and every 8 minutes
- Calls the NMH directly with a `GetCookies` request for `https://login.microsoftonline.com/`
- Strips the cookie string suffix (e.g. `; path=/; domain=...`) from `data` to extract the raw JWT
- Sets `x-ms-RefreshTokenCredential` on `.login.microsoftonline.com` via `chrome.cookies.set()` with a 10-minute expiry

This pre-arms the AAD cookie store so that when Teams/Outlook trigger a fresh interactive flow, the PRT is already available.

#### 4. ADFS interception (`_lastAadAuth` + `webNavigation` + `webRequest`)
**Why needed**: Even with the PRT cookie pre-injected, on a fresh profile or when HRD cache is cold, AAD may still redirect to ADFS. This catches and cancels that redirect.

**Detection**: Any navigation to a URL containing `/adfs/` or `/adfs?` that is NOT `login.microsoftonline.com` or `microsoft.com`.

**Two-layer interception**:

1. **`webNavigation.onBeforeNavigate`** (listener A): records every AAD `/oauth2/.../authorize` URL per tab with a timestamp into `_lastAadAuth[tabId]`.

2. **`webNavigation.onBeforeNavigate`** (listener B): fires on ADFS navigation. Looks up the cached AAD URL, replaces `prompt=<anything>` with `prompt=none`, injects a fresh PRT cookie, then calls `chrome.tabs.update()` to redirect the tab back to the `prompt=none` AAD URL.

3. **`webRequest.onBeforeRequest { cancel: true }`** (network level): fires even before the navigation event, cancels the ADFS request at the TCP level so the ADFS server is never contacted, then schedules `tabs.update` with a 50ms `setTimeout` (synchronous redirect is not possible in `onBeforeRequest`).

The `prompt=none` retry triggers the silent SSO path on AAD, which serves the `sso_nonce` page. `content.js` detects this, calls back to the background which calls the NMH, and returns the PRT JWT — completing auth without ADFS.

**30-second TTL**: cached AAD URLs older than 30s are ignored to avoid mis-routing unrelated ADFS navigations.

---

### `content.js`

Injected into **every page** at `document_start`, including sub-frames. Identical to the Firefox version (`chrome.*` API is available in both).

- Listens for `window.postMessage` events on channel GUID **`53ee284d-920a-4b59-9d30-a60315b26836`**
- This GUID is the AAD WAM browser extension channel identifier — Microsoft's own JS on `login.microsoftonline.com` posts to it
- On `CreateProviderAsync`: registers the extension ID in the DOM so AAD knows this extension is present and can handle PRT requests
- On other methods (e.g. `GetCookies`): forwards the request body to the background page via `chrome.runtime.sendMessage`, receives the PRT JWT response, and posts it back to the page via `window.postMessage`

**Why `document_start`**: The AAD page JS checks the DOM for the extension's element during its own initialization. If content.js runs after `document_end`, the extension won't be discovered and AAD falls back to other auth methods.

---

### `rules/ua_spoof.json` (DeclarativeNetRequest)

Two rules applied to all resource types on `login.microsoftonline.com`:

**Rule 1 — UA override**: Sets `User-Agent` to `Chrome/71.0.3578.98 Safari/537.36`.

**Rule 2 — Client Hints strip**: Removes `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Sec-Ch-Ua-Full-Version`, `Sec-Ch-Ua-Full-Version-List`, `Sec-Ch-Ua-Arch`, `Sec-Ch-Ua-Bitness`, `Sec-Ch-Ua-Model`.

**Why DNR is needed in addition to `webRequest`**: `webRequest` listeners are registered asynchronously after the background page JS executes. On the very first page load after browser startup, there is a race window where the listener may not yet be registered when the first request to `login.microsoftonline.com` fires. DNR rules are evaluated at the network layer by the browser engine itself — they are always active with zero JS startup latency.

Applies to: `main_frame, sub_frame, xmlhttprequest, other, ping, beacon, csp_report, font, image, media, object, script, stylesheet, websocket, webbundle, xml_dtd, xslt`.

---

### `nmh_manifest.json`

Registered at:
- `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\ssoproxy`
- `HKCU\Software\Google\Chrome\NativeMessagingHosts\ssoproxy`

```json
{
  "name": "ssoproxy",
  "path": "C:\\...\\BrowserNativeMessagingClient_NET4.7.2.exe",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://fjkjhjgmiiakphncnigpgongngidebmp/"]
}
```

The `allowed_origins` entry must exactly match the extension's ID. Only messages originating from this extension ID will be accepted by the NMH.

---

## Why Chromium Needs More Than Firefox

Firefox never sends `Sec-Ch-Ua` Client Hint headers (it is not Chromium). When Firefox spoofs `User-Agent: Chrome/71`, AAD has no contradicting signal and routes through the WAM extension channel for all flows including interactive ones.

Chromium (Edge/Chrome) sends `Sec-Ch-Ua: "Microsoft Edge";v="141"` alongside the spoofed UA. AAD reads Client Hints with higher priority than `User-Agent` and determines the real browser is Edge 141 — causing it to skip the WAM extension channel for interactive federated flows and redirect to ADFS instead.

The three Chromium-specific additions compensate:

| Problem | Solution |
|---|---|
| `webRequest` listener registration race on first request | DNR rule — active at network layer before any JS runs |
| AAD HRD redirects to ADFS (no PRT cookie at decision time) | Proactive `injectPrtCookie()` — PRT pre-written to cookie store on startup |
| AAD still reaches ADFS (cold HRD cache / fresh profile) | `onBeforeRequest { cancel: true }` + `tabs.update` → retry as `prompt=none` |

---