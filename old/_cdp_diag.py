"""
_cdp_diag.py  --  Inspect Edge state via CDP for debugging auth issues.

Usage:
    python _cdp_diag.py [--port 9224]

Prints:
  - All open tabs and their current URLs
  - Cookies for login.microsoftonline.com and portal.azure.com
  - JS evaluation on portal tab: signed-in account name, auth state
"""

import argparse, json, sys, time
from urllib.parse import urlparse
import requests
try:
    import websocket
except ImportError:
    sys.exit("[!] pip install websocket-client")


def cdp_send(ws_url, method, params=None):
    ws = websocket.create_connection(ws_url, timeout=10, origin="http://localhost")
    ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
    deadline = time.time() + 10
    while time.time() < deadline:
        raw = ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == 1:
            ws.close()
            if "error" in msg:
                return None, msg["error"]
            return msg.get("result", {}), None
    ws.close()
    return None, "timeout"


def cdp_eval(ws_url, expression):
    ws = websocket.create_connection(ws_url, timeout=10, origin="http://localhost")
    ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                        "params": {"expression": expression, "returnByValue": True}}))
    deadline = time.time() + 10
    while time.time() < deadline:
        raw = ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == 1:
            ws.close()
            result = msg.get("result", {}).get("result", {})
            return result.get("value"), result.get("type")
    ws.close()
    return None, "timeout"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9224)
    args = ap.parse_args()
    port = args.port

    print("=" * 65)
    print("  CDP Diagnostic  (Edge port {})".format(port))
    print("=" * 65)

    # --- 1. List all tabs ---
    try:
        tabs = requests.get("http://127.0.0.1:{}/json".format(port), timeout=5).json()
    except Exception as e:
        sys.exit("[!] Cannot reach Edge CDP: {}".format(e))

    page_tabs = [t for t in tabs if t.get("type") == "page"]
    print("\n[TABS]  {} page tab(s)".format(len(page_tabs)))
    portal_tab = None
    for t in page_tabs:
        url = t.get("url", "")
        print("  {} | {}".format(t["id"][:12], url[:100]))
        parsed_url = urlparse(url)
        if parsed_url.hostname == "portal.azure.com":
            portal_tab = t

    # --- 2. Cookies for key domains ---
    print("\n[COOKIES]  Fetching all browser cookies ...")
    all_cookies = []
    if page_tabs:
        ws_url = page_tabs[0]["webSocketDebuggerUrl"].replace(
            "localhost:{}".format(port), "127.0.0.1:{}".format(port))
        result, err = cdp_send(ws_url, "Network.getAllCookies")
        if err:
            print("  [!] getAllCookies failed: {}".format(err))
        else:
            all_cookies = result.get("cookies", [])

    domains_of_interest = [
        ".login.microsoftonline.com",
        "login.microsoftonline.com",
        "portal.azure.com",
        ".azure.com",
        ".microsoftonline.com",
    ]
    names_of_interest = {
        "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT",
        "x-ms-RefreshTokenCredential", "x-ms-DeviceCredential",
        "brcap", "SignInStateCookie", "fpc", "stsservicecookie",
        "x-ms-gateway-slice",
    }

    relevant = [c for c in all_cookies
                if c.get("domain", "") in domains_of_interest
                or c.get("name", "") in names_of_interest]

    if not relevant:
        print("  [!] No relevant auth cookies found in Edge at all.")
    else:
        # Group by domain
        by_domain = {}
        for c in relevant:
            by_domain.setdefault(c["domain"], []).append(c)
        for domain, cookies in sorted(by_domain.items()):
            print("\n  Domain: {}".format(domain))
            for c in cookies:
                exp = c.get("expires", -1)
                exp_str = ""
                if exp > 0:
                    remaining = exp - time.time()
                    if remaining < 0:
                        exp_str = "  [EXPIRED {:.0f}s ago]".format(-remaining)
                    else:
                        exp_str = "  [expires in {:.0f}s]".format(remaining)
                val_preview = c.get("value", "")[:60]
                print("    {} = {}...{}".format(
                    c["name"], val_preview, exp_str))

    # --- 3. JS evaluation on portal tab ---
    if portal_tab:
        print("\n[PORTAL JS CHECKS]  Tab: {}".format(portal_tab.get("url", "")[:80]))
        ws_url = portal_tab["webSocketDebuggerUrl"].replace(
            "localhost:{}".format(port), "127.0.0.1:{}".format(port))

        checks = [
            # Friendly name shown in the top-right account picker
            ("Signed-in name",
             "document.querySelector('[data-content=\"account-menu\"] .fxs-avatarmenuitem-displayname')?.innerText || "
             "document.querySelector('.fxs-topbar-account .fxs-avatarmenuitem-displayname')?.innerText || "
             "'<not found>'"),
            # portal.azure.com exposes MsPortalFx with user info
            ("MsPortalFx user",
             "try { JSON.stringify({ upn: MsPortalFx.getUser()?.userInfo?.email, "
             "tid: MsPortalFx.getUser()?.userInfo?.tenantId }) } catch(e) { e.message }"),
            # Simple: does the page have the top bar at all?
            ("Top bar present",
             "document.querySelector('.fxs-topbar') !== null"),
            # Current href
            ("window.location.href",
             "window.location.href"),
            # Check if redirected to login
            ("Is on login page",
             "window.location.hostname.includes('login.microsoftonline.com')"),
        ]

        for label, expr in checks:
            val, typ = cdp_eval(ws_url, expr)
            print("  {:30s} {}".format(label + ":", repr(val)))
    else:
        print("\n[PORTAL JS CHECKS]  No portal.azure.com tab found.")
        print("  Available URLs:")
        for t in page_tabs:
            print("    " + t.get("url", "")[:100])

    # --- 4. Check ESTS session cookie validity ---
    print("\n[ESTS COOKIE SUMMARY]")
    ests = [c for c in all_cookies
            if c.get("name", "") in {"ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT"}]
    if not ests:
        print("  [!] No ESTSAUTH* cookies found — session likely not established.")
    for c in ests:
        exp = c.get("expires", -1)
        if exp > 0:
            remaining = exp - time.time()
            status = "VALID ({:.0f}s left)".format(remaining) if remaining > 0 else "EXPIRED"
        else:
            status = "session cookie (no expiry)"
        print("  {} | {} | {}".format(c["name"], c["domain"], status))

    # --- 5. Navigate to Entra ID Users and watch console + network errors ---
    print("\n[ENTRA USERS BLADE — LIVE ERRORS]")
    ENTRA_USERS = "https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers"

    # Find or pick the portal tab
    target_tab = portal_tab
    if not target_tab and page_tabs:
        target_tab = page_tabs[0]
    if not target_tab:
        print("  [!] No tab available to navigate.")
        print("\n[DONE]")
        return

    ws_url = target_tab["webSocketDebuggerUrl"].replace(
        "localhost:{}".format(port), "127.0.0.1:{}".format(port))

    print("  Navigating to Entra ID Users blade and collecting errors for 15s ...")
    print("  Tab: {}".format(target_tab.get("url", "")[:80]))

    # Open a persistent WebSocket and enable all diagnostic domains
    ws2 = websocket.create_connection(ws_url, timeout=20, origin="http://localhost")
    ws2.sock.settimeout(1.0)  # short recv timeout so we can poll in a loop

    _cmd_id = [0]

    def send_cmd(method, params=None):
        _cmd_id[0] += 1
        ws2.send(json.dumps({"id": _cmd_id[0], "method": method, "params": params or {}}))

    # Enable domains
    for domain_enable in ["Network.enable", "Console.enable", "Log.enable",
                           "Runtime.enable", "Page.enable"]:
        send_cmd(domain_enable)

    # Navigate
    send_cmd("Page.navigate", {"url": ENTRA_USERS})

    # Collect messages for 30 seconds (matches Users blade shimmer timeout)
    deadline = time.time() + 30
    events = []
    while time.time() < deadline:
        try:
            raw = ws2.recv()
        except Exception:
            continue
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        method = msg.get("method", "")

        # Console messages
        if method == "Console.messageAdded":
            m = msg["params"]["message"]
            if m.get("level") in ("error", "warning"):
                events.append(("[CONSOLE {}]".format(m["level"].upper()),
                               m.get("text", ""), m.get("url", ""), m.get("line", "")))

        # Runtime exceptions (unhandled JS errors)
        elif method == "Runtime.exceptionThrown":
            exc = msg["params"].get("exceptionDetails", {})
            desc = (exc.get("exception", {}).get("description") or
                    exc.get("text", "") or "")
            url_ = exc.get("url", "")
            line_ = exc.get("lineNumber", "")
            events.append(("[JS EXCEPTION]", desc[:200], url_, line_))

        # Network failures
        elif method == "Network.loadingFailed":
            p = msg["params"]
            events.append(("[NET FAIL]",
                           "{} | {}".format(p.get("errorText", ""), p.get("type", "")),
                           p.get("requestId", ""), ""))

        # Network responses (log 3xx/4xx/5xx)
        elif method == "Network.responseReceived":
            p = msg["params"]
            resp = p.get("response", {})
            status = resp.get("status", 0)
            if status >= 300:
                events.append(("[HTTP {}]".format(status),
                               resp.get("url", "")[:120],
                               p.get("type", ""), ""))

        # Log entries (browser-level errors)
        elif method == "Log.entryAdded":
            entry = msg["params"].get("entry", {})
            if entry.get("level") in ("error", "warning"):
                events.append(("[LOG {}]".format(entry["level"].upper()),
                               entry.get("text", "")[:200],
                               entry.get("url", ""), entry.get("lineNumber", "")))

    ws2.close()

    if not events:
        print("  No errors or warnings captured.")
    else:
        print("  {} event(s) captured:\n".format(len(events)))
        for kind, text, src, line in events:
            loc = ""
            if src:
                loc = "  @ {}".format(str(src)[:80])
                if line:
                    loc += ":{}".format(line)
            print("  {}  {}{}".format(kind, text[:160], loc))

    # --- 6. SOCKS proxy port scan and health check ---
    import socket as _socket
    print("\n[PROXY PORT SCAN]  Scanning 127.0.0.1:1080-1095 for active revtun SOCKS5 listeners ...")
    active_proxy_ports = []
    for _p in range(1080, 1096):
        _s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        _s.settimeout(0.35)
        try:
            _s.connect(('127.0.0.1', _p))
            # SOCKS5 greeting: version=5, nmethods=1, method=0x00 (no-auth)
            _s.sendall(bytes([0x05, 0x01, 0x00]))
            _resp = _s.recv(2)
            if len(_resp) >= 2 and _resp[0] == 0x05:
                active_proxy_ports.append(_p)
                print("  Port {:5d}: SOCKS5  OK  (server method choice: {:02x})".format(_p, _resp[1]))
            else:
                print("  Port {:5d}: LISTENING but did not respond as SOCKS5".format(_p))
        except (_socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            try: _s.close()
            except: pass

    if not active_proxy_ports:
        print("  [!] No active SOCKS5 proxy found — revtun tunnel is likely down")
    else:
        _proxy_port = active_proxy_ports[0]
        _proxy_url  = "socks5://127.0.0.1:{}".format(_proxy_port)
        print("  Testing HTTP routing through SOCKS:{} ...".format(_proxy_port))

        # Plain HTTP sanity check
        try:
            _r = requests.get("http://detectportal.firefox.com/canonical.html",
                              proxies={"http": _proxy_url, "https": _proxy_url},
                              timeout=8)
            print("  HTTP  via SOCKS:{}: {} {}  ({} bytes)".format(
                _proxy_port, _r.status_code, _r.reason, len(_r.content)))
        except requests.exceptions.ConnectionError as _e:
            if "SOCKS" in str(_e) or "proxies" in str(_e).lower():
                print("  [!] pip install requests[socks] (PySocks) required for SOCKS proxy test")
            else:
                print("  HTTP  via SOCKS:{}: FAILED — {}".format(_proxy_port, _e))
        except Exception as _e:
            print("  HTTP  via SOCKS:{}: FAILED — {}".format(_proxy_port, _e))

        # HTTPS to Microsoft Graph (just connectivity, no auth)
        try:
            _r = requests.get("https://graph.microsoft.com/",
                              proxies={"http": _proxy_url, "https": _proxy_url},
                              timeout=10, allow_redirects=True)
            print("  HTTPS Graph via SOCKS:{}: {} {}".format(_proxy_port, _r.status_code, _r.reason))
        except Exception as _e:
            print("  HTTPS Graph via SOCKS:{}: FAILED — {}".format(_proxy_port, _e))

    # --- 7. App Registrations blade errors ---
    APP_REG_URL = ("https://portal.azure.com/#view/Microsoft_AAD_IAM/"
                   "ActiveDirectoryMenuBlade/~/RegisteredApps")

    print("\n[APP REGISTRATIONS BLADE]")
    if not target_tab:
        print("  [!] No portal tab available.")
    else:
        _ws3 = None
        try:
            _ws3_url = target_tab["webSocketDebuggerUrl"].replace(
                "localhost:{}".format(port), "127.0.0.1:{}".format(port))
            _ws3 = websocket.create_connection(_ws3_url, timeout=20, origin="http://localhost")
            _ws3.sock.settimeout(1.0)
            _cmd3 = [0]

            def _send3(method, params=None):
                _cmd3[0] += 1
                _ws3.send(json.dumps({"id": _cmd3[0], "method": method, "params": params or {}}))

            for _d in ["Network.enable", "Console.enable", "Log.enable", "Page.enable"]:
                _send3(_d)
            _send3("Page.navigate", {"url": APP_REG_URL})

            print("  Collecting errors for 15s ...")
            _dl3 = time.time() + 15
            _ev3 = []
            while time.time() < _dl3:
                try: _raw3 = _ws3.recv()
                except: continue
                try: _msg3 = json.loads(_raw3)
                except: continue
                _meth3 = _msg3.get("method", "")
                if _meth3 == "Network.loadingFailed":
                    _pp = _msg3["params"]
                    _ev3.append(("[NET FAIL] ", "{} | {}".format(
                        _pp.get("errorText", ""), _pp.get("type", ""))))
                elif _meth3 == "Console.messageAdded":
                    _mc3 = _msg3["params"]["message"]
                    if _mc3.get("level") == "error":
                        _ev3.append(("[JS ERROR] ", _mc3.get("text", "")[:160]))
                elif _meth3 == "Network.responseReceived":
                    _st3 = _msg3["params"].get("response", {}).get("status", 0)
                    if _st3 >= 400:
                        _ev3.append(("[HTTP {:3d}] ".format(_st3),
                                     _msg3["params"]["response"].get("url", "")[:120]))
                elif _meth3 == "Log.entryAdded":
                    _le3 = _msg3["params"].get("entry", {})
                    if _le3.get("level") == "error":
                        _ev3.append(("[LOG ERR]  ", _le3.get("text", "")[:160]))

            if not _ev3:
                print("  No errors — App Registrations blade loaded cleanly.")
            else:
                # Deduplicate
                _seen3 = []
                for _k3, _t3 in _ev3:
                    if (_k3, _t3[:60]) not in [(x, y[:60]) for x, y in _seen3]:
                        _seen3.append((_k3, _t3))
                print("  {} unique error(s):".format(len(_seen3)))
                for _k3, _t3 in _seen3[:20]:
                    print("  {}{}".format(_k3, _t3))
        except Exception as _e3:
            print("  [!] App Registrations test failed: {}".format(_e3))
        finally:
            if _ws3:
                try: _ws3.close()
                except: pass

    # --- 8. MSAL access token inspection (from browser's token cache) ---
    print("\n[MSAL TOKEN CACHE]")
    if portal_tab:
        _ws4_url = portal_tab["webSocketDebuggerUrl"].replace(
            "localhost:{}".format(port), "127.0.0.1:{}".format(port))
        # Scan sessionStorage + localStorage for MSAL AccessToken cache entries
        _msal_script = """(function(){
            var results = [];
            var stores = [window.sessionStorage, window.localStorage];
            for (var si = 0; si < stores.length; si++) {
                var st = stores[si];
                try {
                    for (var i = 0; i < st.length; i++) {
                        var k = st.key(i);
                        if (!k) continue;
                        try {
                            var v = JSON.parse(st.getItem(k));
                            if (v && (v.credentialType === 'AccessToken' ||
                                      (v.secret && k.toLowerCase().includes('accesstoken')))) {
                                var exp = v.expiresOn
                                    ? new Date(parseInt(v.expiresOn) * 1000).toISOString()
                                    : (v.extendedExpiresOn
                                        ? new Date(parseInt(v.extendedExpiresOn)*1000).toISOString()
                                        : 'unknown');
                                results.push(JSON.stringify({
                                    home: v.homeAccountId || v.uid || '',
                                    scope: (v.target || v.scopes || '').toString().substring(0,100),
                                    expires: exp,
                                    realm: v.realm || v.tenantId || ''
                                }));
                            }
                        } catch(e2) {}
                    }
                } catch(e) {}
            }
            return results.length > 0 ? results.join('|||') : null;
        })()"""
        _toks, _ = cdp_eval(_ws4_url, _msal_script)
        if _toks:
            for _te in str(_toks).split("|||"):
                try:
                    _td = json.loads(_te)
                    print("  Token found:")
                    print("    Account : {}".format(_td.get("home", "")))
                    print("    Tenant  : {}".format(_td.get("realm", "")))
                    print("    Scope   : {}".format(_td.get("scope", "")))
                    print("    Expires : {}".format(_td.get("expires", "")))
                except Exception:
                    print("  Raw: {}".format(_te[:200]))
        else:
            print("  No MSAL access tokens found in browser storage")
            print("  (portal may not have loaded far enough to acquire tokens)")

        # Also check if the portal's JS has a user object available
        _user_script = """(function(){
            try {
                var u = MsPortalFx.getUser ? MsPortalFx.getUser() : null;
                if (u && u.userInfo) return JSON.stringify({
                    email: u.userInfo.email,
                    tid: u.userInfo.tenantId,
                    uid: u.userInfo.oid || u.userInfo.uniqueName
                });
            } catch(e) {}
            return null;
        })()"""
        _ui, _ = cdp_eval(_ws4_url, _user_script)
        if _ui:
            try:
                _uid = json.loads(_ui)
                print("\n  MsPortalFx user object:")
                print("    Email    : {}".format(_uid.get("email", "")))
                print("    Tenant   : {}".format(_uid.get("tid", "")))
            except Exception:
                print("  MsPortalFx user: {}".format(_ui))
    else:
        print("  No portal tab available.")

    # --- 9. PRT / Device credential cookie summary ---
    print("\n[PRT / DEVICE CREDENTIAL COOKIES]")
    _prt_names = {"x-ms-RefreshTokenCredential", "x-ms-DeviceCredential"}
    _prt_cookies = [c for c in all_cookies if c.get("name", "") in _prt_names]
    if not _prt_cookies:
        print("  [!] No PRT or Device credential cookies found")
    for _pc in _prt_cookies:
        _val = _pc.get("value", "")
        _exp = _pc.get("expires", -1)
        _exp_str = ""
        if _exp > 0:
            _rem = _exp - time.time()
            _exp_str = "  VALID {:.0f}s".format(_rem) if _rem > 0 else "  EXPIRED"
        # Decode the JWT header (first segment) to show alg/kid
        try:
            import base64 as _b64
            _hdr_b64 = _val.split(".")[0]
            _hdr_b64 += "=" * (4 - len(_hdr_b64) % 4)  # pad
            _hdr = json.loads(_b64.b64decode(_hdr_b64).decode())
            _hdr_str = "  alg={} kdfver={}".format(
                _hdr.get("alg", "?"), _hdr.get("kdf_ver", _hdr.get("kdfver", "?")))
        except Exception:
            _hdr_str = ""
        print("  {:35s} domain={}{}{}" .format(
            _pc["name"], _pc.get("domain", ""), _exp_str, _hdr_str))

    print("\n[DONE]")


if __name__ == "__main__":
    main()
