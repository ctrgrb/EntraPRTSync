// Copyright (c) 2017 Microsoft Corporation. All rights reserved.
// Chromium MV2 port — persistent background page, localStorage, webRequest blocking UA spoof.

chrome.runtime.onMessage.addListener(
    function (request, sender, sendResponse)
    {
        let enabled = localStorage.getItem("enabled") === "true" || false;
        let token_broker_host = localStorage.getItem("host") || "localhost";
        let token_broker_port = parseInt(localStorage.getItem("port")) || 8889;
        console.log("SSO Request: ", request);

        if (request.method != "GetCookies")
        {
            console.log("SSO Response [MethodNotSupported]: ", request.method);
            return;
        }

        if (!enabled)
        {
            console.log("SSO Response [Disabled]: ", request.method);
            return;
        }

        try
        {
            // Attach config to request if needed
            request.sender = sender.url;
            request.token_broker_host = token_broker_host;
            request.token_broker_port = token_broker_port;

            chrome.runtime.sendNativeMessage(
                "ssoproxy",
                request,
                function (response) {
                    if (response != null) {
                        if (response.status && response.status == "Fail" && response.code) {
                            console.log("SSO Response [Fail]: ", response);
                            sendResponse(response);
                        } else {
                            console.log("SSO Response [Success]: ", response);
                            sendResponse({
                                status: "Success",
                                result: response
                            });
                        }
                    } else {
                        console.log("SSO Response [NoSupport]: ", response, chrome.runtime.lastError);
                        sendResponse({
                            status: "Fail",
                            code: "NoSupport",
                            description: chrome.runtime.lastError ? chrome.runtime.lastError.message : "No response",
                        });
                    }
                }
            );
        } catch (e) {
            console.log("SSO Response [Exception]: ", e);
            sendResponse({
                status: "Fail",
                code: "NoSupport",
                description: e.toString(),
            });
        }

        // Required to keep sendResponse alive for async use
        return true;
    });

chrome.browserAction.onClicked.addListener(function (tab) {
    chrome.tabs.create({ url: "https://www.office.com" });
});

// Proactively inject PRT cookie for login.microsoftonline.com so that
// interactive / federated-domain flows (Teams, etc.) find it without ADFS.
// Called on startup and periodically to keep it fresh.
function injectPrtCookie() {
    let enabled = localStorage.getItem("enabled") === "true";
    let host    = localStorage.getItem("host") || "localhost";
    let port    = parseInt(localStorage.getItem("port")) || 8889;
    if (!enabled) return;

    let req = {
        method: "GetCookies",
        uri: "https://login.microsoftonline.com/",
        sender: "https://login.microsoftonline.com/",
        token_broker_host: host,
        token_broker_port: port
    };

    chrome.runtime.sendNativeMessage("ssoproxy", req, function (response) {
        if (chrome.runtime.lastError || !response) return;
        let cookies = (response.response || response.result || []);
        for (let c of cookies) {
            if (c.name === "x-ms-RefreshTokenCredential" && c.data) {
                // data may contain '; path=/; ...' suffix — strip it to get pure JWT
                let jwt = c.data.split(";")[0].trim();
                chrome.cookies.set({
                    url:            "https://login.microsoftonline.com/",
                    name:           "x-ms-RefreshTokenCredential",
                    value:          jwt,
                    domain:         ".login.microsoftonline.com",
                    path:           "/",
                    secure:         true,
                    httpOnly:       false,
                    sameSite:       "no_restriction",
                    expirationDate: Math.floor(Date.now() / 1000) + 600
                }, function (cookie) {
                    if (chrome.runtime.lastError) {
                        console.log("PRT cookie set error:", chrome.runtime.lastError.message);
                    } else {
                        console.log("PRT cookie injected, expires in 10 min");
                    }
                });
            }
        }
    });
}

// Inject on startup (after a short delay to let settings load)
setTimeout(injectPrtCookie, 2000);
// Refresh every 8 minutes so the cookie stays valid
setInterval(injectPrtCookie, 8 * 60 * 1000);

// ---------------------------------------------------------------------------
// ADFS interception: when AAD redirects the browser to ADFS for a federated
// user's interactive login, we catch the ADFS navigation, cancel it, and
// retry the original AAD authorize URL with prompt=none.  The silent path
// triggers the extension channel (sso_nonce), which content.js handles via
// the PRT broker — completely bypassing ADFS.
// ---------------------------------------------------------------------------
const _lastAadAuth = {};   // tabId → { url, ts }

// Track every AAD authorize attempt per tab so we can retry it.
chrome.webNavigation.onBeforeNavigate.addListener(function (details) {
    if (details.frameId !== 0) return;  // main frame only
    const url = details.url;
    if (url.includes('login.microsoftonline.com') &&
        url.includes('/oauth2/') && url.includes('/authorize')) {
        _lastAadAuth[details.tabId] = { url: url, ts: Date.now() };
    }
});

// Detect ADFS navigation via URL containing '/adfs/' (provider-agnostic).
// Immediately redirect back to the cached AAD authorize URL but with prompt=none.
chrome.webNavigation.onBeforeNavigate.addListener(function (details) {
    if (details.frameId !== 0) return;
    const url = details.url;
    // Detect ADFS: path contains /adfs/ and NOT a Microsoft-owned host
    if (!url.includes('login.microsoftonline.com') &&
        !url.includes('microsoft.com') &&
        (url.includes('/adfs/') || url.includes('/adfs?'))) {

        const cached = _lastAadAuth[details.tabId];
        if (!cached || (Date.now() - cached.ts) > 30000) return; // stale or missing
        delete _lastAadAuth[details.tabId];

        // Build the prompt=none retry URL from the original interactive URL
        let retryUrl = cached.url;
        if (retryUrl.includes('prompt=')) {
            retryUrl = retryUrl.replace(/prompt=[^&]*/g, 'prompt=none');
        } else {
            retryUrl += '&prompt=none';
        }
        // Strip login_hint if present to avoid re-triggering HRD
        // (keep it — it helps AAD select the account)

        console.log('[ssoproxy] ADFS redirect intercepted — retrying AAD with prompt=none');
        console.log('[ssoproxy] Retry URL:', retryUrl.substring(0, 120));

        // Inject fresh PRT cookie and immediately redirect — no delay so we
        // beat the ADFS page before it loads
        injectPrtCookie();
        chrome.tabs.update(details.tabId, { url: retryUrl });
    }
});

// Belt-and-suspenders: cancel ADFS requests at network level (faster than tabs.update)
// and record the redirect URL to rebuild the retry.
chrome.webRequest.onBeforeRequest.addListener(
    function (details) {
        if (details.frameId !== 0 || details.type !== 'main_frame') return;
        const url = details.url;
        if (!url.includes('login.microsoftonline.com') &&
            !url.includes('microsoft.com') &&
            (url.includes('/adfs/') || url.includes('/adfs?'))) {

            const cached = _lastAadAuth[details.tabId];
            if (!cached || (Date.now() - cached.ts) > 30000) return {};
            delete _lastAadAuth[details.tabId];

            let retryUrl = cached.url;
            if (retryUrl.includes('prompt=')) {
                retryUrl = retryUrl.replace(/prompt=[^&]*/g, 'prompt=none');
            } else {
                retryUrl += '&prompt=none';
            }
            console.log('[ssoproxy] Blocking ADFS request; redirecting to prompt=none');
            injectPrtCookie();
            // Schedule tab redirect (can't redirect synchronously in onBeforeRequest)
            setTimeout(function() {
                chrome.tabs.update(details.tabId, { url: retryUrl });
            }, 50);
            return { cancel: true };
        }
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['blocking']
);

// Let Microsoft think we're using Chrome 71, so the PRT/WAM SSO option will be available.
// login.microsoftonline.com checks the UA to decide whether to invoke the extension
// channel (AAD GUID 53ee284d-920a-4b59-9d30-a60315b26836) for cookie injection.
// Chrome requires the "extraHeaders" option to modify the User-Agent header.
let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
const CLIENT_HINT_HEADERS = new Set([
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model"
]);
chrome.webRequest.onBeforeSendHeaders.addListener(
    function (e) {
        let headers = e.requestHeaders.filter(
            h => !CLIENT_HINT_HEADERS.has(h.name.toLowerCase())
        );
        for (let header of headers) {
            if (header.name.toLowerCase() === "user-agent") {
                header.value = ua;
            }
        }
        return { requestHeaders: headers };
    },
    { urls: ["https://login.microsoftonline.com/*"] },
    ["blocking", "requestHeaders", "extraHeaders"]
);
