// Copyright (c) 2017 Microsoft Corporation. All rights reserved.
// Content script — unchanged from Firefox version; chrome.* API is identical in Chromium.

window.addEventListener("message", function (event) {
    if (event && event.data && event.data.channel && (event.data.channel == "53ee284d-920a-4b59-9d30-a60315b26836")) {
        try {
            // Only accept messages from the same frame
            if (event.source != window)
                return;

            var request = event.data;
            var method = request.body.method;

            if (method == "CreateProviderAsync") {
                var extList = document.getElementById("ch-53ee284d-920a-4b59-9d30-a60315b26836");
                if (extList) {
                    var extElement = document.createElement("div");
                    extElement.id = chrome.runtime.id;

                    var version = chrome.runtime.getManifest().version;
                    if (version) {
                        extElement.setAttribute("ver", version);
                    }

                    extList.appendChild(extElement);
                }
            } else if (request.extensionId == chrome.runtime.id && method != "Response") {

                if (OS == null) {
                    OS = {
                        Call: function (request) {
                            try {
                                chrome.runtime.sendMessage(request.body, function (response) {
                                    if (response != null) {
                                        OS.Callback(request, response);
                                    } else {
                                        OS.Callback(request, {
                                            status: "Fail",
                                            code: "ContentError",
                                            description: chrome.runtime.lastError
                                                ? chrome.runtime.lastError.message
                                                : "No response",
                                        });
                                    }
                                    return true;
                                });
                            } catch (e) {
                                OS.Callback(request, {
                                    status: "Fail",
                                    code: "ContentError",
                                    description: e.toString(),
                                });
                            }
                        },

                        Callback: function (request, response) {
                            var req = {
                                channel: "53ee284d-920a-4b59-9d30-a60315b26836",
                                extensionId: chrome.runtime.id,
                                responseId: request.responseId,
                                body: {
                                    method: "Response",
                                    response: response,
                                },
                            };
                            window.postMessage(req, "*");
                        },
                    };
                }

                OS.Call(request);
            }
        } catch (e) {
            console.log("CS: Exception in the channel: " + e.toString());
            // Swallow to avoid breaking page execution
        }
    }
}, true);

var OS = null;
