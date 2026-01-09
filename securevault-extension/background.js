// SecureVault Background Service Worker

let nativePort = null;
const HOST_NAME = "com.securevault.host";

/**
 * Connects to the Native Messaging Host.
 */
function connectToHost() {
    console.log("[SecureVault] Connecting to native host...");
    nativePort = chrome.runtime.connectNative(HOST_NAME);

    nativePort.onMessage.addListener(handleNativeMessage);

    nativePort.onDisconnect.addListener(() => {
        console.warn("[SecureVault] Native host disconnected:", chrome.runtime.lastError);
        nativePort = null;
        // Optional: Auto-reconnect or wait for user action?
        // We'll leave it null so popup checks and reconnects if needed.
    });
}

/**
 * Handles messages coming from the Python host.
 * Typically these are responses to our requests (GET_CREDENTIALS, UNLOCK, etc.)
 * Since port is asynchronous, we need to route these back to the requestor (Popup).
 * A simple way is to broadcast or use a temporary listener mapping, but broadcasting is easiest for Phase 3.
 */
function handleNativeMessage(message) {
    console.log("[SecureVault] Received from host:", message);
    // Broadcast to Popup
    chrome.runtime.sendMessage({ type: "HOST_RESPONSE", payload: message });
}

// Connect immediately on startup
connectToHost();

/**
 * Handles messages from Popup or Content Script.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SEND_TO_HOST") {
        if (!nativePort) {
            connectToHost();
        }

        try {
            nativePort.postMessage(message.payload);
            sendResponse({ success: true });
        } catch (e) {
            console.error("[SecureVault] Failed to send to host:", e);
            sendResponse({ success: false, error: e.message });
        }
    }

    return true; // Keep channel open for async response if needed
});
