// Background Service Worker
// Handles installation, state management, and communication

chrome.runtime.onInstalled.addListener(() => {
    console.log("URL Sentinel: Guardian installed.");

    // CONFIGURATION
    const IS_DEV = true; // Set to FALSE for Web Store Release
    const PROD_API = "https://api.url-sentinel.com";
    const DEV_API = "http://127.0.0.1:5000";

    // Initialize default settings
    chrome.storage.local.set({
        enabled: true,
        backendUrl: IS_DEV ? DEV_API : PROD_API,
        hoverDelay: 200, // ms before triggering scan
        scannedCount: 0,
        blockedCount: 0,
        privacyMode: false
    });
});

// Listener for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkStatus") {
        // Ping backend to see if it's alive
        checkBackendHealth(request.backendUrl).then(isAlive => {
            sendResponse({ status: isAlive ? "online" : "offline" });
        });
        return true; // Keep channel open for async response
    }

    if (request.action === "analyzeUrl") {
        // Increment scan count
        chrome.storage.local.get(['scannedCount', 'privacyMode'], (result) => {
            // PRIVACY CHECK: If enabled, return generic Safe verdict (simulated) or block scan
            if (result.privacyMode) {
                sendResponse({
                    verdict: "Safe",
                    classification: "Safe",
                    score: 0,
                    confidence: 100,
                    note: "Privacy Mode Enabled"
                });
                return;
            }

            const count = (result.scannedCount || 0) + 1;
            chrome.storage.local.set({ scannedCount: count });

            fetch(request.apiUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: request.url })
            })
                .then(response => response.json())
                .then(data => {
                    // Check for threat
                    if (data.verdict === "Malicious" || data.verdict === "Phishing" || data.score > 70) {
                        chrome.storage.local.get(['blockedCount'], (result) => {
                            const count = (result.blockedCount || 0) + 1;
                            chrome.storage.local.set({ blockedCount: count });
                        });
                    }
                    sendResponse(data);
                })
                .catch(error => sendResponse({ error: error.message }));
        });
        return true; // Keep channel open
    }
});

async function checkBackendHealth(baseUrl) {
    try {
        const response = await fetch(`${baseUrl}/healthz`);
        return response.ok;
    } catch (e) {
        return false;
    }
}
