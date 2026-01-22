document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-indicator span');
    const scannedCount = document.getElementById('scanned-count');
    const blockedCount = document.getElementById('blocked-count');
    const currentDomain = document.getElementById('current-domain');
    const btnDashboard = document.getElementById('btn-dashboard');
    const togglePrivacy = document.getElementById('toggle-privacy-mode');

    // 1. Get Current Tab Domain
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
            try {
                const url = new URL(tabs[0].url);
                currentDomain.textContent = url.hostname;
            } catch (e) {
                currentDomain.textContent = "System Page";
            }
        }
    });

    // 2. Check Backend Status (Dev: Localhost / Prod: API)
    chrome.runtime.sendMessage({ action: "checkStatus", backendUrl: "http://127.0.0.1:5000" }, (response) => {
        if (response && response.status === 'online') {
            statusDot.className = "status-dot online";
            statusText.textContent = "ONLINE";
        } else {
            statusDot.className = "status-dot offline";
            statusText.textContent = "OFFLINE";
        }
    });

    // 3. Load Stats & Settings
    chrome.storage.local.get(['scannedCount', 'blockedCount', 'privacyMode'], (result) => {
        scannedCount.textContent = result.scannedCount || 0;
        blockedCount.textContent = result.blockedCount || 0;
        togglePrivacy.checked = result.privacyMode || false;
    });

    // 4. Action Buttons
    btnDashboard.addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://127.0.0.1:5000' });
    });

    // 5. Toggle Listeners
    togglePrivacy.addEventListener('change', (e) => {
        chrome.storage.local.set({ privacyMode: e.target.checked });
    });
});
