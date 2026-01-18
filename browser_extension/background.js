// background.js - Service Worker for URL Sentinel

const MONITOR_DURATION_MS = 60 * 60 * 1000; // 1 Hour

// Auto-start on install or startup
chrome.runtime.onInstalled.addListener(() => {
    startMonitoring();
});

chrome.runtime.onStartup.addListener(() => {
    startMonitoring();
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'startMonitoring') {
        startMonitoring();
        sendResponse({ status: 'started' });
    } else if (request.action === 'stopMonitoring') {
        stopMonitoring();
        sendResponse({ status: 'stopped' });
    } else if (request.action === 'getStatus') {
        checkStatus(sendResponse);
        return true; // Keep channel open for async response
    }
});

// Check status and auto-stop if time expired
function checkStatus(callback) {
    chrome.storage.local.get(['isMonitoring', 'startTime'], (result) => {
        if (result.isMonitoring) {
            const elapsed = Date.now() - (result.startTime || 0);
            if (elapsed > MONITOR_DURATION_MS) {
                stopMonitoring();
                callback({ isMonitoring: false });
            } else {
                callback({ isMonitoring: true, startTime: result.startTime });
            }
        } else {
            callback({ isMonitoring: false });
        }
    });
}

function startMonitoring() {
    const startTime = Date.now();
    chrome.storage.local.set({ isMonitoring: true, startTime: startTime }, () => {
        console.log('Monitoring started automatically');
        chrome.action.setBadgeText({ text: 'ON' });
        chrome.action.setBadgeBackgroundColor({ color: '#3498db' });
    });
}

function stopMonitoring() {
    chrome.storage.local.set({ isMonitoring: false }, () => {
        console.log('Monitoring stopped');
        chrome.action.setBadgeText({ text: 'OFF' });
        chrome.action.setBadgeBackgroundColor({ color: '#7f8c8d' });
    });
}

// Monitor Tab Updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        chrome.storage.local.get(['isMonitoring', 'startTime'], (result) => {
            if (result.isMonitoring) {
                // Check timer again to be safe
                const elapsed = Date.now() - (result.startTime || 0);
                if (elapsed > MONITOR_DURATION_MS) {
                    stopMonitoring();
                    return;
                }

                // Scan the URL
                scanUrl(tab.url, tabId);
            }
        });
    }
});

function scanUrl(url, tabId) {
    // Set loading badge
    chrome.action.setBadgeText({ text: '...', tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#f39c12', tabId: tabId });

    fetch('http://127.0.0.1:5000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, use_combined_analysis: true })
    })
        .then(res => res.json())
        .then(data => {
            // Update Badge
            if (data.score < 50) {
                chrome.action.setBadgeText({ text: 'SAFE', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#2ecc71', tabId: tabId }); // Green
            } else if (data.score < 80) {
                chrome.action.setBadgeText({ text: data.score.toString(), tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#f39c12', tabId: tabId }); // Orange
            } else {
                chrome.action.setBadgeText({ text: 'RISK', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#e74c3c', tabId: tabId }); // Red
            }

            // Send to Content Script for Overlay
            chrome.tabs.sendMessage(tabId, { action: 'showOverlay', data: data }).catch(() => {
                // Ignore error if content script not loaded (e.g. on restricted pages)
            });

            // Alert for high risk
            if (data.score >= 50) {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png',
                    title: 'Threat Detected!',
                    message: `Warning: ${data.verdict} site detected.\nScore: ${data.score}/100\nURL: ${url}`,
                    priority: 2
                });
            }
        })
        .catch(err => {
            console.error('Scan error:', err);
            chrome.action.setBadgeText({ text: 'ERR', tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#95a5a6', tabId: tabId });
        });
}
