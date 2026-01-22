/* content.js: The Guardian "Hover" Engine */

// State
let hoverTimer = null;
const HOVER_DELAY = 200; // ms
const API_URL = "http://127.0.0.1:5000/analyze"; // Should be configurable via storage

// Add styles to page
const linkStyle = document.createElement('link');
linkStyle.rel = 'stylesheet';
linkStyle.href = chrome.runtime.getURL('styles.css');
document.head.appendChild(linkStyle);

// Tooltip Element
const tooltip = document.createElement('div');
tooltip.id = 'url-sentinel-tooltip';
tooltip.style.display = 'none';
document.body.appendChild(tooltip);

// Event Delegation for Performance
document.addEventListener('mouseover', (e) => {
    const target = e.target.closest('a');
    if (target && target.href) {
        // Start debounce timer
        hoverTimer = setTimeout(() => {
            scanLink(target, e.clientX, e.clientY);
        }, HOVER_DELAY);
    }
});

document.addEventListener('mouseout', (e) => {
    const target = e.target.closest('a');
    if (target) {
        clearTimeout(hoverTimer);
        hideTooltip();
    }
});

// Click Interception
document.addEventListener('click', (e) => {
    const target = e.target.closest('a');
    if (target && target.dataset.risk === 'high') {
        const confirmVisit = confirm("⚠️ URL SENTINEL WARNING ⚠️\n\nThis link has been flagged as MALICIOUS.\n\nRisk: " + target.dataset.riskReason + "\n\nDo you really want to proceed?");
        if (!confirmVisit) {
            e.preventDefault();
            e.stopPropagation();
        }
    }
}, true); // Capture phase to intervene early

async function scanLink(element, x, y) {
    const url = element.href;

    // Show "Scanning..."
    showTooltip(x, y, "Scanning...", "loading");

    // PRIVACY CHECK (Local): Avoid network call entirely if Privacy Mode is active
    chrome.storage.local.get(['privacyMode'], async (result) => {
        if (result.privacyMode) {
            console.log("Titan: Privacy Mode Active. Aborting scan.");
            hideTooltip();
            return;
        }

        // Use background script to fetch to avoid Mixed Content (HTTPS -> HTTP) errors
        try {
            const response = await chrome.runtime.sendMessage({
                action: "analyzeUrl",
                url: url,
                apiUrl: API_URL
            });

            // Check for runtime errors or empty response
            if (chrome.runtime.lastError || !response) {
                console.log("Titan: Scan aborted or connection failed (Privacy Mode?)");
                hideTooltip(); // Assume privacy/safe fail-open
                return;
            }

            if (response.error) {
                throw new Error(response.error);
            }

            const data = response;

            // PRIVACY MODE CHECK
            if (data.note === "Privacy Mode Enabled") {
                hideTooltip();
                return;
            }

            if (data.verdict === "Malicious" || data.verdict === "Phishing" || data.score > 70) {
                // Mark element
                element.dataset.risk = 'high';
                // Extract risk names safely
                let riskFactors = [];
                if (data.risks) {
                    Object.values(data.risks).forEach(r => {
                        if (Array.isArray(r) && r.length === 2 && Array.isArray(r[1])) { // (score, details[])
                            r[1].forEach(d => riskFactors.push(d));
                        }
                    });
                }
                element.dataset.riskReason = riskFactors.map(r => r[0]).join(', ');

                // Update Tooltip
                showTooltip(x, y, `⚠️ DANGER: Risk Score ${data.score}`, "danger", riskFactors);

                // TITAN PHASE 3++: ACTIVE DEFENSE
                if (data.score > 85) {
                    activeDefense(data.score);
                }
            } else {
                showTooltip(x, y, "✅ Safe Link", "safe");
            }
        } catch (error) {
            console.error("Titan Scan Error:", error);
            showTooltip(x, y, "Error connecting to Sentinel", "error");
        }
    }); // End local storage check
}

// ==========================================
// TITAN MODULE: "THE MATRIX" & "THE CHAMELEON"
// ==========================================

function activeDefense(riskScore) {
    console.log("🛡️ TITAN: Engaging Active Defense Protocols...");

    // 1. Visual Defacement ("The Matrix")
    defaceSite();

    // 2. Form Poisoning ("The Chameleon")
    if (riskScore > 90) {
        setTimeout(poisonForms, 2000); // Wait for user to potentially land/interact
    }
}

function defaceSite() {
    // Replace all images with "DANGER" placeholder
    const images = document.getElementsByTagName('img');
    for (let img of images) {
        // Only target significant images (likely logos)
        if (img.width > 50 && img.height > 50) {
            img.style.filter = "grayscale(100%) contrast(200%)";
            img.style.border = "5px solid red";
        }
    }

    // Rewrite specific text
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while (node = walk.nextNode()) {
        const text = node.nodeValue;
        if (text.match(/login|sign in|password|bank|secure/i)) {
            node.nodeValue = text.replace(/login|sign in|password|bank|secure/gi, "⚠️ SCAM DETECTED ⚠️");
        }
    }

    // Inject massive warning banner
    const banner = document.createElement('div');
    banner.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; z-index: 2147483647;
        background: red; color: white; font-size: 24px; font-weight: bold;
        text-align: center; padding: 20px; border-bottom: 5px solid black;
    `;
    banner.innerText = "🛑 URL SENTINEL: THIS SITE IS A VERIFIED SCAM. DO NOT ENTER DATA. 🛑";
    document.body.prepend(banner);
}

function poisonForms() {
    const forms = document.forms;
    if (forms.length === 0) return;

    console.log("🦎 CHAMELEON: Injecting poison data...");

    const fakeUsers = ['admin_test', 'user123', 'john.doe99', 'test_act_88'];
    const fakePass = ['123456', 'password', 'qwerty', 'letmein123'];

    for (let form of forms) {
        let poisoned = false;

        // Find inputs
        const inputs = form.getElementsByTagName('input');
        for (let input of inputs) {
            const type = input.type.toLowerCase();
            const name = input.name.toLowerCase();

            if (name.includes('user') || name.includes('email') || type === 'email') {
                input.value = fakeUsers[Math.floor(Math.random() * fakeUsers.length)];
                input.style.backgroundColor = "#ffcccc"; // Visual indicator of poisoning
                poisoned = true;
            }

            if (type === 'password') {
                input.value = fakePass[Math.floor(Math.random() * fakePass.length)];
                input.style.backgroundColor = "#ffcccc";
                poisoned = true;
            }
        }

        // Auto-submit if confirmed dangerous and poisoned
        /* 
        // SAFETY OFF: In a real "God Mode" extension, we would uncomment this to flood the attacker.
        // For demonstration/safety, we just fill it.
        if (poisoned) {
             form.submit(); 
        } 
        */
    }
}

function showTooltip(x, y, text, type, details = []) {
    tooltip.textContent = '';

    const header = document.createElement('div');
    header.className = 'uls-header';
    header.textContent = text;
    tooltip.appendChild(header);

    if (details.length > 0) {
        const list = document.createElement('ul');
        details.slice(0, 3).forEach(detail => {
            const li = document.createElement('li');
            li.textContent = detail[0]; // Risk name
            list.appendChild(li);
        });
        tooltip.appendChild(list);
    }

    tooltip.className = `uls-tooltip uls-${type}`;
    tooltip.style.left = `${x + 15}px`;
    tooltip.style.top = `${y + 15}px`;
    tooltip.style.display = 'block';
}

function hideTooltip() {
    tooltip.style.display = 'none';
}
