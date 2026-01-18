// content.js - In-Page Status Overlay

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'showOverlay') {
        showOverlay(request.data);
    }
});

function showOverlay(data) {
    // Remove existing overlay if present
    const existing = document.getElementById('url-sentinel-overlay');
    if (existing) existing.remove();

    // Create overlay container
    const overlay = document.createElement('div');
    overlay.id = 'url-sentinel-overlay';

    // Styles
    Object.assign(overlay.style, {
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        zIndex: '2147483647', // Max z-index
        backgroundColor: 'white',
        padding: '10px 15px',
        borderLeft: '5px solid #bdc3c7',
        borderRadius: '4px',
        boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
        fontFamily: 'Arial, sans-serif',
        fontSize: '14px',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        transition: 'opacity 0.5s ease-in-out',
        opacity: '0',
        pointerEvents: 'none' // Let clicks pass through initially
    });

    // Content
    let color = '#95a5a6';
    let text = 'ANALYZING...';

    if (data.score < 50) {
        color = '#2ecc71'; // Green
        text = 'SAFE';
        overlay.style.borderLeftColor = color;
    } else if (data.score < 80) {
        color = '#f39c12'; // Orange
        text = 'SUSPICIOUS';
        overlay.style.borderLeftColor = color;
    } else {
        color = '#e74c3c'; // Red
        text = 'RISK DETECTED';
        overlay.style.borderLeftColor = color;
    }

    // HTML Structure
    overlay.innerHTML = `
    <div style="
      width: 10px; 
      height: 10px; 
      background-color: ${color}; 
      border-radius: 50%;">
    </div>
    <div style="display: flex; flex-direction: column;">
      <span style="font-weight: bold; color: #333; font-size: 12px; letter-spacing: 0.5px;">URL SENTINEL</span>
      <span style="font-weight: bold; color: ${color}; font-size: 14px;">${text}</span>
    </div>
  `;

    // Append to body
    document.body.appendChild(overlay);

    // Fade In
    requestAnimationFrame(() => {
        overlay.style.opacity = '1';
    });

    // Auto-hide after 5 seconds if safe
    if (data.score < 50) {
        setTimeout(() => {
            overlay.style.opacity = '0';
            setTimeout(() => overlay.remove(), 500);
        }, 5000);
    } else {
        // Keep visible for risks and enable interaction (e.g. to close)
        overlay.style.pointerEvents = 'auto';
        overlay.style.cursor = 'pointer';
        overlay.title = "Click to dismiss";
        overlay.onclick = () => overlay.remove();
    }
}
