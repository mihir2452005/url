// Frontend enhancements
function copyToClipboard(text) {
    if (navigator.clipboard) {
        // Modern browsers
        navigator.clipboard.writeText(text).then(() => {
            // Show visual feedback
            showCopyFeedback();
        }).catch(err => {
            console.error('Failed to copy: ', err);
            fallbackCopy(text);
        });
    } else {
        // Fallback for older browsers
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    // Create temporary textarea
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopyFeedback();
    } catch (err) {
        console.error('Fallback copy failed: ', err);
    }
    
    document.body.removeChild(textArea);
}

function showCopyFeedback() {
    // Create temporary feedback element
    const feedback = document.createElement('div');
    feedback.textContent = 'Copied!';
    feedback.style.position = 'fixed';
    feedback.style.bottom = '20px';
    feedback.style.right = '20px';
    feedback.style.backgroundColor = '#28a745';
    feedback.style.color = 'white';
    feedback.style.padding = '10px 15px';
    feedback.style.borderRadius = '5px';
    feedback.style.zIndex = '10000';
    feedback.style.fontWeight = 'bold';
    
    document.body.appendChild(feedback);
    
    // Remove after 2 seconds
    setTimeout(() => {
        document.body.removeChild(feedback);
    }, 2000);
}

document.addEventListener('DOMContentLoaded', () => {
    // Real-time preview (optional)
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.addEventListener('input', (e) => {
            // Simple validation preview
            const feedback = document.createElement('div');
            feedback.className = 'form-text';
            feedback.textContent = e.target.validity.valid ? 'Valid URL' : 'Invalid format';
            urlInput.parentNode.appendChild(feedback);
        });
    }
});