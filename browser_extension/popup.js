document.addEventListener('DOMContentLoaded', function () {
    const scanBtn = document.getElementById('scan-btn');
    const statusDiv = document.getElementById('status');
    const urlDisplay = document.getElementById('url-display');
    const resultsDiv = document.getElementById('results');
    const scoreVal = document.getElementById('score-val');
    const scoreCircle = document.querySelector('.score-circle');
    const verdictDiv = document.getElementById('verdict');

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs[0] && tabs[0].url) {
            urlDisplay.textContent = tabs[0].url;
        }
    });

    scanBtn.addEventListener('click', function () {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            const activeTab = tabs[0];
            const urlToScan = activeTab.url;

            if (!urlToScan.startsWith('http')) {
                statusDiv.textContent = "Cannot scan this page type.";
                return;
            }

            statusDiv.textContent = "Scanning...";
            scanBtn.disabled = true;
            resultsDiv.classList.add('hidden');

            fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: urlToScan,
                    use_combined_analysis: true
                })
            })
                .then(response => response.json())
                .then(data => {
                    statusDiv.textContent = "Scan complete";
                    scanBtn.disabled = false;
                    resultsDiv.classList.remove('hidden');

                    // Update UI based on result
                    scoreVal.textContent = data.score;
                    verdictDiv.textContent = data.verdict;

                    // Reset classes
                    scoreCircle.className = 'score-circle';

                    if (data.score < 50) {
                        scoreCircle.classList.add('safe');
                        verdictDiv.style.color = '#2ecc71';
                    } else if (data.score < 80) {
                        scoreCircle.classList.add('suspicious');
                        verdictDiv.style.color = '#f39c12';
                    } else {
                        scoreCircle.classList.add('malicious');
                        verdictDiv.style.color = '#e74c3c';
                    }
                })
                .catch(error => {
                    statusDiv.textContent = "Error: Could not connect to local backend.";
                    console.error('Error:', error);
                    scanBtn.disabled = false;
                });
        });
    });
});
