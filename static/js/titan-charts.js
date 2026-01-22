/* =========================================
   TITAN MODULE: GRID VISUALIZER (CHART.JS)
   ========================================= */

document.addEventListener('DOMContentLoaded', () => {
    initRiskRadar();
});

function initRiskRadar() {
    const ctx = document.getElementById('risk-radar');
    if (!ctx) return;

    // Default Risk Data (If no specific data provided)
    // In production, these should be populated via data attributes from HTML
    const labels = ctx.dataset.labels ? JSON.parse(ctx.dataset.labels) : ['Phishing', 'Malware', 'Suspicious', 'Spam', 'Unusual'];
    const dataPoints = ctx.dataset.scores ? JSON.parse(ctx.dataset.scores) : [0, 0, 0, 0, 0];

    // Calculate total risk for color (0-100)
    const totalRisk = dataPoints.reduce((a, b) => a + b, 0) / (dataPoints.length || 1);

    // Dynamic Colors based on risk
    const borderColor = totalRisk > 50 ? '#ff0055' : '#00f3ff'; // Magenta (Danger) or Cyan (Safe)
    const bgColor = totalRisk > 50 ? 'rgba(255, 0, 85, 0.2)' : 'rgba(0, 243, 255, 0.2)';

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Vector Analysis',
                data: dataPoints,
                backgroundColor: bgColor,
                borderColor: borderColor,
                pointBackgroundColor: borderColor,
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: borderColor,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    pointLabels: {
                        color: '#888',
                        font: {
                            family: '"JetBrains Mono", monospace',
                            size: 10
                        }
                    },
                    ticks: {
                        display: false, // Hide numbers
                        backdropColor: 'transparent'
                    },
                    suggestedMin: 0,
                    suggestedMax: 100
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            },
            animation: {
                duration: 2000,
                easing: 'easeOutQuart'
            }
        }
    });
}
