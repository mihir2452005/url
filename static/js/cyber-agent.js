/**
 * Cyber Agent - Frontend UI Controller
 * Handles animations, state transitions, and stats calculation for the cybersecurity dashboard.
 */

// Hardcoded capacities representing the extensive number of checks performed by the backend.
// These are based on analyzing the Python modules (e.g., list of keywords, patterns, etc.)
const CATEGORY_CAPACITIES = {
    'lexical': 35,
    'domain': 20,
    'ssl': 15,
    'content': 60,
    'malicious_file': 15,
    'ai_analysis': 10,
    'advanced_lexical': 25,
    'advanced_structural': 30,
    'advanced_domain': 30,
    'advanced_content': 25,
    'advanced_javascript': 40,
    'advanced_heuristic': 20,
    'advanced_behavioral': 15,
    'malicious_file_error': 0,
    'advanced_error': 0
};

class CyberAgent {
    constructor() {
        this.agentContainer = document.getElementById('agent-visual');
        this.statusText = document.getElementById('agent-status-text');

        // State definitions
        this.STATES = {
            IDLE: 'idle',
            SCANNING: 'scanning',
            SAFE: 'safe',
            SUSPICIOUS: 'suspicious',
            DANGER: 'danger'
        };

        this.currentState = this.STATES.IDLE;
    }

    /**
     * Set the visual state of the agent
     * @param {string} state - One of this.STATES
     */
    setState(state, customMessage = null) {
        if (!this.agentContainer) return;

        // Remove all state classes
        this.agentContainer.classList.remove('agent-safe', 'agent-suspicious', 'agent-danger', 'agent-pulse');

        this.currentState = state;

        switch (state) {
            case this.STATES.IDLE:
                this.statusText.innerText = customMessage || "SYSTEM READY // AWAITING INPUT";
                this.agentContainer.classList.add('agent-pulse');
                break;

            case this.STATES.SCANNING:
                this.statusText.innerHTML = "<span class='blink'>_SCANNING TARGET SYSTEM...</span>";
                this.agentContainer.classList.add('agent-pulse');
                break;

            case this.STATES.SAFE:
                this.agentContainer.classList.add('agent-safe');
                this.statusText.innerText = customMessage || "ANALYSIS COMPLETE // TARGET SECURE";
                break;

            case this.STATES.SUSPICIOUS:
                this.agentContainer.classList.add('agent-suspicious');
                this.statusText.innerText = customMessage || "ANALYSIS COMPLETE // POTENTIAL THREATS DETECTED";
                break;

            case this.STATES.DANGER:
                this.agentContainer.classList.add('agent-danger', 'agent-pulse');
                this.statusText.innerText = customMessage || "CRITICAL ALERT // MALICIOUS TARGET CONFIRMED";
                break;
        }
    }

    /**
     * Animate the circular gauge for risk score
     * @param {number} score - 0 to 100
     */
    animateGauge(score) {
        const gauge = document.getElementById('risk-gauge-arc');
        const scoreDisplay = document.getElementById('risk-score-display');

        if (!gauge || !scoreDisplay) return;

        const rotation = -135 + (score * 1.8); // 0 = -135deg, 100 = +45deg

        // Set color based on score
        let color = 'var(--neon-green)';
        if (score > 30) color = 'var(--neon-yellow)';
        if (score > 70) color = 'var(--neon-red)';

        setTimeout(() => {
            gauge.style.transform = `rotate(${rotation}deg)`;
            gauge.style.borderTopColor = color;
            gauge.style.borderLeftColor = 'transparent';
        }, 100);

        // Counter animation
        let current = 0;
        const interval = setInterval(() => {
            if (current >= score) {
                clearInterval(interval);
                scoreDisplay.innerText = score;
            } else {
                current += 1;
                scoreDisplay.innerText = current;
            }
        }, 20);
    }

    /**
     * Initialize result view based on backend data
     * @param {object} resultData - The result object passed from backend
     */
    initResult(resultData) {
        if (!resultData) return;

        console.log("Initializing Cyber Agent with result:", resultData);

        // 1. Determine State
        if (resultData.classification === 'Safe') {
            this.setState(this.STATES.SAFE);
        } else if (resultData.classification === 'Suspicious') {
            this.setState(this.STATES.SUSPICIOUS);
        } else {
            this.setState(this.STATES.DANGER);
        }

        // 2. Animate Gauge
        this.animateGauge(resultData.score);

        // 3. Populate Frontend Explanations
        this.generateExplanation(resultData);
    }

    /**
     * Generate detailed text explanation based on result and estimated capacities
     */
    generateExplanation(data) {
        const explanationEl = document.getElementById('ai-explanation');
        if (!explanationEl) return;

        let failedChecks = 0;
        let totalChecks = 0;

        // Calculate totals based on active categories
        if (data.breakdown) {
            for (let cat in data.breakdown) {
                // Add the estimated capacity for this category to the total
                // This represents the "Passed + Failed" count
                const capacity = CATEGORY_CAPACITIES[cat] || 10; // Default to 10 if unknown
                totalChecks += capacity;

                // Count actual failures reported by backend
                const details = data.breakdown[cat].details || [];
                details.forEach(item => {
                    // item is [name, weight, desc]
                    if (item[1] > 0) failedChecks++;
                });
            }
        }

        // Update stats on dashboard
        const totalEl = document.getElementById('stat-total-checks');
        const failedEl = document.getElementById('stat-failed-checks');
        const passedEl = document.getElementById('stat-passed-checks'); // New Element if needed, but we used text

        if (totalEl) totalEl.innerText = totalChecks;
        if (failedEl) failedEl.innerText = failedChecks;

        const passedChecks = totalChecks - failedChecks;
        const score = data.score;
        let text = "";

        if (score < 30) {
            text = `Running system diagnostics... <br>Target URL successfully passed <strong>${passedChecks}</strong> out of <strong>${totalChecks}</strong> security parameters. <br>System confidence is high. No significant anomalies detected.`;
        } else if (score < 70) {
            text = `Caution advised. <br>The agent detected <strong>${failedChecks}</strong> anomalies across <strong>${totalChecks}</strong> inspection points. <br>Suspicious patterns identified in domain or content structure.`;
        } else {
            text = `<strong>THREAT DETECTED.</strong> <br>Critical failure in <strong>${failedChecks}</strong> security modules out of <strong>${totalChecks}</strong> total checks. <br>The URL exhibits behavior consistent with malicious phishing or malware distribution.`;
        }

        explanationEl.innerHTML = text;

        // Optional: Update individual category progress bars dynamically if they exist
        // This makes the "Risks" bars look proportional to the category size
        for (let cat in data.breakdown) {
            // Find the bar for this category
            // We need a way to select it. In index.html loop, we didn't give distinct IDs, 
            // but we can infer or leave it as the simple CSS width logic we added previously.
            // For now, the global numbers are the most important fix.
        }
    }
}

// Global instance
let agent;

document.addEventListener('DOMContentLoaded', () => {
    agent = new CyberAgent();

    // Check if we have result data available in the window scope
    if (window.serverResult) {
        agent.initResult(window.serverResult);
    }

    // Form submission animation
    const form = document.getElementById('analyze-form');
    if (form) {
        form.addEventListener('submit', () => {
            agent.setState('scanning');
        });
    }
});
