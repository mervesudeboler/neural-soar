/**
 * Neural SOAR Dashboard - Client-side JavaScript
 * Real-time visualization and chart management
 */

// Global state
const DashboardClient = {
    socket: null,
    charts: {},
    isConnected: false,
    lastUpdate: Date.now(),
    pollingInterval: null,
    
    /**
     * Initialize the dashboard
     */
    init: function() {
        console.log('[Dashboard] Initializing...');
        this.initializeClock();
        this.initializeCharts();
        this.connectWebSocket();
        this.setupPollingFallback();
        this.setupSimulateButton();
        console.log('[Dashboard] Initialization complete');
    },
    
    /**
     * Initialize live clock display
     */
    initializeClock: function() {
        const updateClock = () => {
            const now = new Date();
            const timeStr = now.toLocaleTimeString('en-US', { hour12: true });
            const dateStr = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
            const clockEl = document.getElementById('liveClock');
            if (clockEl) {
                clockEl.textContent = timeStr + ' ' + dateStr;
            }
        };
        updateClock();
        setInterval(updateClock, 1000);
    },
    
    /**
     * Initialize all Chart.js charts
     */
    initializeCharts: function() {
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: 'rgba(224, 224, 224, 0.8)',
                        font: { family: "'Courier New', monospace", size: 11 }
                    }
                }
            }
        };

        // Attack Distribution Chart (Doughnut)
        const attackCtx = document.getElementById('attackChart');
        if (attackCtx) {
            this.charts.attack = new Chart(attackCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'Malware', 'Reconnaissance'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ff1744', '#ff9100', '#ffd600', '#4caf50', '#00bfff', '#00ff41'
                        ],
                        borderColor: '#1a1f3a',
                        borderWidth: 2
                    }]
                },
                options: {
                    ...chartOptions,
                    plugins: {
                        ...chartOptions.plugins,
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return context.label + ': ' + context.parsed;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Response Latency Chart (Line)
        const latencyCtx = document.getElementById('latencyChart');
        if (latencyCtx) {
            this.charts.latency = new Chart(latencyCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Response Time (ms)',
                        data: [],
                        borderColor: '#00bfff',
                        backgroundColor: 'rgba(0, 191, 255, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointBackgroundColor: '#00ff41',
                        pointBorderColor: '#00bfff',
                        pointRadius: 3,
                        pointHoverRadius: 5
                    }]
                },
                options: {
                    ...chartOptions,
                    scales: {
                        y: {
                            min: 0,
                            max: 500,
                            ticks: { color: 'rgba(224, 224, 224, 0.6)', font: { size: 10 } },
                            grid: { color: 'rgba(42, 63, 95, 0.5)' }
                        },
                        x: {
                            ticks: { color: 'rgba(224, 224, 224, 0.6)', font: { size: 10 } },
                            grid: { color: 'rgba(42, 63, 95, 0.5)' }
                        }
                    }
                }
            });
        }

        // Reward Curve Chart (Line)
        const rewardCtx = document.getElementById('rewardChart');
        if (rewardCtx) {
            this.charts.reward = new Chart(rewardCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Average Reward',
                        data: [],
                        borderColor: '#00ff41',
                        backgroundColor: 'rgba(0, 255, 65, 0.1)',
                        borderWidth: 3,
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: '#00bfff',
                        pointBorderColor: '#00ff41',
                        pointRadius: 3,
                        pointHoverRadius: 6,
                        pointBorderWidth: 2
                    }]
                },
                options: {
                    ...chartOptions,
                    scales: {
                        y: {
                            min: -1,
                            max: 1,
                            ticks: { color: 'rgba(224, 224, 224, 0.6)', font: { size: 10 } },
                            grid: { color: 'rgba(42, 63, 95, 0.5)' }
                        },
                        x: {
                            ticks: { color: 'rgba(224, 224, 224, 0.6)', font: { size: 10 } },
                            grid: { color: 'rgba(42, 63, 95, 0.5)' }
                        }
                    }
                }
            });
        }

        console.log('[Charts] Initialized 3 charts');
    },
    
    /**
     * Connect to WebSocket server
     */
    connectWebSocket: function() {
        try {
            this.socket = io.connect(window.location.origin);

            this.socket.on('connect', () => {
                this.isConnected = true;
                this.updateConnectionStatus(true);
                console.log('[WebSocket] Connected');
            });

            this.socket.on('disconnect', () => {
                this.isConnected = false;
                this.updateConnectionStatus(false);
                console.log('[WebSocket] Disconnected');
            });

            this.socket.on('new_event', (event) => {
                this.addEventToFeed(event);
            });

            this.socket.on('new_action', (action) => {
                this.addActionToTable(action);
            });

            this.socket.on('state_update', (data) => {
                this.updateSystemState(data.state, data.metrics, data.training);
            });

            this.socket.on('error', (error) => {
                console.error('[WebSocket] Error:', error);
            });
        } catch (e) {
            console.warn('[WebSocket] Connection failed:', e.message);
        }
    },
    
    /**
     * Setup polling fallback for when WebSocket is unavailable
     */
    setupPollingFallback: function() {
        this.pollingInterval = setInterval(() => {
            if (!this.isConnected) {
                this.pollState();
            }
        }, 2000);
    },
    
    /**
     * Poll server for state updates
     */
    pollState: function() {
        Promise.all([
            fetch('/api/state').then(r => r.json()),
            fetch('/api/metrics').then(r => r.json()),
            fetch('/api/training').then(r => r.json())
        ])
        .then(([state, metrics, training]) => {
            this.updateSystemState(state, metrics, training);
        })
        .catch(e => console.error('[Polling] Error:', e));
    },
    
    /**
     * Update all system state displays
     * @param {Object} state - System state data
     * @param {Object} metrics - System metrics
     * @param {Object} training - Training statistics
     */
    updateSystemState: function(state, metrics, training) {
        if (!state || !metrics) return;

        // Update CPU gauge
        const cpu = parseFloat(state.cpu_usage || 45);
        const cpuValue = document.getElementById('cpuValue');
        const cpuGauge = document.getElementById('cpuGauge');
        if (cpuValue) cpuValue.textContent = cpu.toFixed(1) + '%';
        if (cpuGauge) cpuGauge.style.width = Math.min(100, cpu) + '%';

        // Update active connections
        const connections = parseInt(state.active_connections || 128);
        const connValue = document.getElementById('connectionsValue');
        if (connValue) connValue.textContent = connections.toString();

        // Update trust score
        const trust = parseFloat(state.trust_score || 0.92);
        const trustValue = document.getElementById('trustScoreValue');
        const trustGauge = document.getElementById('trustGauge');
        if (trustValue) trustValue.textContent = (trust * 100).toFixed(1) + '%';
        if (trustGauge) trustGauge.style.width = (trust * 100) + '%';

        // Update threat level badge
        const threatLevel = state.threat_level || 'MEDIUM';
        const threatBadge = document.getElementById('threatBadge');
        if (threatBadge) {
            threatBadge.textContent = threatLevel;
            threatBadge.className = 'threat-badge threat-' + threatLevel.toLowerCase();
        }

        // Update security metrics
        if (metrics) {
            this.updateMetrics(metrics);
        }

        // Update charts with metrics data
        if (metrics) {
            if (metrics.attack_types) {
                this.updateAttackChart(metrics.attack_types);
            }
            if (metrics.response_times && metrics.response_times.length > 0) {
                this.updateLatencyChart(metrics.response_times);
            }
        }

        // Update training chart
        if (training && training.reward_history) {
            this.updateRewardChart(training.reward_history);
        }

        this.lastUpdate = Date.now();
    },
    
    /**
     * Update metric cards
     * @param {Object} metrics - Metrics object
     */
    updateMetrics: function(metrics) {
        const updates = {
            'totalAttacksMetric': metrics.total_attacks || 0,
            'blockedAttacksMetric': metrics.blocked_attacks || 0,
            'honeypotMetric': metrics.honeypot_redirects || 0,
            'securityScoreMetric': (metrics.security_score || 95.5).toFixed(1),
            'falsePositiveMetric': (metrics.false_positive_rate || 0.02).toFixed(2),
            'avgResponseMetric': Math.round(metrics.avg_response_time_ms || 145)
        };

        Object.entries(updates).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });
    },
    
    /**
     * Add event to events feed
     * @param {Object} event - Event object
     */
    addEventToFeed: function(event) {
        const feed = document.getElementById('eventsFeed');
        if (!feed) return;
        
        // Clear placeholder if needed
        if (feed.children.length === 1 && feed.children[0].textContent.includes('Waiting')) {
            feed.innerHTML = '';
        }

        const eventEl = document.createElement('div');
        const severity = (event.severity || 'medium').toLowerCase();
        eventEl.className = 'event-item severity-' + severity;
        
        const time = this.formatTimestamp(event.timestamp);
        const attackType = event.attack_type || event.type || 'UNKNOWN';
        
        eventEl.innerHTML = `
            <div class="event-time">${time}</div>
            <div class="event-type">${attackType}</div>
            <div class="event-details">From: ${event.source_ip || 'N/A'} → ${event.target_endpoint || 'N/A'}</div>
        `;
        
        feed.insertBefore(eventEl, feed.firstChild);
        
        // Keep only last 20 visible
        while (feed.children.length > 20) {
            feed.removeChild(feed.lastChild);
        }

        console.log('[Events] Added event:', attackType);
    },
    
    /**
     * Add action to actions table
     * @param {Object} action - Action object
     */
    addActionToTable: function(action) {
        const tbody = document.getElementById('actionsTableBody');
        if (!tbody) return;
        
        // Clear placeholder if needed
        if (tbody.children.length === 1 && tbody.children[0].textContent.includes('No actions')) {
            tbody.innerHTML = '';
        }

        const row = document.createElement('tr');
        const actionType = (action.action_type || 'MONITOR').replace(/_/g, ' ');
        const actionClass = 'action-type-' + (action.action_type || 'MONITOR').toLowerCase().replace(/_/g, '-');
        
        row.innerHTML = `
            <td>${this.formatTimestamp(action.timestamp)}</td>
            <td class="${actionClass}">${actionType}</td>
            <td>${action.target || 'N/A'}</td>
            <td>${action.status || 'UNKNOWN'}</td>
            <td>${action.details || ''}</td>
        `;
        
        tbody.insertBefore(row, tbody.firstChild);
        
        // Keep only last 20 visible
        while (tbody.children.length > 20) {
            tbody.removeChild(tbody.lastChild);
        }

        console.log('[Actions] Added action:', actionType);
    },
    
    /**
     * Format timestamp to HH:MM:SS format
     * @param {string} ts - ISO timestamp
     * @returns {string} Formatted time
     */
    formatTimestamp: function(ts) {
        if (!ts) return '--:--:--';
        const date = new Date(ts);
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${hours}:${minutes}:${seconds}`;
    },
    
    /**
     * Update connection status indicator
     * @param {boolean} connected - Connection status
     */
    updateConnectionStatus: function(connected) {
        const dot = document.getElementById('connectionDot');
        const status = document.getElementById('connectionStatus');
        
        if (dot) {
            dot.className = connected ? 'connection-dot connection-connected' : 'connection-dot connection-disconnected';
        }
        if (status) {
            status.textContent = connected ? 'WebSocket Connected' : 'Polling Fallback';
        }
    },
    
    /**
     * Update attack distribution chart
     * @param {Object} attackTypes - Attack type counts
     */
    updateAttackChart: function(attackTypes) {
        const chart = this.charts.attack;
        if (!chart) return;

        const types = ['SQL_INJECTION', 'XSS', 'DDoS', 'BRUTE_FORCE', 'MALWARE', 'RECONNAISSANCE'];
        const data = types.map(t => attackTypes[t] || 0);
        
        chart.data.datasets[0].data = data;
        chart.update('none');
    },
    
    /**
     * Update response latency chart
     * @param {Array} responseTimes - Array of response times
     */
    updateLatencyChart: function(responseTimes) {
        const chart = this.charts.latency;
        if (!chart) return;

        const labels = Array.from({ length: responseTimes.length }, (_, i) => i);
        chart.data.labels = labels;
        chart.data.datasets[0].data = responseTimes;
        chart.update('none');
    },
    
    /**
     * Update reward curve chart
     * @param {Array} rewardHistory - Array of rewards
     */
    updateRewardChart: function(rewardHistory) {
        const chart = this.charts.reward;
        if (!chart) return;

        const labels = Array.from({ length: rewardHistory.length }, (_, i) => i);
        chart.data.labels = labels;
        chart.data.datasets[0].data = rewardHistory;
        chart.update('none');
    },
    
    /**
     * Setup simulate attack button
     */
    setupSimulateButton: function() {
        // Create button
        const button = document.createElement('button');
        button.textContent = 'Simulate Attack';
        button.id = 'simulateBtn';
        button.style.cssText = `
            padding: 8px 16px;
            background: rgba(255, 23, 68, 0.2);
            border: 1px solid #ff1744;
            color: #ff1744;
            border-radius: 4px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
        `;
        
        button.onmouseover = function() {
            this.style.background = 'rgba(255, 23, 68, 0.3)';
            this.style.boxShadow = '0 0 10px rgba(255, 23, 68, 0.5)';
        };
        button.onmouseout = function() {
            this.style.background = 'rgba(255, 23, 68, 0.2)';
            this.style.boxShadow = 'none';
        };
        button.onclick = () => this.triggerSimulatedAttack();
        
        // Insert button into header
        const statusIndicator = document.querySelector('.status-indicator');
        if (statusIndicator && statusIndicator.parentElement) {
            statusIndicator.parentElement.insertBefore(button, statusIndicator.nextSibling);
        }

        console.log('[UI] Simulate button setup complete');
    },
    
    /**
     * Trigger a simulated attack
     */
    triggerSimulatedAttack: function() {
        const attacks = ['SQL_INJECTION', 'XSS', 'DDoS', 'BRUTE_FORCE', 'MALWARE', 'RECONNAISSANCE'];
        const attack = attacks[Math.floor(Math.random() * attacks.length)];
        
        fetch('/api/simulate/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attack })
        })
        .then(r => r.json())
        .then(data => {
            console.log('[Simulate] Attack triggered:', attack, data);
        })
        .catch(e => console.error('[Simulate] Error:', e));
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    DashboardClient.init();
});
