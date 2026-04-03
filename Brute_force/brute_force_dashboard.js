class BruteForceDashboard {
    constructor() {
        this.isRunning = false;
        this.updateInterval = null;
        this.maxAttempts = 0;
        this.logEntries = [];
        
        this.initializeElements();
        this.bindEvents();
        this.startStatusUpdates();
    }
    
    initializeElements() {
        // Form elements
        this.targetIpInput = document.getElementById('target-ip');
        this.targetUsernameInput = document.getElementById('target-username');
        this.passwordMethodSelect = document.getElementById('password-method');
        this.maxAttemptsInput = document.getElementById('max-attempts');
        
        // Buttons
        this.startBtn = document.getElementById('start-btn');
        this.stopBtn = document.getElementById('stop-btn');
        this.resetBtn = document.getElementById('reset-btn');
        this.clearLogBtn = document.getElementById('clear-log');
        this.exportLogBtn = document.getElementById('export-log');
        
        // Status elements
        this.attackStatus = document.getElementById('attack-status');
        this.totalAttempts = document.getElementById('total-attempts');
        this.successfulAttempts = document.getElementById('successful-attempts');
        this.failedAttempts = document.getElementById('failed-attempts');
        this.elapsedTime = document.getElementById('elapsed-time');
        this.currentPassword = document.getElementById('current-password');
        
        // Progress elements
        this.progressFill = document.getElementById('progress-fill');
        this.progressText = document.getElementById('progress-text');
        this.passwordsList = document.getElementById('passwords-list');
        
        // Log element
        this.attackLog = document.getElementById('attack-log');
    }
    
    bindEvents() {
        this.startBtn.addEventListener('click', () => this.startAttack());
        this.stopBtn.addEventListener('click', () => this.stopAttack());
        this.resetBtn.addEventListener('click', () => this.resetDashboard());
        this.clearLogBtn.addEventListener('click', () => this.clearLog());
        this.exportLogBtn.addEventListener('click', () => this.exportLog());
        
        // Form validation
        this.maxAttemptsInput.addEventListener('input', () => this.validateInput());
        this.targetIpInput.addEventListener('input', () => this.validateInput());
        this.targetUsernameInput.addEventListener('input', () => this.validateInput());
    }
    
    validateInput() {
        const ipValid = this.isValidIP(this.targetIpInput.value);
        const usernameValid = this.targetUsernameInput.value.trim().length > 0;
        const attemptsValid = parseInt(this.maxAttemptsInput.value) > 0;
        
        this.startBtn.disabled = !(ipValid && usernameValid && attemptsValid && !this.isRunning);
        
        if (!ipValid && this.targetIpInput.value) {
            this.targetIpInput.style.borderColor = '#e74c3c';
        } else {
            this.targetIpInput.style.borderColor = '';
        }
    }
    
    isValidIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }
    
    async startAttack() {
        const config = {
            target_ip: this.targetIpInput.value.trim(),
            target_username: this.targetUsernameInput.value.trim(),
            password_method: this.passwordMethodSelect.value,
            max_attempts: parseInt(this.maxAttemptsInput.value)
        };
        
        try {
            const response = await fetch('/api/brute-force/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.isRunning = true;
                this.maxAttempts = config.max_attempts;
                this.updateButtonStates();
                this.addLogEntry('info', `Attack started against ${config.target_username}@${config.target_ip}`);
                this.startStatusUpdates();
            } else {
                this.addLogEntry('error', `Failed to start attack: ${result.message}`);
            }
        } catch (error) {
            this.addLogEntry('error', `Network error: ${error.message}`);
        }
    }
    
    async stopAttack() {
        try {
            const response = await fetch('/api/brute-force/stop', {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.isRunning = false;
                this.updateButtonStates();
                this.addLogEntry('warning', 'Attack stopped by user');
            } else {
                this.addLogEntry('error', `Failed to stop attack: ${result.message}`);
            }
        } catch (error) {
            this.addLogEntry('error', `Network error: ${error.message}`);
        }
    }
    
    async fetchAttackStatus() {
        try {
            const response = await fetch('/api/brute-force/status');
            const data = await response.json();
            
            this.updateStatusDisplay(data);
            
            // Check if attack completed
            if (this.isRunning && !data.is_running) {
                this.isRunning = false;
                this.updateButtonStates();
                this.addLogEntry('success', 'Attack completed');
            }
            
        } catch (error) {
            console.error('Error fetching status:', error);
        }
    }
    
    updateStatusDisplay(data) {
        const stats = data.stats;
        
        // Update status
        this.attackStatus.textContent = stats.status.charAt(0).toUpperCase() + stats.status.slice(1);
        this.attackStatus.className = `status-value ${stats.status}`;
        
        // Update counters
        this.totalAttempts.textContent = stats.attempts;
        this.successfulAttempts.textContent = stats.successful_attempts;
        this.failedAttempts.textContent = stats.failed_attempts;
        
        // Update elapsed time
        this.elapsedTime.textContent = this.formatTime(stats.elapsed_time);
        
        // Update current password
        this.currentPassword.textContent = stats.current_password || '-';
        
        // Update progress
        const progress = this.maxAttempts > 0 ? (stats.attempts / this.maxAttempts) * 100 : 0;
        this.progressFill.style.width = `${progress}%`;
        this.progressText.textContent = `${stats.attempts} / ${this.maxAttempts} attempts`;
        
        // Update passwords tried list
        this.updatePasswordsList(stats.passwords_tried || []);
    }
    
    updatePasswordsList(passwords) {
        if (passwords.length === 0) {
            this.passwordsList.innerHTML = '<div class="no-passwords">No passwords tried yet</div>';
            return;
        }
        
        const recentPasswords = passwords.slice(-10).reverse();
        this.passwordsList.innerHTML = recentPasswords.map((password, index) => {
            const isLatest = index === 0;
            const cssClass = isLatest ? 'password-item latest' : 'password-item';
            return `
                <div class="${cssClass}">
                    <span>${password}</span>
                    <span>${isLatest ? 'Current' : ''}</span>
                </div>
            `;
        }).join('');
    }
    
    updateButtonStates() {
        this.startBtn.disabled = this.isRunning;
        this.stopBtn.disabled = !this.isRunning;
        
        if (this.isRunning) {
            this.startBtn.innerHTML = '<i class="fas fa-play"></i> Running...';
        } else {
            this.startBtn.innerHTML = '<i class="fas fa-play"></i> Start Attack';
        }
    }
    
    startStatusUpdates() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        
        this.updateInterval = setInterval(() => {
            if (this.isRunning) {
                this.fetchAttackStatus();
            }
        }, 1000);
    }
    
    resetDashboard() {
        // Stop any running attack
        if (this.isRunning) {
            this.stopAttack();
        }
        
        // Reset form
        this.targetIpInput.value = '192.168.1.100';
        this.targetUsernameInput.value = 'admin';
        this.passwordMethodSelect.value = 'common';
        this.maxAttemptsInput.value = '50';
        
        // Reset status display
        this.attackStatus.textContent = 'Stopped';
        this.attackStatus.className = 'status-value stopped';
        this.totalAttempts.textContent = '0';
        this.successfulAttempts.textContent = '0';
        this.failedAttempts.textContent = '0';
        this.elapsedTime.textContent = '00:00:00';
        this.currentPassword.textContent = '-';
        
        // Reset progress
        this.progressFill.style.width = '0%';
        this.progressText.textContent = '0 / 0 attempts';
        this.passwordsList.innerHTML = '<div class="no-passwords">No passwords tried yet</div>';
        
        // Clear logs
        this.clearLog();
        
        // Update buttons
        this.updateButtonStates();
        this.validateInput();
        
        this.addLogEntry('info', 'Dashboard reset');
    }
    
    addLogEntry(type, message) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = {
            timestamp,
            type,
            message
        };
        
        this.logEntries.push(logEntry);
        
        const logElement = document.createElement('div');
        logElement.className = `log-entry ${type}`;
        logElement.innerHTML = `
            <span class="timestamp">[${timestamp}]</span>
            <span class="message">${message}</span>
        `;
        
        this.attackLog.appendChild(logElement);
        this.attackLog.scrollTop = this.attackLog.scrollHeight;
        
        // Limit log entries to prevent memory issues
        if (this.logEntries.length > 100) {
            this.logEntries.shift();
            this.attackLog.removeChild(this.attackLog.firstChild);
        }
    }
    
    clearLog() {
        this.logEntries = [];
        this.attackLog.innerHTML = `
            <div class="log-entry info">
                <span class="timestamp">[${new Date().toLocaleTimeString()}]</span>
                <span class="message">Log cleared</span>
            </div>
        `;
    }
    
    exportLog() {
        if (this.logEntries.length === 0) {
            this.addLogEntry('warning', 'No log entries to export');
            return;
        }
        
        const logText = this.logEntries.map(entry => 
            `[${entry.timestamp}] [${entry.type.toUpperCase()}] ${entry.message}`
        ).join('\n');
        
        const blob = new Blob([logText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `brute_force_log_${new Date().toISOString().slice(0,10)}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.addLogEntry('info', 'Log exported successfully');
    }
    
    formatTime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        return [hours, minutes, secs]
            .map(val => val.toString().padStart(2, '0'))
            .join(':');
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new BruteForceDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.dashboard && window.dashboard.updateInterval) {
        clearInterval(window.dashboard.updateInterval);
    }
});
