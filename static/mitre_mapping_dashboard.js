// MITRE Mapping Dashboard JavaScript

class MITREMappingDashboard {
    constructor() {
        this.currentFramework = 'attack';
        this.selectedIP = null;
        this.selectedTechnique = null;
        this.mappingsData = [];
        this.frameworkData = {
            attack: [],
            car: [],
            d3fend: [],
            engage: []
        };
        
        this.initializeElements();
        this.bindEvents();
        this.loadMappings();
    }
    
    initializeElements() {
        // Header stats
        this.mappedTechniquesEl = document.getElementById('mappedTechniques');
        this.mappedIPsEl = document.getElementById('mappedIPs');
        this.totalLogsEl = document.getElementById('totalLogs');
        
        // Sidebar elements
        this.ipSearchEl = document.getElementById('ipSearch');
        this.frameworkFilterEl = document.getElementById('frameworkFilter');
        this.severityFilterEl = document.getElementById('severityFilter');
        this.ipMappingsListEl = document.getElementById('ipMappingsList');
        
        // Framework tabs
        this.tabBtns = document.querySelectorAll('.tab-btn');
        this.frameworkPanels = document.querySelectorAll('.framework-panel');
        
        // Framework grids
        this.attackTechniquesGridEl = document.getElementById('attackTechniquesGrid');
        this.carAnalyticsGridEl = document.getElementById('carAnalyticsGrid');
        this.d3fendDefensesGridEl = document.getElementById('d3fendDefensesGrid');
        this.engageTechniquesGridEl = document.getElementById('engageTechniquesGrid');
        
        // Log details
        this.selectedItemEl = document.getElementById('selectedItem');
        this.logEntriesEl = document.getElementById('logEntries');
        
        // Modal
        this.modalOverlayEl = document.getElementById('modalOverlay');
        this.modalTitleEl = document.getElementById('modalTitle');
        this.modalBodyEl = document.getElementById('modalBody');
        this.investigationModalEl = document.getElementById('investigationModal');
        this.investigationModalBodyEl = document.getElementById('investigationModalBody');
        this.modalCloseEl = document.getElementById('modalClose');
    }
    
    bindEvents() {
        // Tab switching
        this.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => this.switchFramework(btn.dataset.framework));
        });
        
        // Search and filters
        this.ipSearchEl.addEventListener('input', () => this.filterMappings());
        this.frameworkFilterEl.addEventListener('change', () => this.filterMappings());
        this.severityFilterEl.addEventListener('change', () => this.filterMappings());
        
        // Control buttons
        document.getElementById('refreshMappings').addEventListener('click', () => this.loadMappings());
        document.getElementById('exportMappings').addEventListener('click', () => this.exportMappings());
        document.getElementById('clearLogDetails').addEventListener('click', () => this.clearLogDetails());
        
        // Modal
        this.modalCloseEl.addEventListener('click', () => this.closeModal());
        this.modalOverlayEl.addEventListener('click', (e) => {
            if (e.target === this.modalOverlayEl) this.closeModal();
        });
    }
    
    async loadMappings() {
        try {
            this.updateSystemStatus('Loading mappings...', 'loading');
            
            const [mappingsResponse, summaryResponse] = await Promise.all([
                fetch('/api/mitre/mappings/all'),
                fetch('/api/mitre/mappings/summary')
            ]);
            
            const mappings = await mappingsResponse.json();
            const summary = await summaryResponse.json();
            
            this.mappingsData = mappings.mappings;
            this.frameworkData = mappings.framework_data;
            
            this.updateHeaderStats(summary);
            this.renderIPMappings();
            this.renderFrameworkPanels();
            this.updateSystemStatus('Connected', 'connected');
            
        } catch (error) {
            console.error('Error loading mappings:', error);
            this.updateSystemStatus('Error loading mappings', 'error');
        }
    }
    
    updateSystemStatus(text, status) {
        const statusText = document.getElementById('statusText');
        const statusBadge = document.getElementById('systemStatus');
        
        statusText.textContent = text;
        statusBadge.className = `status-badge ${status}`;
    }
    
    updateHeaderStats(summary) {
        this.mappedTechniquesEl.textContent = summary.techniques_detected || 0;
        this.mappedIPsEl.textContent = summary.unique_ips || 0;
        this.totalLogsEl.textContent = summary.total_logs || 0;
    }
    
    renderIPMappings() {
        const ipGroups = this.groupMappingsByIP();
        const filteredGroups = this.filterIPGroups(ipGroups);
        
        this.ipMappingsListEl.innerHTML = '';
        
        Object.entries(filteredGroups).forEach(([ip, mappings]) => {
            const ipItem = this.createIPMappingItem(ip, mappings);
            this.ipMappingsListEl.appendChild(ipItem);
        });
    }
    
    groupMappingsByIP() {
        const groups = {};
        
        this.mappingsData.forEach(mapping => {
            const ip = mapping.ip_address || 'Unknown';
            if (!groups[ip]) {
                groups[ip] = [];
            }
            groups[ip].push(mapping);
        });
        
        return groups;
    }
    
    filterIPGroups(groups) {
        const searchTerm = this.ipSearchEl.value.toLowerCase();
        const frameworkFilter = this.frameworkFilterEl.value;
        const severityFilter = this.severityFilterEl.value;
        
        const filtered = {};
        
        Object.entries(groups).forEach(([ip, mappings]) => {
            // Filter by search term
            if (searchTerm && !ip.toLowerCase().includes(searchTerm)) {
                const hasMatchingTechnique = mappings.some(m => 
                    m.mitre_attack?.technique_id?.toLowerCase().includes(searchTerm) ||
                    m.mitre_car?.analytics_id?.toLowerCase().includes(searchTerm) ||
                    m.mitre_d3fend?.defend_id?.toLowerCase().includes(searchTerm) ||
                    m.mitre_engage?.engage_id?.toLowerCase().includes(searchTerm)
                );
                if (!hasMatchingTechnique) return;
            }
            
            // Filter by severity
            if (severityFilter !== 'all') {
                const hasMatchingSeverity = mappings.some(m => 
                    m.severity?.toLowerCase() === severityFilter
                );
                if (!hasMatchingSeverity) return;
            }
            
            // Filter by framework
            if (frameworkFilter !== 'all') {
                const hasFrameworkMapping = mappings.some(m => 
                    this.hasFrameworkMapping(m, frameworkFilter)
                );
                if (!hasFrameworkMapping) return;
            }
            
            filtered[ip] = mappings;
        });
        
        return filtered;
    }
    
    hasFrameworkMapping(mapping, framework) {
        switch (framework) {
            case 'attack':
                return mapping.mitre_attack && Object.keys(mapping.mitre_attack).length > 0;
            case 'car':
                return mapping.mitre_car && Object.keys(mapping.mitre_car).length > 0;
            case 'd3fend':
                return mapping.mitre_d3fend && Object.keys(mapping.mitre_d3fend).length > 0;
            case 'engage':
                return mapping.mitre_engage && Object.keys(mapping.mitre_engage).length > 0;
            default:
                return false;
        }
    }
    
    createIPMappingItem(ip, mappings) {
        const div = document.createElement('div');
        div.className = 'ip-mapping-item';
        
        const techniques = this.extractTechniques(mappings);
        const severity = this.getHighestSeverity(mappings);
        
        div.innerHTML = `
            <div class="ip-address">
                ${ip}
                <span class="severity-badge severity-${severity.toLowerCase()}">${severity}</span>
                <button class="investigate-btn" onclick="event.stopPropagation(); dashboard.showInvestigationReport('${ip}')" title="Generate Investigation Report">
                    <i class="fas fa-search"></i>
                </button>
            </div>
            <div class="technique-tags">
                ${techniques.map(t => `<span class="technique-tag">${t}</span>`).join('')}
            </div>
        `;
        
        div.addEventListener('click', () => this.selectIP(ip, mappings));
        
        return div;
    }
    
    extractTechniques(mappings) {
        const techniques = new Set();
        
        mappings.forEach(mapping => {
            if (mapping.mitre_attack?.technique_id) {
                techniques.add(mapping.mitre_attack.technique_id);
            }
            if (mapping.mitre_car?.analytics_id) {
                techniques.add(mapping.mitre_car.analytics_id);
            }
            if (mapping.mitre_d3fend?.defend_id) {
                techniques.add(mapping.mitre_d3fend.defend_id);
            }
            if (mapping.mitre_engage?.engage_id) {
                techniques.add(mapping.mitre_engage.engage_id);
            }
        });
        
        return Array.from(techniques).slice(0, 5); // Limit to 5 techniques
    }
    
    getHighestSeverity(mappings) {
        const severities = mappings.map(m => m.severity || 'LOW');
        const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        
        for (const level of severityOrder) {
            if (severities.includes(level)) return level;
        }
        
        return 'LOW';
    }
    
    selectIP(ip, mappings) {
        this.selectedIP = ip;
        this.selectedTechnique = null;
        
        // Update UI
        document.querySelectorAll('.ip-mapping-item').forEach(el => {
            el.classList.remove('selected');
        });
        event.currentTarget.classList.add('selected');
        
        // Show log details
        this.showLogDetails(ip, mappings);
    }
    
    showLogDetails(ip, mappings) {
        this.selectedItemEl.innerHTML = `
            <h3>IP Address: ${ip}</h3>
            <p><strong>Total Mappings:</strong> ${mappings.length}</p>
            <p><strong>Threat Types:</strong> ${[...new Set(mappings.map(m => m.threat_type))].join(', ')}</p>
            <p><strong>Highest Severity:</strong> ${this.getHighestSeverity(mappings)}</p>
        `;
        
        // Show log entries
        this.logEntriesEl.innerHTML = '';
        mappings.forEach(mapping => {
            const logEntry = this.createLogEntry(mapping);
            this.logEntriesEl.appendChild(logEntry);
        });
    }
    
    createLogEntry(mapping) {
        const div = document.createElement('div');
        div.className = 'log-entry';
        
        const log = mapping.log_entry;
        const timestamp = log.timestamp || 'Unknown';
        const source = log.source || 'Unknown';
        const message = log.message || 'No message';
        const status = log.status || 'unknown';
        
        div.innerHTML = `
            <div class="log-timestamp">${timestamp}</div>
            <div class="log-source">Source: ${source}</div>
            <div class="log-message">${message}</div>
            <div class="log-status status-${status}">${status.toUpperCase()}</div>
        `;
        
        return div;
    }
    
    switchFramework(framework) {
        this.currentFramework = framework;
        
        // Update tabs
        this.tabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.framework === framework);
        });
        
        // Update panels
        this.frameworkPanels.forEach(panel => {
            panel.classList.toggle('active', panel.id === `${framework}-panel`);
        });
    }
    
    renderFrameworkPanels() {
        this.renderAttackPanel();
        this.renderCARPanel();
        this.renderD3FENDPanel();
        this.renderEngagePanel();
    }
    
    renderAttackPanel() {
        const techniques = this.extractUniqueTechniques('attack');
        
        document.getElementById('attackTechniques').textContent = techniques.length;
        document.getElementById('attackTactics').textContent = [...new Set(techniques.map(t => t.tactic))].length;
        document.getElementById('attackCoverage').textContent = '85%'; // Calculate actual coverage
        
        this.attackTechniquesGridEl.innerHTML = '';
        techniques.forEach(technique => {
            const card = this.createTechniqueCard(technique, 'attack');
            this.attackTechniquesGridEl.appendChild(card);
        });
    }
    
    renderCARPanel() {
        const analytics = this.extractUniqueAnalytics();
        
        document.getElementById('carAnalytics').textContent = analytics.length;
        document.getElementById('carConfidence').textContent = '78%'; // Calculate actual confidence
        
        this.carAnalyticsGridEl.innerHTML = '';
        analytics.forEach(analytic => {
            const card = this.createAnalyticsCard(analytic);
            this.carAnalyticsGridEl.appendChild(card);
        });
    }
    
    renderD3FENDPanel() {
        const defenses = this.extractUniqueDefenses();
        
        document.getElementById('d3fendDefenses').textContent = defenses.length;
        document.getElementById('d3fendEffectiveness').textContent = '82%'; // Calculate actual effectiveness
        
        this.d3fendDefensesGridEl.innerHTML = '';
        defenses.forEach(defense => {
            const card = this.createDefenseCard(defense);
            this.d3fendDefensesGridEl.appendChild(card);
        });
    }
    
    renderEngagePanel() {
        const techniques = this.extractUniqueEngageTechniques();
        
        document.getElementById('engageTechniques').textContent = techniques.length;
        document.getElementById('engageRisk').textContent = 'LOW'; // Calculate actual risk
        
        this.engageTechniquesGridEl.innerHTML = '';
        techniques.forEach(technique => {
            const card = this.createEngageCard(technique);
            this.engageTechniquesGridEl.appendChild(card);
        });
    }
    
    extractUniqueTechniques(framework) {
        const techniques = new Map();
        
        this.mappingsData.forEach(mapping => {
            const data = mapping[`mitre_${framework}`];
            if (data && data.technique_id) {
                const key = data.technique_id;
                if (!techniques.has(key)) {
                    techniques.set(key, data);
                }
            }
        });
        
        return Array.from(techniques.values());
    }
    
    extractUniqueAnalytics() {
        const analytics = new Map();
        
        this.mappingsData.forEach(mapping => {
            const data = mapping.mitre_car;
            if (data && data.analytics_id) {
                const key = data.analytics_id;
                if (!analytics.has(key)) {
                    analytics.set(key, data);
                }
            }
        });
        
        return Array.from(analytics.values());
    }
    
    extractUniqueDefenses() {
        const defenses = new Map();
        
        this.mappingsData.forEach(mapping => {
            const data = mapping.mitre_d3fend;
            if (data && data.defend_id) {
                const key = data.defend_id;
                if (!defenses.has(key)) {
                    defenses.set(key, data);
                }
            }
        });
        
        return Array.from(defenses.values());
    }
    
    extractUniqueEngageTechniques() {
        const techniques = new Map();
        
        this.mappingsData.forEach(mapping => {
            const data = mapping.mitre_engage;
            if (data && data.engage_id) {
                const key = data.engage_id;
                if (!techniques.has(key)) {
                    techniques.set(key, data);
                }
            }
        });
        
        return Array.from(techniques.values());
    }
    
    createTechniqueCard(technique, framework) {
        const div = document.createElement('div');
        div.className = 'technique-card';
        div.addEventListener('click', () => this.showTechniqueDetails(technique, framework));
        
        div.innerHTML = `
            <div class="technique-header">
                <span class="technique-id">${technique.technique_id}</span>
                <span class="severity-badge severity-${(technique.severity || 'MEDIUM').toLowerCase()}">${technique.severity || 'MEDIUM'}</span>
            </div>
            <div class="technique-name">${technique.technique_name}</div>
            <div class="technique-description">${technique.description || 'No description available'}</div>
            <div class="technique-tactics">
                <span class="tactic-tag">${technique.tactic || 'Unknown'}</span>
                <span class="tactic-tag">${technique.tactic_id || 'Unknown'}</span>
            </div>
        `;
        
        return div;
    }
    
    createAnalyticsCard(analytic) {
        const div = document.createElement('div');
        div.className = 'analytics-card';
        div.addEventListener('click', () => this.showAnalyticsDetails(analytic));
        
        div.innerHTML = `
            <div class="analytics-header">
                <span class="analytics-id">${analytic.analytics_id}</span>
                <span class="confidence-level">${analytic.confidence || 'MEDIUM'}</span>
            </div>
            <div class="analytics-name">${analytic.analytics_name}</div>
            <div class="analytics-description">${analytic.hypothesis || 'No description available'}</div>
            <div class="analytics-confidence">
                <span>Domain: ${analytic.information_domain || 'Unknown'}</span>
                <span>Difficulty: ${analytic.difficulty || 'MEDIUM'}</span>
            </div>
        `;
        
        return div;
    }
    
    createDefenseCard(defense) {
        const div = document.createElement('div');
        div.className = 'defense-card';
        div.addEventListener('click', () => this.showDefenseDetails(defense));
        
        div.innerHTML = `
            <div class="defense-header">
                <span class="defense-id">${defense.defend_id}</span>
                <span class="effectiveness-level">${defense.effectiveness || 'MEDIUM'}</span>
            </div>
            <div class="defense-name">${defense.defend_name}</div>
            <div class="defense-description">${defense.description || 'No description available'}</div>
            <div class="defense-effectiveness">
                <span>Tactic: ${defense.tactic || 'Unknown'}</span>
                <span>Cost: ${defense.implementation_cost || 'MEDIUM'}</span>
            </div>
        `;
        
        return div;
    }
    
    createEngageCard(technique) {
        const div = document.createElement('div');
        div.className = 'engage-card';
        div.addEventListener('click', () => this.showEngageDetails(technique));
        
        div.innerHTML = `
            <div class="engage-header">
                <span class="engage-id">${technique.engage_id}</span>
                <span class="risk-level">${technique.risk_level || 'LOW'}</span>
            </div>
            <div class="engage-name">${technique.engage_name}</div>
            <div class="engage-description">${technique.description || 'No description available'}</div>
            <div class="engage-risk">
                <span>Strategy: ${technique.strategy || 'Unknown'}</span>
                <span>Resources: ${technique.resource_requirements || 'LOW'}</span>
            </div>
        `;
        
        return div;
    }
    
    showTechniqueDetails(technique, framework) {
        this.selectedTechnique = technique;
        this.modalTitleEl.textContent = `${technique.technique_id} - ${technique.technique_name}`;
        
        this.modalBodyEl.innerHTML = `
            <div class="technique-details">
                <h4>Framework: MITRE ATT&CK</h4>
                <p><strong>Technique ID:</strong> ${technique.technique_id}</p>
                <p><strong>Technique Name:</strong> ${technique.technique_name}</p>
                <p><strong>Tactic:</strong> ${technique.tactic} (${technique.tactic_id})</p>
                <p><strong>Severity:</strong> ${technique.severity || 'MEDIUM'}</p>
                <p><strong>Description:</strong></p>
                <p>${technique.description || 'No description available'}</p>
                
                ${technique.url ? `<p><strong>Reference:</strong> <a href="${technique.url}" target="_blank">${technique.url}</a></p>` : ''}
                
                ${technique.subtechniques && Object.keys(technique.subtechniques).length > 0 ? `
                    <h5>Sub-techniques:</h5>
                    <ul>
                        ${Object.entries(technique.subtechniques).map(([id, name]) => 
                            `<li>${id}: ${name}</li>`
                        ).join('')}
                    </ul>
                ` : ''}
                
                ${technique.ioc_fields ? `
                    <h5>IOC Fields:</h5>
                    <p>${technique.ioc_fields.join(', ')}</p>
                ` : ''}
                
                ${technique.response ? `
                    <h5>Recommended Response:</h5>
                    <p>${technique.response}</p>
                ` : ''}
            </div>
        `;
        
        this.openModal();
    }
    
    showAnalyticsDetails(analytic) {
        this.modalTitleEl.textContent = `${analytic.analytics_id} - ${analytic.analytics_name}`;
        
        this.modalBodyEl.innerHTML = `
            <div class="analytics-details">
                <h4>Framework: MITRE CAR</h4>
                <p><strong>Analytics ID:</strong> ${analytic.analytics_id}</p>
                <p><strong>Analytics Name:</strong> ${analytic.analytics_name}</p>
                <p><strong>Information Domain:</strong> ${analytic.information_domain}</p>
                <p><strong>Confidence:</strong> ${analytic.confidence}</p>
                <p><strong>Difficulty:</strong> ${analytic.difficulty}</p>
                <p><strong>Hypothesis:</strong></p>
                <p>${analytic.hypothesis}</p>
                
                ${analytic.attack_techniques ? `
                    <h5>Attack Techniques:</h5>
                    <p>${analytic.attack_techniques.join(', ')}</p>
                ` : ''}
                
                ${analytic.attack_tactics ? `
                    <h5>Attack Tactics:</h5>
                    <p>${analytic.attack_tactics.join(', ')}</p>
                ` : ''}
                
                ${analytic.data_sources ? `
                    <h5>Data Sources:</h5>
                    <p>${analytic.data_sources.join(', ')}</p>
                ` : ''}
                
                ${analytic.implementation ? `
                    <h5>Implementation:</h5>
                    <p>${analytic.implementation.join(', ')}</p>
                ` : ''}
            </div>
        `;
        
        this.openModal();
    }
    
    showDefenseDetails(defense) {
        this.modalTitleEl.textContent = `${defense.defend_id} - ${defense.defend_name}`;
        
        this.modalBodyEl.innerHTML = `
            <div class="defense-details">
                <h4>Framework: MITRE D3FEND</h4>
                <p><strong>Defense ID:</strong> ${defense.defend_id}</p>
                <p><strong>Defense Name:</strong> ${defense.defend_name}</p>
                <p><strong>Tactic:</strong> ${defense.tactic}</p>
                <p><strong>Technique:</strong> ${defense.technique}</p>
                <p><strong>Effectiveness:</strong> ${defense.effectiveness}</p>
                <p><strong>Implementation Cost:</strong> ${defense.implementation_cost}</p>
                <p><strong>Description:</strong></p>
                <p>${defense.description}</p>
                
                ${defense.attack_techniques ? `
                    <h5>Counteracts Attack Techniques:</h5>
                    <p>${defense.attack_techniques.join(', ')}</p>
                ` : ''}
                
                ${defense.countermeasures ? `
                    <h5>Countermeasures:</h5>
                    <ul>
                        ${defense.countermeasures.map(cm => `<li>${cm}</li>`).join('')}
                    </ul>
                ` : ''}
                
                ${defense.implementation_examples ? `
                    <h5>Implementation Examples:</h5>
                    <ul>
                        ${defense.implementation_examples.map(ex => `<li>${ex}</li>`).join('')}
                    </ul>
                ` : ''}
            </div>
        `;
        
        this.openModal();
    }
    
    showEngageDetails(technique) {
        this.modalTitleEl.textContent = `${technique.engage_id} - ${technique.engage_name}`;
        
        this.modalBodyEl.innerHTML = `
            <div class="engage-details">
                <h4>Framework: MITRE ENGAGE</h4>
                <p><strong>Engage ID:</strong> ${technique.engage_id}</p>
                <p><strong>Engage Name:</strong> ${technique.engage_name}</p>
                <p><strong>Strategy:</strong> ${technique.strategy}</p>
                <p><strong>Technique:</strong> ${technique.technique}</p>
                <p><strong>Risk Level:</strong> ${technique.risk_level}</p>
                <p><strong>Resource Requirements:</strong> ${technique.resource_requirements}</p>
                <p><strong>Description:</strong></p>
                <p>${technique.description}</p>
                
                ${technique.attack_techniques ? `
                    <h5>Targets Attack Techniques:</h5>
                    <p>${technique.attack_techniques.join(', ')}</p>
                ` : ''}
                
                ${technique.engagement_goals ? `
                    <h5>Engagement Goals:</h5>
                    <ul>
                        ${technique.engagement_goals.map(goal => `<li>${goal}</li>`).join('')}
                    </ul>
                ` : ''}
                
                ${technique.deception_tactics ? `
                    <h5>Deception Tactics:</h5>
                    <ul>
                        ${technique.deception_tactics.map(tactic => `<li>${tactic}</li>`).join('')}
                    </ul>
                ` : ''}
                
                ${technique.success_metrics ? `
                    <h5>Success Metrics:</h5>
                    <ul>
                        ${technique.success_metrics.map(metric => `<li>${metric}</li>`).join('')}
                    </ul>
                ` : ''}
            </div>
        `;
        
        this.openModal();
    }
    
    openModal() {
        this.modalOverlayEl.classList.add('active');
    }
    
    closeModal() {
        this.modalOverlayEl.classList.remove('active');
    }
    
    filterMappings() {
        this.renderIPMappings();
    }
    
    clearLogDetails() {
        this.selectedIP = null;
        this.selectedTechnique = null;
        
        this.selectedItemEl.innerHTML = '<p class="placeholder">Select an IP or technique to view details</p>';
        this.logEntriesEl.innerHTML = '';
        
        document.querySelectorAll('.ip-mapping-item').forEach(el => {
            el.classList.remove('selected');
        });
    }
    
    async showInvestigationReport(ip) {
        try {
            const response = await fetch(`/api/investigation/report/${ip}`);
            const report = await response.json();
            
            if (response.ok) {
                this.renderInvestigationReport(report);
                this.investigationModalEl.classList.remove('hidden');
            } else {
                alert(report.error || 'Failed to load investigation report');
            }
        } catch (error) {
            console.error('Error loading investigation report:', error);
            alert('Error loading investigation report. Please try again.');
        }
    }
    
    renderInvestigationReport(report) {
        const severityClass = report.severity.toLowerCase();
        const riskColor = report.risk_score >= 80 ? '#ff3860' : 
                         report.risk_score >= 60 ? '#ff9f43' : 
                         report.risk_score >= 40 ? '#ffd32a' : '#00ff88';
        
        let mitreMappingHTML = '';
        if (report.mitre_mappings && report.mitre_mappings.length > 0) {
            const techniques = {};
            report.mitre_mappings.forEach(mapping => {
                if (mapping.mitre_attack && mapping.mitre_attack.technique_id) {
                    const tid = mapping.mitre_attack.technique_id;
                    if (!techniques[tid]) {
                        techniques[tid] = {
                            ...mapping.mitre_attack,
                            severity: mapping.severity
                        };
                    }
                }
            });
            
            mitreMappingHTML = Object.values(techniques).map(tech => `
                <div class="mitre-technique">
                    <div class="technique-header">
                        <span class="technique-id">${tech.technique_id}</span>
                        <span class="technique-severity ${tech.severity.toLowerCase()}">${tech.severity}</span>
                    </div>
                    <div class="technique-name">${tech.name}</div>
                    <div class="technique-description">${tech.description}</div>
                </div>
            `).join('');
        }
        
        let evidenceHTML = '';
        if (report.evidence && report.evidence.length > 0) {
            evidenceHTML = report.evidence.map(log => `
                <div class="evidence-log">
                    <div class="log-time">${log.timestamp}</div>
                    <div class="log-source">${log.source || 'Unknown'}</div>
                    <div class="log-message">${log.message || log.status}</div>
                </div>
            `).join('');
        }
        
        this.investigationModalBodyEl.innerHTML = `
            <div class="investigation-report">
                <div class="report-header">
                    <div class="report-title">INVESTIGATION REPORT</div>
                    <div class="report-risk">
                        <span class="risk-label">RISK</span>
                        <span class="risk-score" style="color: ${riskColor}">${report.risk_score}</span>
                    </div>
                </div>
                
                <div class="report-summary">
                    <div class="summary-item">
                        <span class="summary-label">Attacker IP:</span>
                        <span class="summary-value">${report.ip}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">First Observed:</span>
                        <span class="summary-value">${report.first_seen || 'N/A'}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Last Activity:</span>
                        <span class="summary-value">${report.last_seen || 'N/A'}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Successful Logins:</span>
                        <span class="summary-value">${report.successful_logins}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Privilege Escalation:</span>
                        <span class="summary-value">${report.privilege_escalation_attempts} sudo events</span>
                    </div>
                </div>
                
                <div class="mitre-mapping-section">
                    <div class="section-title">MITRE ATT&CK MAPPING</div>
                    <div class="mitre-techniques">
                        ${mitreMappingHTML || '<p>No MITRE techniques detected</p>'}
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="section-title">EVIDENCE (${report.evidence.length} log entries)</div>
                    <div class="evidence-logs">
                        ${evidenceHTML}
                    </div>
                </div>
            </div>
        `;
    }
    
    closeInvestigationModal() {
        this.investigationModalEl.classList.add('hidden');
    }
    
    async exportMappings() {
        try {
            const response = await fetch('/api/mitre/mappings/export');
            const blob = await response.blob();
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `mitre_mappings_${new Date().toISOString().slice(0,10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
        } catch (error) {
            console.error('Error exporting mappings:', error);
            alert('Error exporting mappings. Please try again.');
        }
    }
}

// Initialize dashboard when DOM is loaded
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new MITREMappingDashboard();
});
