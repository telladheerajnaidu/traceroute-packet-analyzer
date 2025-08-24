// Advanced Traceroute Packet Analysis Simulation
class AdvancedTracerouteSimulation {
    constructor() {
        this.isRunning = false;
        this.isPaused = false;
        this.currentHop = 0;
        this.maxHops = 8;
        this.animationSpeed = 1000;
        this.stepMode = false;
        this.currentStep = 0;
        this.tracerouteMode = 'udp';
        this.selectedPacket = null;
        
        // Packet data from provided JSON
        this.packetStructures = {
            ipv4Header: {
                version: 4,
                ihl: 5,
                dscp: 0,
                ecn: 0,
                totalLength: 60,
                identification: "0x1234",
                flags: "0x02",
                fragmentOffset: 0,
                ttl: 1,
                protocol: 17,
                headerChecksum: "0x7a2b",
                sourceIP: "192.168.1.100",
                destinationIP: "8.8.8.8"
            },
            udpHeader: {
                sourcePort: 54321,
                destinationPort: 33434,
                length: 40,
                checksum: "0x8f3a"
            },
            icmpTimeExceeded: {
                type: 11,
                code: 0,
                checksum: "0x1f4a",
                unused: 0,
                originalIPHeader: "45000054123400004011...",
                originalUDPData: "d431829a002800008f3a..."
            }
        };

        // Network topology
        this.networkData = {
            source: { ip: "192.168.1.100", name: "Your Computer", mac: "00:1a:2b:3c:4d:5e" },
            routers: [
                { ip: "192.168.1.1", name: "Gateway Router", mac: "00:50:56:12:34:56", rtt_base: 1 },
                { ip: "10.0.1.1", name: "ISP Router 1", mac: "00:90:f5:ab:cd:ef", rtt_base: 5 },
                { ip: "10.0.2.1", name: "ISP Router 2", mac: "00:d0:59:12:ab:cd", rtt_base: 12 },
                { ip: "203.0.113.1", name: "Backbone Router", mac: "00:a0:24:ef:12:34", rtt_base: 25 }
            ],
            destination: { ip: "8.8.8.8", name: "Google DNS", mac: "00:1f:f3:56:78:9a", rtt_base: 45 }
        };

        this.packetExamples = [
            {
                type: "UDP_PROBE",
                ttl: 1,
                hexDump: "45 00 00 3c 12 34 40 00 01 11 7a 2b c0 a8 01 64 08 08 08 08 d4 31 82 9a 00 28 8f 3a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68",
                description: "UDP probe packet with TTL=1 to port 33434"
            },
            {
                type: "ICMP_TIME_EXCEEDED",
                sourceRouter: "192.168.1.1",
                hexDump: "45 00 00 46 00 00 40 00 40 01 b6 cc c0 a8 01 01 c0 a8 01 64 0b 00 1f 4a 00 00 00 00 45 00 00 3c 12 34 40 00 01 11 7a 2b c0 a8 01 64 08 08 08 08",
                description: "ICMP Time Exceeded response from first router"
            }
        ];

        this.initializeElements();
        this.bindEvents();
        this.updateSliderValues();
        this.updatePacketDisplay();
    }

    initializeElements() {
        // Control elements
        this.startBtn = document.getElementById('start-btn');
        this.pauseBtn = document.getElementById('pause-btn');
        this.resetBtn = document.getElementById('reset-btn');
        this.nextStepBtn = document.getElementById('next-step-btn');
        this.maxHopsSlider = document.getElementById('max-hops');
        this.stepModeCheck = document.getElementById('step-mode');
        this.tracerouteModeSelect = document.getElementById('traceroute-mode');
        this.statusIndicator = document.getElementById('status-indicator');
        this.terminalOutput = document.getElementById('terminal-output');
        this.packetsContainer = document.getElementById('packets-container');
        this.currentStepDisplay = document.getElementById('current-step');
        
        // Packet analysis elements
        this.flowSteps = document.getElementById('flow-steps');
        this.packetDetails = document.getElementById('packet-details');
        this.hexDump = document.getElementById('hex-dump');
        
        // Tab elements
        this.tabBtns = document.querySelectorAll('.tab-btn');
        this.tabContents = document.querySelectorAll('.tab-content');
        
        // Protocol expand buttons
        this.expandBtns = document.querySelectorAll('.expand-btn');
    }

    bindEvents() {
        // Control buttons
        this.startBtn.addEventListener('click', () => this.startSimulation());
        this.pauseBtn.addEventListener('click', () => this.togglePause());
        this.resetBtn.addEventListener('click', () => this.resetSimulation());
        this.nextStepBtn.addEventListener('click', () => this.nextStep());

        // Settings
        this.maxHopsSlider.addEventListener('input', () => this.updateSliderValues());
        this.stepModeCheck.addEventListener('change', () => this.updateStepMode());
        
        // Fix dropdown interaction by ensuring proper event handling
        this.tracerouteModeSelect.addEventListener('change', (e) => {
            this.tracerouteMode = e.target.value;
            this.updateTracerouteMode();
            this.showPacketUpdateNotification();
        });
        
        // Also handle click events to ensure dropdown opens
        this.tracerouteModeSelect.addEventListener('mousedown', (e) => {
            e.stopPropagation();
        });

        // Tab switching
        this.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
        });

        // Protocol expand/collapse
        this.expandBtns.forEach(btn => {
            btn.addEventListener('click', () => this.toggleProtocolSection(btn));
        });

        // Node clicking for packet analysis
        document.querySelectorAll('.network-node, .hop-node').forEach(node => {
            node.addEventListener('click', () => this.analyzeNode(node));
        });
    }

    showPacketUpdateNotification() {
        // Show visual feedback when packet analysis is updated
        const notification = document.createElement('div');
        notification.className = 'packet-update-notification';
        notification.textContent = `Packet analysis updated for ${this.tracerouteMode.toUpperCase()} mode`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--color-primary);
            color: var(--color-btn-primary-text);
            padding: 12px 16px;
            border-radius: var(--radius-base);
            font-size: var(--font-size-sm);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, 2000);
    }

    updateSliderValues() {
        document.getElementById('max-hops-value').textContent = this.maxHopsSlider.value;
        this.maxHops = parseInt(this.maxHopsSlider.value);
    }

    updateStepMode() {
        this.stepMode = this.stepModeCheck.checked;
        this.nextStepBtn.disabled = !this.stepMode || !this.isRunning;
        
        if (this.stepMode) {
            this.showPacketUpdateNotification();
        }
    }

    updateTracerouteMode() {
        this.updatePacketDisplay();
        this.updateFlowSteps();
    }

    switchTab(tabName) {
        // Update tab buttons
        this.tabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        
        // Update tab content with smooth transition
        this.tabContents.forEach(content => {
            const isActive = content.id === `${tabName}-tab`;
            content.classList.toggle('active', isActive);
            
            if (isActive) {
                // Add a subtle highlight animation when switching tabs
                content.style.animation = 'fadeIn 0.3s ease-out';
            }
        });
    }

    toggleProtocolSection(btn) {
        const targetId = btn.dataset.target;
        const targetElement = document.getElementById(targetId);
        const isCollapsed = targetElement.classList.contains('collapsed');
        
        targetElement.classList.toggle('collapsed');
        btn.classList.toggle('collapsed', !isCollapsed);
        btn.textContent = isCollapsed ? '▼' : '▶';
    }

    updatePacketDisplay() {
        // Update packet structure based on current mode
        if (this.tracerouteMode === 'icmp') {
            // Update for ICMP mode
            document.getElementById('ip-protocol').textContent = '1';
            document.querySelector('#ip-protocol').nextElementSibling.textContent = '(ICMP)';
            
            // Hide UDP header, show ICMP
            const udpSection = document.querySelector('.protocol-section:nth-child(2)');
            if (udpSection) {
                udpSection.style.display = 'none';
            }
        } else {
            // Update for UDP mode
            document.getElementById('ip-protocol').textContent = '17';
            document.querySelector('#ip-protocol').nextElementSibling.textContent = '(UDP)';
            
            // Show UDP header
            const udpSection = document.querySelector('.protocol-section:nth-child(2)');
            if (udpSection) {
                udpSection.style.display = 'block';
            }
        }

        // Update destination port for current hop
        const currentPort = 33434 + this.currentHop;
        const udpDstPort = document.getElementById('udp-dst-port');
        if (udpDstPort) {
            udpDstPort.textContent = currentPort;
        }
    }

    updateFlowSteps() {
        const steps = document.querySelectorAll('.flow-step');
        const stepTitles = this.tracerouteMode === 'icmp' ? 
            ['ICMP Echo Request Sent', 'Router Processes Packet', 'Packet Discarded', 'ICMP Time Exceeded'] :
            ['UDP Probe Packet Sent', 'Router Processes Packet', 'Packet Discarded', 'ICMP Time Exceeded'];
            
        const stepDescriptions = this.tracerouteMode === 'icmp' ? 
            ['Sending ICMP Echo Request with TTL=1', 'Router decrements TTL from 1 to 0', 'TTL=0, packet is discarded', 'Router generates ICMP Type 11 response'] :
            ['Sending UDP packet to port 33434 with TTL=1', 'Router decrements TTL from 1 to 0', 'TTL=0, packet is discarded', 'Router generates ICMP Type 11 response'];
            
        steps.forEach((step, index) => {
            if (stepTitles[index]) {
                const titleElement = step.querySelector('.step-title');
                const descElement = step.querySelector('.step-description');
                if (titleElement) {
                    titleElement.textContent = stepTitles[index];
                }
                if (descElement) {
                    descElement.textContent = stepDescriptions[index];
                }
            }
        });
    }

    async startSimulation() {
        if (this.isRunning) return;

        this.isRunning = true;
        this.isPaused = false;
        this.currentHop = 0;
        this.currentStep = 0;

        this.updateControlButtons();
        this.updateStatus('Running', 'status--warning');
        this.clearTerminal();
        this.addTerminalLine(`traceroute to google.com (8.8.8.8), ${this.maxHops} hops max, 60 byte packets`);
        this.currentStepDisplay.textContent = 'Starting...';

        // Start the simulation
        this.runTraceroute();
    }

    async runTraceroute() {
        const totalHops = this.networkData.routers.length + 1; // +1 for destination
        let destinationReached = false;

        for (let ttl = 1; ttl <= this.maxHops && this.isRunning && !destinationReached; ttl++) {
            // Wait if paused or in step mode
            while ((this.isPaused || this.stepMode) && this.isRunning) {
                await this.sleep(100);
            }

            if (!this.isRunning) break;

            this.currentHop = ttl;
            this.updatePacketDisplay();
            
            const result = await this.simulateHopWithSteps(ttl);
            
            // Check if we reached the destination
            if (ttl >= totalHops && result === 'success') {
                destinationReached = true;
                this.updateStatus('Complete', 'status--success');
                this.addTerminalLine('\nTraceroute complete!');
                break;
            }

            // Add delay between hops
            if (!this.stepMode) {
                await this.sleep(1200);
            }
        }

        if (!destinationReached && this.currentHop >= this.maxHops && this.isRunning) {
            this.updateStatus('Max Hops Reached', 'status--error');
            this.addTerminalLine('\n*** Maximum hops reached ***');
        }

        this.isRunning = false;
        this.updateControlButtons();
    }

    async simulateHopWithSteps(ttl) {
        const hopIndex = ttl - 1;
        let targetNode, targetData;

        // Determine target (router or destination)
        if (hopIndex < this.networkData.routers.length) {
            targetNode = document.getElementById(`hop-${ttl}`);
            targetData = this.networkData.routers[hopIndex];
        } else {
            targetNode = document.getElementById('destination-node');
            targetData = this.networkData.destination;
        }

        // Step 1: Send packet
        await this.executeStep(1, `Sending ${this.tracerouteMode.toUpperCase()} probe with TTL=${ttl}`);
        this.highlightCurrentHop(ttl);
        await this.animatePacketToHop(ttl);

        // Step 2: Router processes packet
        await this.executeStep(2, 'Router decrements TTL and checks value');
        await this.sleep(this.stepMode ? 0 : 500);

        // Step 3: Packet discarded (TTL=0)
        await this.executeStep(3, 'TTL reaches 0, packet discarded');
        await this.sleep(this.stepMode ? 0 : 300);

        // Step 4: ICMP response
        await this.executeStep(4, 'Router sends ICMP Time Exceeded response');
        await this.animateIcmpResponse(ttl);

        // Handle response
        const result = await this.handleHopResponse(ttl, targetData);
        this.clearHopHighlighting();
        
        // Reset steps for next hop
        this.resetFlowSteps();
        
        return result;
    }

    async executeStep(stepNumber, description) {
        this.currentStep = stepNumber;
        this.currentStepDisplay.textContent = `Step ${stepNumber}: ${description}`;
        
        // Update flow step visual
        const steps = document.querySelectorAll('.flow-step');
        steps.forEach((step, index) => {
            step.classList.remove('active', 'completed');
            if (index + 1 < stepNumber) {
                step.classList.add('completed');
            } else if (index + 1 === stepNumber) {
                step.classList.add('active');
            }
        });

        if (this.stepMode) {
            // Wait for user to click next step
            return new Promise((resolve) => {
                this.nextStepResolve = resolve;
            });
        } else {
            await this.sleep(800);
        }
    }

    nextStep() {
        if (this.nextStepResolve) {
            this.nextStepResolve();
            this.nextStepResolve = null;
        }
    }

    resetFlowSteps() {
        const steps = document.querySelectorAll('.flow-step');
        steps.forEach(step => {
            step.classList.remove('active', 'completed');
        });
        steps[0]?.classList.add('ready');
    }

    async handleHopResponse(ttl, targetData) {
        // Simulate RTT measurements
        const baseRtt = targetData.rtt_base;
        const rtt1 = this.generateRTT(baseRtt);
        const rtt2 = this.generateRTT(baseRtt);
        const rtt3 = this.generateRTT(baseRtt);

        // Mark hop as responding
        this.markHopResponding(ttl);

        // Format output line
        const outputLine = `${String(ttl).padStart(2, ' ')}  ${targetData.ip} (${targetData.name})  ${rtt1}ms  ${rtt2}ms  ${rtt3}ms`;
        this.addTerminalLine(outputLine);
        
        // Update packet analysis
        this.updatePacketAnalysis(ttl, targetData, 'response');
        
        await this.sleep(200);
        return 'success';
    }

    updatePacketAnalysis(ttl, targetData, type) {
        // Update TTL in packet display
        const ttlElement = document.getElementById('ip-ttl');
        if (ttlElement) {
            ttlElement.textContent = ttl;
        }
        
        // Update destination port for UDP
        if (this.tracerouteMode === 'udp') {
            const currentPort = 33434 + ttl - 1;
            const udpDstPort = document.getElementById('udp-dst-port');
            if (udpDstPort) {
                udpDstPort.textContent = currentPort;
            }
        }
        
        // Update hex dump with current TTL
        this.updateHexDump(ttl);
        
        // Update destination IP if at final hop
        if (ttl > this.networkData.routers.length) {
            const ipDst = document.getElementById('ip-dst');
            if (ipDst) {
                ipDst.textContent = this.networkData.destination.ip;
            }
        }
    }

    updateHexDump(ttl) {
        // Update hex dump with current TTL value
        const ttlHex = ttl.toString(16).padStart(2, '0');
        const hexContent = document.querySelector('.hex-content');
        if (hexContent) {
            // Update the TTL byte in the hex dump
            const ttlElement = hexContent.querySelector('.ttl-highlight');
            if (ttlElement) {
                ttlElement.textContent = ttlHex;
            }
        }
    }

    generateRTT(baseRtt) {
        // Add realistic variation to RTT
        const variation = 0.2;
        const rtt = baseRtt + (Math.random() - 0.5) * 2 * baseRtt * variation;
        return Math.max(0.1, Math.round(rtt * 10) / 10);
    }

    async animatePacketToHop(ttl) {
        return new Promise((resolve) => {
            const sourceElement = document.getElementById('source');
            let targetElement;
            
            if (ttl <= this.networkData.routers.length) {
                targetElement = document.getElementById(`hop-${ttl}`);
            } else {
                targetElement = document.getElementById('destination-node');
            }

            if (!sourceElement || !targetElement) {
                resolve();
                return;
            }

            // Get positions
            const containerRect = this.packetsContainer.getBoundingClientRect();
            const sourceRect = sourceElement.getBoundingClientRect();
            const targetRect = targetElement.getBoundingClientRect();

            const startX = sourceRect.left - containerRect.left + sourceRect.width / 2;
            const startY = sourceRect.top - containerRect.top + sourceRect.height / 2;
            const endX = targetRect.left - containerRect.left + targetRect.width / 2;
            const endY = targetRect.top - containerRect.top + targetRect.height / 2;

            // Create packet element
            const packet = document.createElement('div');
            packet.className = 'packet probe-packet visible';
            packet.textContent = ttl; // Show TTL value
            packet.dataset.type = this.tracerouteMode;
            packet.dataset.ttl = ttl;
            packet.title = `Click to inspect ${this.tracerouteMode.toUpperCase()} packet with TTL=${ttl}`;
            
            // Make packet clickable with improved feedback
            packet.addEventListener('click', (e) => {
                e.stopPropagation();
                this.inspectPacket(packet);
            });
            
            // Add hover effects
            packet.addEventListener('mouseenter', () => {
                packet.style.transform = 'scale(1.3)';
                packet.style.zIndex = '20';
            });
            
            packet.addEventListener('mouseleave', () => {
                if (!packet.classList.contains('selected')) {
                    packet.style.transform = 'scale(1)';
                    packet.style.zIndex = '10';
                }
            });
            
            packet.style.left = startX + 'px';
            packet.style.top = startY + 'px';
            
            this.packetsContainer.appendChild(packet);

            // Animate to target
            setTimeout(() => {
                packet.style.transition = `all ${this.animationSpeed}ms ease-out`;
                packet.style.left = endX + 'px';
                packet.style.top = endY + 'px';

                setTimeout(() => {
                    // Show packet expiry if TTL reached 0 at intermediate hop
                    if (ttl <= this.networkData.routers.length) {
                        packet.classList.add('expired');
                        packet.textContent = '0'; // TTL expired
                        packet.title = 'Packet expired (TTL=0) - Click to inspect';
                    }
                    
                    setTimeout(() => {
                        packet.remove();
                        resolve();
                    }, 500);
                }, this.animationSpeed);
            }, 100);
        });
    }

    async animateIcmpResponse(ttl) {
        return new Promise((resolve) => {
            let sourceElement;
            if (ttl <= this.networkData.routers.length) {
                sourceElement = document.getElementById(`hop-${ttl}`);
            } else {
                sourceElement = document.getElementById('destination-node');
            }
            
            const targetElement = document.getElementById('source');

            if (!sourceElement || !targetElement) {
                resolve();
                return;
            }

            const containerRect = this.packetsContainer.getBoundingClientRect();
            const sourceRect = sourceElement.getBoundingClientRect();
            const targetRect = targetElement.getBoundingClientRect();

            const startX = sourceRect.left - containerRect.left + sourceRect.width / 2;
            const startY = sourceRect.top - containerRect.top + sourceRect.height / 2;
            const endX = targetRect.left - containerRect.left + targetRect.width / 2;
            const endY = targetRect.top - containerRect.top + targetRect.height / 2;

            // Create ICMP response packet
            const icmpPacket = document.createElement('div');
            icmpPacket.className = 'packet icmp-packet visible';
            icmpPacket.textContent = '11'; // ICMP Type 11 (Time Exceeded)
            icmpPacket.dataset.type = 'icmp_response';
            icmpPacket.dataset.icmpType = '11';
            icmpPacket.title = 'Click to inspect ICMP Time Exceeded packet';
            
            // Make packet clickable with improved feedback
            icmpPacket.addEventListener('click', (e) => {
                e.stopPropagation();
                this.inspectPacket(icmpPacket);
            });
            
            // Add hover effects
            icmpPacket.addEventListener('mouseenter', () => {
                icmpPacket.style.transform = 'scale(1.3)';
                icmpPacket.style.zIndex = '20';
            });
            
            icmpPacket.addEventListener('mouseleave', () => {
                if (!icmpPacket.classList.contains('selected')) {
                    icmpPacket.style.transform = 'scale(1)';
                    icmpPacket.style.zIndex = '10';
                }
            });

            icmpPacket.style.left = startX + 'px';
            icmpPacket.style.top = startY + 'px';
            
            this.packetsContainer.appendChild(icmpPacket);

            // Animate back to source
            setTimeout(() => {
                icmpPacket.style.transition = `all ${this.animationSpeed * 0.8}ms ease-out`;
                icmpPacket.style.left = endX + 'px';
                icmpPacket.style.top = endY + 'px';

                setTimeout(() => {
                    icmpPacket.remove();
                    resolve();
                }, this.animationSpeed * 0.8);
            }, 300);
        });
    }

    inspectPacket(packet) {
        // Clear previous selection
        document.querySelectorAll('.packet').forEach(p => {
            p.classList.remove('selected');
            if (!p.matches(':hover')) {
                p.style.transform = 'scale(1)';
                p.style.zIndex = '10';
            }
        });
        
        // Highlight selected packet with improved visual feedback
        packet.classList.add('selected');
        packet.style.transform = 'scale(1.4)';
        packet.style.zIndex = '21';
        this.selectedPacket = packet;
        
        // Update packet analysis based on packet type
        const packetType = packet.dataset.type;
        const ttl = packet.dataset.ttl;
        const icmpType = packet.dataset.icmpType;
        
        if (packetType === 'icmp_response') {
            this.showIcmpPacketAnalysis(icmpType);
        } else {
            this.showProbePacketAnalysis(packetType, ttl);
        }
        
        // Switch to structure tab and show notification
        this.switchTab('structure');
        this.showPacketInspectionNotification(packetType, ttl, icmpType);
    }

    showPacketInspectionNotification(packetType, ttl, icmpType) {
        const notification = document.createElement('div');
        notification.className = 'packet-inspection-notification';
        
        let message = '';
        if (packetType === 'icmp_response') {
            message = `Inspecting ICMP Time Exceeded packet (Type ${icmpType})`;
        } else {
            message = `Inspecting ${packetType.toUpperCase()} probe packet (TTL=${ttl})`;
        }
        
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 70px;
            right: 20px;
            background: var(--color-success);
            color: var(--color-btn-primary-text);
            padding: 12px 16px;
            border-radius: var(--radius-base);
            font-size: var(--font-size-sm);
            font-weight: var(--font-weight-medium);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
            border-left: 4px solid var(--color-primary);
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    showProbePacketAnalysis(type, ttl) {
        // Update packet details for probe packet
        const ttlElement = document.getElementById('ip-ttl');
        const protocolElement = document.getElementById('ip-protocol');
        
        if (ttlElement) {
            ttlElement.textContent = ttl || this.currentHop;
        }
        if (protocolElement) {
            protocolElement.textContent = type === 'icmp' ? '1' : '17';
            protocolElement.nextElementSibling.textContent = type === 'icmp' ? '(ICMP)' : '(UDP)';
        }
        
        // Show appropriate protocol section
        const protocolSections = document.querySelectorAll('.protocol-section');
        protocolSections.forEach((section, index) => {
            if (index === 1) { // UDP/ICMP section
                section.style.display = type === 'udp' ? 'block' : 'none';
            }
        });
    }

    showIcmpPacketAnalysis(icmpType) {
        // Update for ICMP Time Exceeded packet
        const protocolElement = document.getElementById('ip-protocol');
        if (protocolElement) {
            protocolElement.textContent = '1';
            protocolElement.nextElementSibling.textContent = '(ICMP)';
        }
        
        // Hide UDP section, could add ICMP section here
        const udpSection = document.querySelector('.protocol-section:nth-child(2)');
        if (udpSection) {
            udpSection.style.display = 'none';
        }
    }

    analyzeNode(node) {
        // Show analysis for clicked network node
        const nodeId = node.id;
        const nodeIP = node.querySelector('.node-ip')?.textContent || '';
        
        // Highlight the clicked node temporarily
        node.style.animation = 'pulseActive 1s ease-in-out';
        
        // Show node analysis notification
        const notification = document.createElement('div');
        notification.textContent = `Analyzing node: ${nodeIP}`;
        notification.style.cssText = `
            position: fixed;
            top: 120px;
            right: 20px;
            background: var(--color-info);
            color: var(--color-btn-primary-text);
            padding: 10px 14px;
            border-radius: var(--radius-base);
            font-size: var(--font-size-sm);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, 2000);
    }

    highlightCurrentHop(ttl) {
        this.clearHopHighlighting();
        
        if (ttl <= this.networkData.routers.length) {
            const hopElement = document.getElementById(`hop-${ttl}`);
            if (hopElement) hopElement.classList.add('active');
        } else {
            const destElement = document.getElementById('destination-node');
            if (destElement) destElement.classList.add('active');
        }
    }

    clearHopHighlighting() {
        document.querySelectorAll('.hop-node, .network-node').forEach(node => {
            node.classList.remove('active', 'responding');
        });
    }

    markHopResponding(ttl) {
        if (ttl <= this.networkData.routers.length) {
            const hopElement = document.getElementById(`hop-${ttl}`);
            if (hopElement) {
                hopElement.classList.remove('active');
                hopElement.classList.add('responding');
            }
        } else {
            const destElement = document.getElementById('destination-node');
            if (destElement) {
                destElement.classList.remove('active');
                destElement.classList.add('responding');
            }
        }
    }

    togglePause() {
        if (!this.isRunning) return;

        this.isPaused = !this.isPaused;
        this.updateControlButtons();
        this.updateStatus(this.isPaused ? 'Paused' : 'Running', 
                         this.isPaused ? 'status--warning' : 'status--info');
    }

    resetSimulation() {
        this.isRunning = false;
        this.isPaused = false;
        this.currentHop = 0;
        this.currentStep = 0;
        this.selectedPacket = null;

        this.updateControlButtons();
        this.updateStatus('Ready', 'status--info');
        this.clearTerminal();
        this.clearHopHighlighting();
        this.clearPackets();
        this.resetFlowSteps();
        this.currentStepDisplay.textContent = 'Ready';

        // Reset terminal to initial state
        this.addTerminalLine('traceroute to google.com (8.8.8.8), 8 hops max, 60 byte packets');
        
        // Reset packet display
        this.updatePacketDisplay();
    }

    updateControlButtons() {
        this.startBtn.disabled = this.isRunning;
        this.pauseBtn.disabled = !this.isRunning || this.stepMode;
        this.nextStepBtn.disabled = !this.stepMode || !this.isRunning;
        this.pauseBtn.textContent = this.isPaused ? 'Resume' : 'Pause';

        if (this.isRunning) {
            this.startBtn.textContent = 'Running...';
        } else {
            this.startBtn.textContent = 'Start Traceroute';
        }
    }

    updateStatus(text, className) {
        const statusElement = this.statusIndicator.querySelector('.status');
        if (statusElement) {
            statusElement.textContent = text;
            statusElement.className = `status ${className}`;
        }
    }

    clearTerminal() {
        this.terminalOutput.innerHTML = '';
    }

    addTerminalLine(text, className = '') {
        const line = document.createElement('div');
        line.className = `terminal-line new-line ${className}`;
        line.textContent = text;
        this.terminalOutput.appendChild(line);
        
        // Auto-scroll to bottom
        this.terminalOutput.scrollTop = this.terminalOutput.scrollHeight;

        // Remove new-line class after animation
        setTimeout(() => {
            line.classList.remove('new-line');
        }, 300);
    }

    clearPackets() {
        this.packetsContainer.innerHTML = '';
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Initialize simulation when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const simulation = new AdvancedTracerouteSimulation();
    
    // Make simulation globally accessible for debugging
    window.advancedTracerouteSimulation = simulation;
});