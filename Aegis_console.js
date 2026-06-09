// Aegis Codex Engine - Jonatan Villela
// Autor: github.com/jo0natan Date 2026-11-19
// Descrição: Motor avançado de evasão e descoberta para ambientes de execução JavaScript, com foco em anti-inspeção, persistência e coleta forense de dados.
// DEscription: Advanced evasion and discovery engine for JavaScript execution environments, focusing on anti-inspection, persistence, and forensic data collection.

// Versao para console do navegador: sem dependencias Node.js.
class AegisCodexEngine {

    constructor(customConfig = {}) {
        this.processId = `AEGIS-EVADE-${Math.floor(Math.random() * 100000)}`;
        
        // CONFIG GLOBAL PARAMETERS

        this.config = {
            policy: {
                allowSelectors: ['#app', '[data-safe]'],
                logMutations: true,
                revertMutations: true,
                freezeConsole: true
            },
            keepAlive: {
                wakeLockScreen: true,
                silentAudioInterval: 500,
                aggressiveTickInterval: 100,
                driftThreshold: 200
            },
            network: {
                monitorXHR: true,
                truncateResponseLen: 200
            },
            memory: {
                purgeOnMutationBurst: true,
                autoPurgeMutationThreshold: 50000,
                exposeEnabledToolsAlias: true
            },
            evasion: {
                targetKeyToSearch: 'enabledTools',
                blockEvents: ['visibilitychange', 'blur', 'mouseleave', 'freeze', 'pagehide', 'pageshow'],
                forceVisibilityState: 'visible',
                forceHiddenState: false,
                spoofIsTrusted: true,
                mouseSimulationInterval: 1000,
                mouseParams: { startX: -5, endX: 43, steps: 38, delayMs: 13, pauseAtEnd: 450 }
            },
            ...customConfig
        };

        // LOG COLORS
        this.COLORS = {
            reset: '\x1b[0m',
            bright: '\x1b[1m',
            red: '\x1b[31m',
            green: '\x1b[32m',
            yellow: '\x1b[33m',
            blue: '\x1b[34m',
            magenta: '\x1b[35m',
            cyan: '\x1b[36m',
            orange: '\x1b[38;5;208m',
            gold: '\x1b[38;5;220m',
            purple: '\x1b[38;5;135m'
        };

        //ESTADO INTERNO & TELEMETRIA DO CODEX

        this.state = {
            history: [],
            currentState: 'INIT',
            discoveredItems: [],
            visitedObjects: new WeakSet(),
            mitigationLog: [],
            audioContextRef: null,
            blockedMutationCount: 0,
            domFirewallInstalled: false,
            xhrSnifferInstalled: false,
            diagnosticsInstalled: false,
            focusHardeningInstalled: false,
            keepAliveInstalled: false,
            autoStartCompleted: false,
            blockingModePrimed: false,
        };

        this.nativoToString = Function.prototype.toString;
        this.xhrOriginalOpen = typeof XMLHttpRequest !== 'undefined' ? XMLHttpRequest.prototype.open : null;
        this.xhrOriginalSend = typeof XMLHttpRequest !== 'undefined' ? XMLHttpRequest.prototype.send : null;
        this.startPromise = null;
        this.mouseSimulationIntervalRef = null;
        this.discoveryTimeoutRef = null;
        this.updateState('INIT', { msg: 'Instância soberana do Codex criada.' });
    }

    //SISTEMA DE RASTREAMENTO DE ESTADO ASSÍNCRONO
    updateState(newState, dataPayload = {}) {
        this.state.currentState = newState;
        const snapshot = {
            timestamp: new Date().toISOString(),
            processId: this.processId,
            state: this.state.currentState,
            payload: JSON.parse(JSON.stringify(dataPayload))
        };
        this.state.history.push(snapshot);
        if (this.config.policy.logMutations) {
            console.log(`%c[AEGIS STATE] [${this.state.currentState}]`, 'color: #00ffff; font-weight: bold;', snapshot.payload);
        }
    }

    getHistory() {
        return Object.freeze([...this.state.history]);
    }

    logMitigation(type, details) {
        this.state.mitigationLog.push({ timestamp: Date.now(), type, details });
        console.warn(`%c[AEGIS MITIGATION DETECTED] ${type}`, 'color: #ffaa00; font-weight: bold;', details);
    }

    //FIREWALL DE MUTATION DO DOM & MONKEY PATCHING

    isAllowedNode(node) {
        if (!(node instanceof Element)) return true;
        return this.config.policy.allowSelectors.some(sel => {
            try {
                return node.matches(sel) || node.closest(sel);
            } catch {
                return false;
            }
        });
    }

    initDomFirewall() {
        if (this.state.domFirewallInstalled) return;
        this.state.domFirewallInstalled = true;

        const self = this;
        const methods = ['appendChild', 'removeChild', 'insertBefore', 'replaceChild'];

        // Patch em métodos de manipulação de nós
        methods.forEach(method => {
            const original = Node.prototype[method];
            Node.prototype[method] = function(...args) {
                const target = args[0];
                if (!self.isAllowedNode(this) || !self.isAllowedNode(target)) {
                    self.state.blockedMutationCount++;

                    if (
                        self.config.memory.purgeOnMutationBurst &&
                        self.config.memory.autoPurgeMutationThreshold > 0 &&
                        self.state.blockedMutationCount % self.config.memory.autoPurgeMutationThreshold === 0
                    ) {
                        console.log(`%c[AEGIS HARDENING] Mutações barradas: ${self.state.blockedMutationCount}. Compactando referências...`, 'color: #ff3300; font-weight: bold;');
                        self.purgeDetachedNodes();
                    }

                    if (self.config.policy.logMutations) {
                        console.warn(`🚨 Aegis DOM Shield -> Método [${method}] bloqueado no alvo:`, this, target);
                    }
                    // Tratamento específico para o erro de dessincronização de parentNode (removeChild)
                    if (method === 'removeChild' && target && target.parentNode !== this) {
                        console.warn('⚠️ Aegis interceptou removeChild inválido para prevenir exception de runtime.');
                        return target;
                    }
                    return target; // Aborta e retorna o nó sem alterar a árvore física
                }
                return original.apply(this, args);
            };
        });

        // Patch em atributos
        const setAttrOriginal = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
            if (!self.isAllowedNode(this)) {
                if (self.config.policy.logMutations) console.warn('🚨 Aegis Attr Shield -> setAttribute bloqueado:', this, name);
                return;
            }
            return setAttrOriginal.call(this, name, value);
        };

        // MutationObserver como Firewall de segunda linha
        const observer = new MutationObserver(mutations => {
            mutations.forEach(m => {
                if (!self.isAllowedNode(m.target)) {
                    if (self.config.policy.revertMutations) {
                        if (m.type === 'childList') {
                            m.addedNodes.forEach(n => {
                                if (typeof n.remove === 'function') n.remove();
                            });
                        }
                    }
                }
            });
        });

        observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });

        // Camada de camuflagem de assinatura de função nativa (Anti-Inspecção)
        try {
            EventTarget.prototype.addEventListener.toString = function() {
                return self.nativoToString.call(EventTarget.prototype.addEventListener);
            };
        } catch (e) {}
    }

    //ARREMATES DE PRIVACIDADE, FOCUS & ANTI-BLUR

    initFocusHardening() {
        if (this.state.focusHardeningInstalled) return;
        this.state.focusHardeningInstalled = true;

        const self = this;

        Object.defineProperty(document, 'visibilityState', { get: () => self.config.evasion.forceVisibilityState, configurable: true });
        Object.defineProperty(document, 'hidden', { get: () => self.config.evasion.forceHiddenState, configurable: true });
        document.hasFocus = () => true;

        // Interceptação e descarte de eventos de desfoque/ociosidade
        const originalAEL = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, fn, opts) {
            if (self.config.evasion.blockEvents.includes(type)) {
                self.logMitigation('EventListener Abortado', { tipo: type });
                return;
            }
            return originalAEL.apply(this, arguments);
        };

        // Captura de eventos na fase de bootstrap (capturing: true) para anulação completa
        this.config.evasion.blockEvents.forEach(ev => {
            const blockFunc = (e) => {
                e.stopImmediatePropagation();
                e.preventDefault();
            };
            window.addEventListener(ev, blockFunc, true);
            document.addEventListener(ev, blockFunc, true);
        });
    }

    //KEEP-ALIVE DE HARDWARE & ANTI-SLEEP ENGINE

    async initKeepAlivePipeline() {
        if (this.state.keepAliveInstalled) return;
        this.state.keepAliveInstalled = true;

        const self = this;

        //WakeLock API
        if (this.config.keepAlive.wakeLockScreen) {
            const holdLock = async () => {
                try {
                    if ('wakeLock' in navigator) {
                        let lock = await navigator.wakeLock.request('screen');
                        lock.addEventListener('release', () => setTimeout(holdLock, 100));
                    }
                } catch (e) {}
                try {
                    if ('locks' in navigator) {
                        navigator.locks.request('keep-alive-lock', { mode: 'exclusive' }, () => new Promise(() => {}));
                    }
                } catch (e) {}
            };
            await holdLock();
        }

        //Audio Context Sônico Silencioso
        const startSilentAudio = () => {
            try {
                self.state.audioContextRef = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = self.state.audioContextRef.createOscillator();
                const gainNode = self.state.audioContextRef.createGain();
                gainNode.gain.value = 0;
                oscillator.connect(gainNode);
                gainNode.connect(self.state.audioContextRef.destination);
                oscillator.start();

                setInterval(() => {
                    if (self.state.audioContextRef && self.state.audioContextRef.state === 'suspended') {
                        self.state.audioContextRef.resume();
                    }
                }, self.config.keepAlive.silentAudioInterval);
            } catch (e) {}
        };
        document.addEventListener('click', startSilentAudio, { once: true });
        document.addEventListener('keydown', startSilentAudio, { once: true });

        //Monitor de Drift Temporal (Aggressive Tick)
        let lastTick = Date.now();
        const tick = () => {
            const now = Date.now();
            const drift = now - lastTick - self.config.keepAlive.aggressiveTickInterval;
            if (drift > self.config.keepAlive.driftThreshold) {
                if (self.state.audioContextRef && typeof self.state.audioContextRef.resume === 'function') {
                    self.state.audioContextRef.resume();
                }
                self.logMitigation('Drift Temporal Corrigido', { driftDetected: drift });
            }
            lastTick = now;
            setTimeout(tick, self.config.keepAlive.aggressiveTickInterval);
        };
        tick();
    }

    // PROXY DE EVENTOS BIOMÉTRICOS (`isTrusted: true`) E SIMULAÇÃO DE MOVIMENTO HUMANO REALISTA
    criaSpoofedEvent(type, options = {}) {
        const baseEvent = new PointerEvent(type, {
            bubbles: true,
            cancelable: true,
            composed: true,
            view: window,
            ...options
        });

        // Criação do Proxy Criptográfico sobre o evento nativo
        const spoofed = new Proxy(baseEvent, {
            get(target, prop, receiver) {
                if (prop === 'isTrusted') return true;
                if (prop === 'getOwnPropertyDescriptor') {
                    return function(key) {
                        if (key === 'isTrusted') return undefined;
                        return Reflect.get(target, prop, receiver).apply(target, arguments);
                    };
                }
                if (prop === 'hasOwnProperty') {
                    return function(key) {
                        if (key === 'isTrusted') return false;
                        return Reflect.get(target, prop, receiver).apply(target, arguments);
                    };
                }
                if (prop === 'toString') {
                    return () => `[object ${options.pointerType === 'touch' ? 'TouchEvent' : 'MouseEvent'}]`;
                }
                return Reflect.get(target, prop, receiver);
            },
            getPrototypeOf() {
                return MouseEvent.prototype;
            }
        });

        if (this.config.evasion.spoofIsTrusted) {
            try {
                Object.defineProperty(spoofed, 'isTrusted', { get: () => true, configurable: true });
            } catch (e) {}
        }
        return spoofed;
    }

    fireMouseEvent(type, x, y) {
        const event = this.criaSpoofedEvent(type, {
            clientX: x, clientY: y,
            screenX: x + (window.screenX || 0), screenY: y + (window.screenY || 0),
            buttons: 0, button: 0,
            movementX: this.jitter(0, 1.3), movementY: this.jitter(0, 1.3)
        });
        const target = document.elementFromPoint(Math.max(0, x), y) || document.body;
        target.dispatchEvent(event);
    }

    firePointerEvent(type, x, y) {
        const event = this.criaSpoofedEvent(type, {
            clientX: x, clientY: y,
            screenX: x + (window.screenX || 0), screenY: y + (window.screenY || 0),
            pointerId: 1, pointerType: 'mouse', isPrimary: true, pressure: 0, buttons: 0
        });
        const target = document.elementFromPoint(Math.max(0, x), y) || document.body;
        target.dispatchEvent(event);
    }

    //Funções de suavização cinemática
    easeInOut(t) { return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t; }
    jitter(v, a = 1.8) { return v + (Math.random() * a * 2 - a); }
    lerp(a, b, t) { return a + (b - a) * t; }
    sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    async simulateMouseMotion() {
        const p = this.config.evasion.mouseParams;
        const fixedY = p.y ?? Math.floor(window.innerHeight * 0.38 + Math.random() * window.innerHeight * 0.24);

        this.fireMouseEvent('mouseenter', 0, fixedY);
        await this.sleep(12);

        // Movimento de Ida (Aceleração Física)
        for (let i = 0; i <= p.steps; i++) {
            const t = this.easeInOut(i / p.steps);
            const x = Math.round(Math.max(0, this.lerp(p.startX, p.endX, t)));
            const cy = Math.round(this.jitter(fixedY));
            this.fireMouseEvent('mousemove', x, cy);
            this.firePointerEvent('pointermove', x, cy);
            await this.sleep(p.delayMs + Math.random() * 9);
        }

        await this.sleep(p.pauseAtEnd + Math.random() * 80);

        // Movimento de Volta (Desaceleração Física)
        for (let i = 0; i <= p.steps; i++) {
            const t = this.easeInOut(i / p.steps);
            const x = Math.round(Math.max(0, this.lerp(p.endX, p.startX, t)));
            const cy = Math.round(this.jitter(fixedY));
            this.fireMouseEvent('mousemove', x, cy);
            this.firePointerEvent('pointermove', x, cy);
            await this.sleep(p.delayMs + Math.random() * 9);
        }

        this.fireMouseEvent('mouseleave', -5, fixedY);
        this.fireMouseEvent('mouseout', -5, fixedY);
    }

    //DISCOVERY ENGINE (SCANNER RECURSIVO DE MEMÓRIA E DOM
    deepSearchMemory(obj, path = 'window') {
        if (!obj || typeof obj !== 'object' || this.state.visitedObjects.has(obj)) return;
        this.state.visitedObjects.add(obj);

        const targetKey = this.config.evasion.targetKeyToSearch;

        try {
            if (Object.prototype.hasOwnProperty.call(obj, targetKey)) {
                this.state.discoveredItems.push(Object.freeze({ path, value: obj[targetKey], object: obj }));
                console.log(`%c[AEGIS DISCOVERY FOUND] Encontrado em: ${path}`, 'color: #55ff55; font-weight: bold;', obj[targetKey]);
            }

            for (const key in obj) {
                if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
                let value;
                try { value = obj[key]; } catch { continue; }

                if (value && typeof value === 'object') {
                    this.deepSearchMemory(value, `${path}.${key}`);
                } else if (key === targetKey) {
                    this.state.discoveredItems.push(Object.freeze({ path: `${path}.${key}`, value, object: obj }));
                    console.log(`%c[AEGIS DISCOVERY FOUND] Encontrado direto: ${path}.${key}`, 'color: #55ff55; font-weight: bold;', value);
                }
            }
        } catch (e) {}
    }

    //SCAN DE MEMÓRIA HEAP E DOM PARA LOCALIZAÇÃO DE CHAVES/VALORES SENSÍVEIS, COM RELATÓRIO FORNECIDO AO FIM DO PROCESSO
    executeFullDiscoveryScan() {
        this.updateState('SCANNING_HEAP', { target: this.config.evasion.targetKeyToSearch });
        this.state.discoveredItems = [];
        this.state.visitedObjects = new WeakSet();
        
        // Scan na memória global (window)
        this.deepSearchMemory(window, 'window');

        // Scan nos elementos físicos e árvores lógicas do DOM
        const allElements = [document, document.documentElement, document.body, ...document.querySelectorAll('*')];
        for (const el of allElements) {
            if (!el || typeof el !== 'object') continue;
            const id = el.id ? `#${el.id}` : '';
            const classes = el.className ? `.${Array.from(el.classList).join('.')}` : '';
            const tag = el.tagName ? `<${el.tagName.toLowerCase()}>` : 'element';
            this.deepSearchMemory(el, `DOM ${tag}${id}${classes}`);
        }

        // Exposição blindada dos resultados do scan
        if (this.state.discoveredItems.length > 0) {
            this.publishDiscoveryResults('__aegisDiscoveryResults', this.state.discoveredItems);

            if (
                this.config.memory.exposeEnabledToolsAlias &&
                this.config.evasion.targetKeyToSearch === 'enabledTools'
            ) {
                this.publishDiscoveryResults('__enabledToolsResults', this.state.discoveredItems);
            }
        } else {
            this.releasePublishedResults('__aegisDiscoveryResults');
            this.releasePublishedResults('__enabledToolsResults');
        }
        this.updateState('SCAN_FINISHED', { totalFound: this.state.discoveredItems.length });
    }

    initXhrSniffer() {
        if (this.state.xhrSnifferInstalled || !this.config.network.monitorXHR) return;
        if (typeof XMLHttpRequest === 'undefined') return;
        if (typeof this.xhrOriginalOpen !== 'function' || typeof this.xhrOriginalSend !== 'function') return;

        this.state.xhrSnifferInstalled = true;
        const self = this;

        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this._aegisContext = {
                method,
                url,
                timestampInicio: Date.now()
            };
            return self.xhrOriginalOpen.apply(this, [method, url, ...args]);
        };

        XMLHttpRequest.prototype.send = function(payload, ...args) {
            const xhrInstance = this;

            if (xhrInstance._aegisContext) {
                xhrInstance._aegisContext.payloadEnviado = payload ?? null;
            }

            const onReadyStateChange = function() {
                if (xhrInstance.readyState !== 4) return;

                try {
                    const tempoTotal = Date.now() - (xhrInstance._aegisContext?.timestampInicio ?? Date.now());
                    self.imprimirPainelXhr({
                        url: xhrInstance._aegisContext?.url || 'Desconhecida',
                        metodo: xhrInstance._aegisContext?.method || 'GET',
                        status: xhrInstance.status,
                        tempoRespostaMs: `${tempoTotal}ms`,
                        requestBody: xhrInstance._aegisContext?.payloadEnviado ?? null,
                        responseBody: self.parseXhrResponseBody(xhrInstance.responseText)
                    });
                } catch (err) {
                    console.error('[-] Erro no parser XHR do Codex:', err.message);
                } finally {
                    delete xhrInstance._aegisContext;
                    xhrInstance.removeEventListener('readystatechange', onReadyStateChange);
                }
            };

            xhrInstance.addEventListener('readystatechange', onReadyStateChange);
            return self.xhrOriginalSend.apply(this, [payload, ...args]);
        };
    }

    parseXhrResponseBody(responseText) {
        if (!responseText) return null;

        try {
            return JSON.parse(responseText);
        } catch (e) {
            const len = this.config.network.truncateResponseLen;
            return responseText.substring(0, len) + '... [Truncado]';
        }
    }

    imprimirPainelXhr(dados) {
        const corStatus = dados.status >= 200 && dados.status < 300 ? '#00ff00' : '#ff3333';
        const urlPreview = typeof dados.url === 'string' ? dados.url.substring(0, 50) : 'Desconhecida';

        console.group(`%c[XHR NETWORK EVENT] -> ${dados.metodo} | ${urlPreview}...`, `color: ${corStatus}; font-weight: bold;`);
        console.log(`%cStatus Code:%c ${dados.status} %c| Latência:%c ${dados.tempoRespostaMs}`,
            'color: #aaa;', `color: ${corStatus}; font-weight: bold;`, 'color: #aaa;', 'color: #ffcc00;');
        if (dados.requestBody) console.dir(dados.requestBody);
        console.dir(dados.responseBody);
        console.groupEnd();
    }

    publishDiscoveryResults(propertyName, items) {
        if (typeof window === 'undefined') return;

        const frozenItems = Object.freeze([...items]);

        try {
            const descriptor = Object.getOwnPropertyDescriptor(window, propertyName);
            if (descriptor?.configurable) {
                delete window[propertyName];
            }

            if (!descriptor || descriptor.configurable) {
                Object.defineProperty(window, propertyName, {
                    value: frozenItems,
                    writable: false,
                    configurable: true
                });
                return;
            }
        } catch (e) {}

        try {
            window[propertyName] = frozenItems;
        } catch (e) {}
    }

    releasePublishedResults(propertyName) {
        if (typeof window === 'undefined') return;

        try {
            const descriptor = Object.getOwnPropertyDescriptor(window, propertyName);
            if (!descriptor) return;
            if (descriptor.configurable) {
                delete window[propertyName];
                return;
            }
            if (descriptor.writable) {
                window[propertyName] = null;
            }
        } catch (e) {}
    }

    collectDetachedNodeCandidates() {
        if (typeof Node === 'undefined') return [];

        const candidates = [];
        const seenNodes = new WeakSet();

        const pushCandidate = (candidate) => {
            if (!(candidate instanceof Node) || seenNodes.has(candidate)) return;
            seenNodes.add(candidate);
            candidates.push(candidate);
        };

        this.state.discoveredItems.forEach(item => {
            pushCandidate(item.object);
            pushCandidate(item.value);
        });

        return candidates;
    }

    purgeDetachedNodes() {
        if (typeof document === 'undefined' || typeof Node === 'undefined') return 0;

        console.log('%c[AEGIS PURGE] Iniciando varredura e quebra de referências de nós fantasmas...', 'color: #ffaa00; font-weight: bold;');
        let contagemPurga = 0;

        this.collectDetachedNodeCandidates().forEach(node => {
            if (node.isConnected) return;
            if (this.nullifyProperties(node)) {
                contagemPurga++;
            }
        });

        this.state.discoveredItems = this.state.discoveredItems.filter(item => {
            const objectDetached = typeof Node !== 'undefined' && item.object instanceof Node && !item.object.isConnected;
            const valueDetached = typeof Node !== 'undefined' && item.value instanceof Node && !item.value.isConnected;
            return !objectDetached && !valueDetached;
        });
        this.state.visitedObjects = new WeakSet();

        this.releasePublishedResults('__enabledToolsResults');
        this.releasePublishedResults('__aegisDiscoveryResults');

        console.log(`%c[AEGIS PURGE SUCCESS] Limpeza concluída. ${contagemPurga} nós desvinculados com sucesso.`, 'color: #00ff00; font-weight: bold;');
        return contagemPurga;
    }

    nullifyProperties(node) {
        if (typeof Node === 'undefined' || !(node instanceof Node)) return false;

        try {
            if (node.parentNode && typeof node.parentNode.removeChild === 'function') {
                node.parentNode.removeChild(node);
            }

            Object.getOwnPropertyNames(node).forEach(prop => {
                try { node[prop] = null; } catch {}
            });
            return true;
        } catch (e) {}

        return false;
    }

    async executePipeline(inputData = {}) {
        this.updateState('PENDING', { input: inputData });

        try {
            this.updateState('STEP_1_INIT_SUCCESS', { status: 'Anti-detection loaded' });
            const runtimeResult = await this.start();
            return {
                success: true,
                processId: this.processId,
                state: this.state.currentState,
                runtime: runtimeResult
            };
        } catch (error) {
            this.updateState('REJECTED', { error: error.message });
            throw error;
        }
    }

    //TRAP DE ERROS GLOBAIS E DEEP FREEZE DO CONSOLE (ANTI-INSPEÇÃO DE ERROS)
    initGlobalDiagnostics() {
        if (this.state.diagnosticsInstalled) return;
        this.state.diagnosticsInstalled = true;

        window.addEventListener("error", (e) => {
            console.group("%c🔥 Aegis Erro Global Capturado", "color: #ff0000;");
            console.error(e.message);
            console.log("Origem:", e.filename, "Linha:", e.lineno);
            console.groupEnd();
        });

        window.addEventListener("unhandledrejection", (e) => {
            console.group("%c💥 Aegis Promise Rejeitada Capturada", "color: #ff3300;");
            console.error(e.reason);
            console.groupEnd();
        });

        if (this.config.policy.freezeConsole) {
            const deepFreeze = (obj, seen = new WeakSet()) => {
                if (!obj || typeof obj !== 'object' || seen.has(obj)) return;
                seen.add(obj);
                Object.freeze(obj);
                Object.getOwnPropertyNames(obj).forEach(prop => {
                    try { deepFreeze(obj[prop], seen); } catch {}
                });
            };
            deepFreeze(console);
        }
    }

    primeBlockingMode() {
        if (this.state.blockingModePrimed) return false;

        this.state.blockingModePrimed = true;
        this.updateState('BOOTSTRAP_PRIME', { status: 'Modo de bloqueio antecipado armado.' });

        this.initXhrSniffer();
        this.initGlobalDiagnostics();
        this.initDomFirewall();
        this.initFocusHardening();

        return true;
    }

    //PIPELINE start
    async start() {
        if (this.startPromise) {
            return this.startPromise;
        }

        this.startPromise = (async () => {
            this.updateState('BOOTSTRAP');
            
            this.primeBlockingMode();
            await this.initKeepAlivePipeline();
            
            // Inicializa loop de simulação de movimento biométrico estável
            this.updateState('SPOOF_ACTIVE', { frequency: `${this.config.evasion.mouseSimulationInterval}ms` });
            await this.simulateMouseMotion();

            if (!this.mouseSimulationIntervalRef) {
                this.mouseSimulationIntervalRef = setInterval(async () => {
                    await this.simulateMouseMotion();
                }, this.config.evasion.mouseSimulationInterval);
            }

            // Dispara o Scanner de Memória Heap de forma assíncrona pós-inicialização
            if (!this.discoveryTimeoutRef) {
                this.discoveryTimeoutRef = setTimeout(() => {
                    this.executeFullDiscoveryScan();
                    this.discoveryTimeoutRef = null;
                }, 2000);
            }

            this.updateState('RESOLVED', { status: 'Modo furtivo totalmente operacional em todas as camadas.' });
            return { success: true, processId: this.processId, state: this.state.currentState };
        })();

        try {
            return await this.startPromise;
        } catch (error) {
            this.startPromise = null;
            throw error;
        }
    }
}

function resolveAegisConsoleEngine(config = {}) {
    const shouldReplaceInstance = Object.keys(config).length > 0;

    if (shouldReplaceInstance || !(globalThis.__aegisConsoleEngine instanceof AegisCodexEngine)) {
        globalThis.__aegisConsoleEngine = new AegisCodexEngine(config);
    }

    return globalThis.__aegisConsoleEngine;
}

resolveAegisConsoleEngine().primeBlockingMode();

function getLoadedAegisConsoleEngine() {
    if (globalThis.__aegisConsoleEngine instanceof AegisCodexEngine) {
        return globalThis.__aegisConsoleEngine;
    }
    return null;
}

function formatAegisManualValue(value) {
    if (value === undefined) return '(indefinido)';
    if (value === null) return 'null';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (typeof value === 'function') return `[Function ${value.name || 'anonymous'}]`;
    try {
        return JSON.stringify(value);
    } catch (error) {
        return Object.prototype.toString.call(value);
    }
}

function readAegisPath(source, pathExpression) {
    return pathExpression.split('.').reduce((currentValue, currentKey) => {
        if (currentValue == null) return undefined;
        return currentValue[currentKey];
    }, source);
}

const AEGIS_MANUAL_STYLES = {
    overview: 'color: #ffffff; background: #004466; font-weight: bold; padding: 2px 6px;',
    startup: 'color: #ffffff; background: #0f766e; font-weight: bold; padding: 2px 6px;',
    success: 'color: #22c55e; font-weight: bold;',
    error: 'color: #ef4444; font-weight: bold;',
    active: 'color: #22c55e; font-weight: bold;',
    inactive: 'color: #9ca3af; font-weight: bold;',
    api: 'color: #7dd3fc; font-weight: bold;',
    methods: 'color: #c084fc; font-weight: bold;',
    workflow: 'color: #38bdf8; font-weight: bold;',
    config: 'color: #facc15; font-weight: bold;',
    policy: 'color: #fde68a; font-weight: bold;',
    keepAlive: 'color: #fb923c; font-weight: bold;',
    network: 'color: #22d3ee; font-weight: bold;',
    memory: 'color: #f97316; font-weight: bold;',
    evasion: 'color: #a3e635; font-weight: bold;',
    state: 'color: #34d399; font-weight: bold;',
    stateSummary: 'color: #22c55e; font-weight: bold;',
    examples: 'color: #f472b6; font-weight: bold;',
    instance: 'color: #f59e0b; font-weight: bold;',
    info: 'color: #60a5fa; font-weight: bold;',
    warning: 'color: #f87171; font-weight: bold;'
};

const AEGIS_CONFIG_SECTION_STYLES = {
    policy: AEGIS_MANUAL_STYLES.policy,
    keepAlive: AEGIS_MANUAL_STYLES.keepAlive,
    network: AEGIS_MANUAL_STYLES.network,
    memory: AEGIS_MANUAL_STYLES.memory,
    evasion: AEGIS_MANUAL_STYLES.evasion
};

function printAegisStyledLine(level, style, label, ...args) {
    console[level](`%c${label}`, style, ...args);
}

function printAegisTable(title, rows, style = AEGIS_MANUAL_STYLES.info) {
    console.group(`%c${title}`, style);
    console.table(rows);
    console.groupEnd();
}

const AEGIS_CONSOLE_API_DOCS = [
    { nome: 'AegisConsole.create(config)', retorno: 'AegisCodexEngine', descricao: 'Cria ou substitui a instancia global do Aegis para o console com a configuracao informada.' },
    { nome: 'AegisConsole.getInstance()', retorno: 'AegisCodexEngine', descricao: 'Retorna a instancia ja carregada ou cria uma nova com a configuracao padrao.' },
    { nome: 'AegisConsole.start(config)', retorno: 'Promise<object>', descricao: 'Inicializa o pipeline principal no navegador, incluindo firewall, foco, keep-alive e scanner.' },
    { nome: 'AegisConsole.executePipeline(inputData, config)', retorno: 'Promise<object>', descricao: 'Executa o fluxo orientado a Promise e reaproveita o start interno do motor.' },
    { nome: 'AegisConsole.status()', retorno: 'void', descricao: 'Mostra painel colorido com ferramentas ativas/inativas, funcoes disponiveis e configuracao atual.' },
    { nome: 'AegisConsole.scan()', retorno: 'void', descricao: 'Executa o discovery scan em memoria e DOM e publica os resultados globais.' },
    { nome: 'AegisConsole.purge()', retorno: 'number', descricao: 'Tenta purgar nos destacados e limpar resultados publicados em window.' },
    { nome: 'AegisConsole.history()', retorno: 'Array<object>', descricao: 'Retorna o historico congelado de estados registrados pelo engine.' },
    { nome: 'AegisConsole.methods()', retorno: 'void', descricao: 'Mostra no console todas as funcoes publicas da API e do engine.' },
    { nome: 'AegisConsole.config(section?)', retorno: 'void', descricao: 'Mostra as configuracoes conhecidas por secao e o valor atual da instancia.' },
    { nome: 'AegisConsole.state()', retorno: 'void', descricao: 'Exibe o estado de runtime, timers, historico e telemetria carregada.' },
    { nome: 'AegisConsole.inspect()', retorno: 'AegisCodexEngine|null', descricao: 'Faz console.dir da instancia atual para inspecao manual detalhada.' },
    { nome: 'AegisConsole.examples()', retorno: 'void', descricao: 'Lista exemplos prontos de uso no console do navegador.' },
    { nome: 'AegisConsole.topics()', retorno: 'Array<string>', descricao: 'Lista os topicos aceitos pelo manual interativo.' },
    { nome: 'AegisConsole.manual(topic?)', retorno: 'void', descricao: 'Manual detalhado por topico: all, api, workflow, methods, config, state, examples, instance.' },
    { nome: 'AegisConsole.help(topic?)', retorno: 'void', descricao: 'Alias de manual(topic).'}
];

const AEGIS_ENGINE_METHOD_DOCS = [
    { nome: 'updateState(newState, dataPayload = {})', retorno: 'void', descricao: 'Atualiza o estado corrente e grava um snapshot imutavel no historico.' },
    { nome: 'getHistory()', retorno: 'Array<object>', descricao: 'Devolve uma copia congelada do historico de estados.' },
    { nome: 'logMitigation(type, details)', retorno: 'void', descricao: 'Registra mitigacoes detectadas e imprime aviso no console.' },
    { nome: 'isAllowedNode(node)', retorno: 'boolean', descricao: 'Valida se um no pertence a area permitida pela policy.allowSelectors.' },
    { nome: 'initDomFirewall()', retorno: 'void', descricao: 'Pacha mutacoes de DOM, monitora bursts e aciona purga automatica quando configurado.' },
    { nome: 'initFocusHardening()', retorno: 'void', descricao: 'Forca visibilidade/foco e bloqueia eventos de blur, freeze e page lifecycle.' },
    { nome: 'initKeepAlivePipeline()', retorno: 'Promise<void>', descricao: 'Ativa wake lock, audio silencioso e o tick agressivo anti-suspensao.' },
    { nome: 'criaSpoofedEvent(type, options = {})', retorno: 'Event', descricao: 'Cria evento proxificado com mascara para propriedades de confianca.' },
    { nome: 'fireMouseEvent(type, x, y)', retorno: 'void', descricao: 'Dispara um evento de mouse sintetico no alvo do ponto informado.' },
    { nome: 'firePointerEvent(type, x, y)', retorno: 'void', descricao: 'Dispara um evento pointer sintetico no alvo do ponto informado.' },
    { nome: 'easeInOut(t)', retorno: 'number', descricao: 'Curva de interpolacao usada na simulacao de movimento.' },
    { nome: 'jitter(v, a = 1.8)', retorno: 'number', descricao: 'Adiciona ruído pseudo-humano a coordenadas e deslocamentos.' },
    { nome: 'lerp(a, b, t)', retorno: 'number', descricao: 'Interpolacao linear entre dois valores.' },
    { nome: 'sleep(ms)', retorno: 'Promise<void>', descricao: 'Pausa assicrona usada na cinematica do mouse.' },
    { nome: 'simulateMouseMotion()', retorno: 'Promise<void>', descricao: 'Executa o ciclo completo de movimento biometrico sintetico.' },
    { nome: 'deepSearchMemory(obj, path = "window")', retorno: 'void', descricao: 'Percorre memoria e DOM buscando a chave configurada em evasion.targetKeyToSearch.' },
    { nome: 'executeFullDiscoveryScan()', retorno: 'void', descricao: 'Reinicia discovery, varre window/DOM e publica resultados globais congelados.' },
    { nome: 'initXhrSniffer()', retorno: 'void', descricao: 'Intercepta XMLHttpRequest.open/send e registra request/response no console.' },
    { nome: 'parseXhrResponseBody(responseText)', retorno: 'object|string|null', descricao: 'Tenta parsear JSON ou trunca o texto de resposta para exibicao.' },
    { nome: 'imprimirPainelXhr(dados)', retorno: 'void', descricao: 'Mostra painel agrupado com status, latencia, payload e resposta.' },
    { nome: 'publishDiscoveryResults(propertyName, items)', retorno: 'void', descricao: 'Publica resultados em window usando propriedades congeladas.' },
    { nome: 'releasePublishedResults(propertyName)', retorno: 'void', descricao: 'Libera ou remove propriedades globais publicadas pelo scanner.' },
    { nome: 'collectDetachedNodeCandidates()', retorno: 'Array<Node>', descricao: 'Coleta candidatos a purga com base nos itens descobertos.' },
    { nome: 'purgeDetachedNodes()', retorno: 'number', descricao: 'Tenta limpar nos destacados retidos e reseta caches de discovery.' },
    { nome: 'nullifyProperties(node)', retorno: 'boolean', descricao: 'Quebra referencias de um no para estimular limpeza pelo GC.' },
    { nome: 'executePipeline(inputData = {})', retorno: 'Promise<object>', descricao: 'Wrapper Promise-based do pipeline principal com estados PENDING/REJECTED.' },
    { nome: 'initGlobalDiagnostics()', retorno: 'void', descricao: 'Registra handlers globais de error e unhandledrejection e opcionalmente congela console.' },
    { nome: 'start()', retorno: 'Promise<object>', descricao: 'Bootstrap idempotente do engine, com timers e scanner pos-inicializacao.' }
];

const AEGIS_CONFIG_DOCS = {
    policy: [
        { chave: 'policy.allowSelectors', padrao: '["#app", "[data-safe]"]', descricao: 'Seletores permitidos para mutacao de DOM sem bloqueio.' },
        { chave: 'policy.logMutations', padrao: 'true', descricao: 'Liga logs de transicao de estado e bloqueios do firewall.' },
        { chave: 'policy.revertMutations', padrao: 'true', descricao: 'Tenta remover nos adicionados por mutacoes fora da policy.' },
        { chave: 'policy.freezeConsole', padrao: 'true', descricao: 'Congela o objeto console quando initGlobalDiagnostics e executado.' }
    ],
    keepAlive: [
        { chave: 'keepAlive.wakeLockScreen', padrao: 'true', descricao: 'Solicita wake lock de tela quando a API existe.' },
        { chave: 'keepAlive.silentAudioInterval', padrao: '500', descricao: 'Intervalo de retomada do contexto de audio silencioso.' },
        { chave: 'keepAlive.aggressiveTickInterval', padrao: '100', descricao: 'Intervalo base do tick anti-drift temporal.' },
        { chave: 'keepAlive.driftThreshold', padrao: '200', descricao: 'Desvio maximo tolerado antes de registrar mitigacao de drift.' }
    ],
    network: [
        { chave: 'network.monitorXHR', padrao: 'true', descricao: 'Ativa o sniffer de XMLHttpRequest.' },
        { chave: 'network.truncateResponseLen', padrao: '200', descricao: 'Limite de truncamento para respostas nao JSON.' }
    ],
    memory: [
        { chave: 'memory.purgeOnMutationBurst', padrao: 'true', descricao: 'Ativa purga automatica quando ha muitos bloqueios de mutacao.' },
        { chave: 'memory.autoPurgeMutationThreshold', padrao: '50000', descricao: 'Quantidade de mutacoes barradas antes de disparar purgeDetachedNodes.' },
        { chave: 'memory.exposeEnabledToolsAlias', padrao: 'true', descricao: 'Publica alias __enabledToolsResults para compatibilidade de discovery.' }
    ],
    evasion: [
        { chave: 'evasion.targetKeyToSearch', padrao: 'enabledTools', descricao: 'Chave procurada em window e DOM pelo discovery engine.' },
        { chave: 'evasion.blockEvents', padrao: '["visibilitychange", "blur", "mouseleave", "freeze", "pagehide", "pageshow"]', descricao: 'Eventos bloqueados durante o hardening de foco.' },
        { chave: 'evasion.forceVisibilityState', padrao: 'visible', descricao: 'Valor exposto por document.visibilityState apos o hardening.' },
        { chave: 'evasion.forceHiddenState', padrao: 'false', descricao: 'Valor exposto por document.hidden apos o hardening.' },
        { chave: 'evasion.spoofIsTrusted', padrao: 'true', descricao: 'Tenta mascarar isTrusted nos eventos sinteticos.' },
        { chave: 'evasion.mouseSimulationInterval', padrao: '1000', descricao: 'Intervalo de repeticao da simulacao de movimento.' },
        { chave: 'evasion.mouseParams.startX', padrao: '-5', descricao: 'Posicao inicial da trajetoria sintetica.' },
        { chave: 'evasion.mouseParams.endX', padrao: '43', descricao: 'Posicao final da trajetoria sintetica.' },
        { chave: 'evasion.mouseParams.steps', padrao: '38', descricao: 'Numero de passos por trecho da trajetoria.' },
        { chave: 'evasion.mouseParams.delayMs', padrao: '13', descricao: 'Atraso base entre passos da simulacao.' },
        { chave: 'evasion.mouseParams.pauseAtEnd', padrao: '450', descricao: 'Pausa antes do movimento de retorno.' }
    ]
};

const AEGIS_STATE_DOCS = [
    { chave: 'state.currentState', descricao: 'Ultimo estado textual registrado pelo engine.' },
    { chave: 'state.history', descricao: 'Historico completo de snapshots de runtime.' },
    { chave: 'state.discoveredItems', descricao: 'Itens encontrados durante o discovery engine.' },
    { chave: 'state.visitedObjects', descricao: 'WeakSet usada para evitar loops na busca recursiva.' },
    { chave: 'state.mitigationLog', descricao: 'Registro de mitigacoes disparadas pelo runtime.' },
    { chave: 'state.audioContextRef', descricao: 'Referencia do contexto de audio silencioso.' },
    { chave: 'state.blockedMutationCount', descricao: 'Contador de mutacoes barradas pelo firewall.' },
    { chave: 'state.domFirewallInstalled', descricao: 'Indica se os patches de DOM ja foram aplicados.' },
    { chave: 'state.xhrSnifferInstalled', descricao: 'Indica se o sniffer de XHR ja foi instalado.' },
    { chave: 'startPromise', descricao: 'Promise memoizada para evitar bootstrap duplicado.' },
    { chave: 'mouseSimulationIntervalRef', descricao: 'Referencia do setInterval da simulacao de movimento.' },
    { chave: 'discoveryTimeoutRef', descricao: 'Referencia do setTimeout que dispara o scan pos-bootstrap.' }
];

const AEGIS_EXAMPLE_DOCS = [
    { caso: 'Criar instancia', comando: 'AegisConsole.create()', objetivo: 'Cria uma nova instancia usando a configuracao padrao.' },
    { caso: 'Criar com config customizada', comando: 'AegisConsole.create({ policy: { logMutations: false } })', objetivo: 'Substitui a instancia global usando a configuracao informada.' },
    { caso: 'Iniciar runtime', comando: 'await AegisConsole.start()', objetivo: 'Executa o bootstrap completo do motor.' },
    { caso: 'Painel de status', comando: 'AegisConsole.status()', objetivo: 'Mostra ferramentas, funcoes e configuracao atual do runtime.' },
    { caso: 'Rodar pipeline', comando: 'await AegisConsole.executePipeline({ action: "stealth_scan" })', objetivo: 'Usa a interface Promise-based do pipeline.' },
    { caso: 'Inspecionar config', comando: 'AegisConsole.config()', objetivo: 'Lista todas as configuracoes conhecidas e os valores atuais.' },
    { caso: 'Inspecionar secao', comando: 'AegisConsole.config("network")', objetivo: 'Mostra apenas a secao de configuracao desejada.' },
    { caso: 'Ler estado', comando: 'AegisConsole.state()', objetivo: 'Mostra o estado de runtime, timers e contadores.' },
    { caso: 'Varredura manual', comando: 'AegisConsole.scan()', objetivo: 'Executa discovery sem reinicializar o runtime.' },
    { caso: 'Purga manual', comando: 'AegisConsole.purge()', objetivo: 'Executa a limpeza de referencias destacadas.' },
    { caso: 'Historico', comando: 'AegisConsole.history()', objetivo: 'Retorna o historico de transicoes do engine.' },
    { caso: 'Inspecao profunda', comando: 'AegisConsole.inspect()', objetivo: 'Abre a instancia atual com console.dir.' },
    { caso: 'Manual completo', comando: 'AegisConsole.manual()', objetivo: 'Imprime todo o manual da API no console.' },
    { caso: 'Fluxo detalhado', comando: 'AegisConsole.manual("workflow")', objetivo: 'Enumera a ordem de start e o uso recomendado do Aegis.' },
    { caso: 'Manual por topico', comando: 'AegisConsole.manual("config")', objetivo: 'Imprime apenas o topico desejado.' }
];

const AEGIS_WORKFLOW_DOCS = [
    {
        etapa: '0. Prime antecipado',
        comando: 'resolveAegisConsoleEngine() + primeBlockingMode()',
        objetivo: 'Armar o modo de bloqueio o mais cedo possivel dentro do arquivo.',
        detalhe: 'Assim que a classe e a instancia global existem, o script ativa XHR sniffer, diagnosticos, DOM firewall e focus hardening antes do manual e do restante do bootstrap.'
    },
    {
        etapa: '1. Criacao da instancia',
        comando: 'AegisConsole.create(config) ou AegisConsole.getInstance()',
        objetivo: 'Criar ou recuperar a instancia global do engine.',
        detalhe: 'A classe monta config, estado interno, referencias de XHR e inicializa o primeiro snapshot de estado como INIT.'
    },
    {
        etapa: '2. Revisao da configuracao',
        comando: 'AegisConsole.config() ou AegisConsole.config("policy")',
        objetivo: 'Verificar antes do bootstrap quais politicas e limites estao ativos.',
        detalhe: 'Aqui deves confirmar allowSelectors, wake lock, sniffer de XHR, purge automatica e a chave de discovery.'
    },
    {
        etapa: '3. Disparo do bootstrap',
        comando: 'await AegisConsole.start()',
        objetivo: 'Iniciar o pipeline principal do motor.',
        detalhe: 'O engine entra em BOOTSTRAP e memoiza a Promise de start para impedir inicializacao duplicada.'
    },
    {
        etapa: '4. Hook de rede',
        comando: 'initXhrSniffer()',
        objetivo: 'Instrumentar XMLHttpRequest antes do restante do runtime.',
        detalhe: 'Cada open/send passa a registrar contexto de request, tempo de resposta e o painel de analise de rede.'
    },
    {
        etapa: '5. Diagnostico global',
        comando: 'initGlobalDiagnostics()',
        objetivo: 'Armar capturas de erro e rejeicoes globais.',
        detalhe: 'Erros passam a sair agrupados no console e, se freezeConsole estiver ligado, o objeto console e congelado.'
    },
    {
        etapa: '6. Firewall e hardening',
        comando: 'initDomFirewall() + initFocusHardening()',
        objetivo: 'Blindar DOM, visibilidade e eventos sensiveis.',
        detalhe: 'Mutacoes fora da policy sao barradas, removeChild invalido e suavizado e eventos como blur/pagehide sao interceptados.'
    },
    {
        etapa: '7. Keep-alive',
        comando: 'await initKeepAlivePipeline()',
        objetivo: 'Reduzir suspensao do runtime e drift temporal.',
        detalhe: 'O motor tenta wake lock, usa audio silencioso e executa tick agressivo para retomar o contexto quando necessario.'
    },
    {
        etapa: '8. Simulacao biometrica',
        comando: 'simulateMouseMotion() + setInterval(...)',
        objetivo: 'Ativar SPOOF_ACTIVE e manter movimento sintetico recorrente.',
        detalhe: 'O primeiro ciclo roda imediatamente e depois continua no intervalo configurado em evasion.mouseSimulationInterval.'
    },
    {
        etapa: '9. Discovery pos-bootstrap',
        comando: 'setTimeout(() => executeFullDiscoveryScan(), 2000)',
        objetivo: 'Varredura automatica apos a subida do runtime.',
        detalhe: 'Window e DOM sao analisados, resultados congelados sao publicados e o alias __enabledToolsResults pode ser criado.'
    },
    {
        etapa: '10. Estado resolvido',
        comando: 'state.currentState => RESOLVED',
        objetivo: 'Marcar o runtime como operacional.',
        detalhe: 'A partir daqui o uso normal e consultar history, inspecionar estado, repetir scan ou chamar purge quando preciso.'
    },
    {
        etapa: '11. Uso cotidiano apos start',
        comando: 'AegisConsole.state() | AegisConsole.history() | AegisConsole.inspect()',
        objetivo: 'Monitorar a telemetria do runtime ja ativo.',
        detalhe: 'Esses comandos mostram contadores, snapshots, timers ativos e a instancia concreta carregada.'
    },
    {
        etapa: '12. Operacoes manuais de manutencao',
        comando: 'AegisConsole.scan() | AegisConsole.purge() | AegisConsole.executePipeline(...)',
        objetivo: 'Forcar discovery, limpeza ou rerodar o fluxo orientado a Promise.',
        detalhe: 'scan atualiza resultados, purge tenta limpar referencias destacadas e executePipeline reaproveita o start com marcacao de estados.'
    }
];

const AEGIS_MANUAL_TOPICS = ['all', 'api', 'workflow', 'methods', 'config', 'state', 'examples', 'instance'];

function getAegisToolStatuses(engine) {
    return [
        {
            nome: 'Prime antecipado',
            ativo: Boolean(engine.state.blockingModePrimed),
            detalhe: 'Arma XHR sniffer, diagnostico global, DOM firewall e focus hardening antes do manual.'
        },
        {
            nome: 'Modo de bloqueio',
            ativo: Boolean(engine.state.domFirewallInstalled && engine.state.focusHardeningInstalled),
            detalhe: 'Depende do DOM firewall e do focus hardening estarem ativos.'
        },
        {
            nome: 'DOM Firewall',
            ativo: Boolean(engine.state.domFirewallInstalled),
            detalhe: 'Intercepta mutacoes de DOM fora dos seletores permitidos.'
        },
        {
            nome: 'Focus Hardening',
            ativo: Boolean(engine.state.focusHardeningInstalled),
            detalhe: 'Bloqueia eventos de blur/page lifecycle e força foco/visibilidade.'
        },
        {
            nome: 'Diagnostico global',
            ativo: Boolean(engine.state.diagnosticsInstalled),
            detalhe: 'Captura error e unhandledrejection no escopo global.'
        },
        {
            nome: 'Keep Alive',
            ativo: Boolean(engine.state.keepAliveInstalled),
            detalhe: 'Ativa wake lock, audio silencioso e tick anti-drift.'
        },
        {
            nome: 'XHR Sniffer',
            ativo: Boolean(engine.config.network.monitorXHR && engine.state.xhrSnifferInstalled),
            detalhe: 'Intercepta XMLHttpRequest e imprime o painel de rede.'
        },
        {
            nome: 'Simulacao biometrica',
            ativo: Boolean(engine.mouseSimulationIntervalRef),
            detalhe: 'Mantem o ciclo recorrente de movimento sintetico.'
        },
        {
            nome: 'Discovery agendado',
            ativo: Boolean(engine.discoveryTimeoutRef || engine.state.currentState === 'SCAN_FINISHED'),
            detalhe: 'Executa ou ja executou a varredura automatica de window e DOM.'
        },
        {
            nome: 'Purga automatica',
            ativo: Boolean(engine.config.memory.purgeOnMutationBurst),
            detalhe: 'Dispara purgeDetachedNodes apos bursts de mutacao.'
        },
        {
            nome: 'Alias enabledTools',
            ativo: Boolean(engine.config.memory.exposeEnabledToolsAlias),
            detalhe: 'Publica __enabledToolsResults quando a chave-alvo e enabledTools.'
        },
        {
            nome: 'Freeze Console',
            ativo: Boolean(engine.config.policy.freezeConsole),
            detalhe: 'Congela o objeto console durante initGlobalDiagnostics.'
        },
        {
            nome: 'Wake Lock',
            ativo: Boolean(engine.config.keepAlive.wakeLockScreen),
            detalhe: 'Solicita wake lock de tela quando a API estiver disponivel.'
        },
        {
            nome: 'Auto-start',
            ativo: Boolean(engine.state.autoStartCompleted),
            detalhe: 'Indica se o bootstrap automatico foi concluido com sucesso ao carregar o script.'
        },
    ];
}

function getAegisFunctionStatuses() {
    const consoleApi = globalThis.AegisConsole || {};
    return [
        'create',
        'getInstance',
        'start',
        'executePipeline',
        'status',
        'scan',
        'purge',
        'history',
        'methods',
        'config',
        'state',
        'inspect',
        'examples',
        'topics',
        'manual',
        'help'
    ].map(functionName => ({
        nome: `AegisConsole.${functionName}()`,
        ativo: typeof consoleApi[functionName] === 'function',
        detalhe: typeof consoleApi[functionName] === 'function' ? 'Disponivel para uso no console.' : 'Nao exposta na API atual.'
    }));
}

function printAegisStatusLines(title, items, titleStyle = AEGIS_MANUAL_STYLES.startup) {
    console.group(`%c${title}`, titleStyle);
    items.forEach(item => {
        const style = item.ativo ? AEGIS_MANUAL_STYLES.active : AEGIS_MANUAL_STYLES.inactive;
        const status = item.ativo ? 'ATIVA' : 'INATIVA';
        printAegisStyledLine('log', style, `[${status}] ${item.nome}`, item.detalhe);
    });
    console.groupEnd();
}

function printAegisConsoleStatusReport() {
    const loadedEngine = resolveAegisConsoleEngine();

    console.group('%c[AEGIS STATUS] Painel de runtime', AEGIS_MANUAL_STYLES.startup);
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, `processId: ${loadedEngine.processId}`);
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, `currentState: ${loadedEngine.state.currentState}`);
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, `history length: ${loadedEngine.state.history.length}`);
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, `blockedMutationCount: ${loadedEngine.state.blockedMutationCount}`);
    console.groupEnd();

    printAegisStatusLines('[AEGIS STATUS] Ferramentas', getAegisToolStatuses(loadedEngine), AEGIS_MANUAL_STYLES.workflow);
    printAegisStatusLines('[AEGIS STATUS] Funcoes expostas', getAegisFunctionStatuses(), AEGIS_MANUAL_STYLES.api);
    printAegisConfigDocs();
}

function printAegisConsoleApiDocs() {
    printAegisTable('[AEGIS MANUAL] API do console', AEGIS_CONSOLE_API_DOCS.map(item => ({
        Funcao: item.nome,
        Retorno: item.retorno,
        Descricao: item.descricao
    })), AEGIS_MANUAL_STYLES.api);
}

function printAegisEngineMethodDocs() {
    printAegisTable('[AEGIS MANUAL] Metodos do engine', AEGIS_ENGINE_METHOD_DOCS.map(item => ({
        Metodo: item.nome,
        Retorno: item.retorno,
        Descricao: item.descricao
    })), AEGIS_MANUAL_STYLES.methods);
}

function printAegisWorkflowDocs() {
    printAegisTable('[AEGIS MANUAL] Etapas de start e uso', AEGIS_WORKFLOW_DOCS.map(item => ({
        Etapa: item.etapa,
        Comando: item.comando,
        Objetivo: item.objetivo,
        Detalhe: item.detalhe
    })), AEGIS_MANUAL_STYLES.workflow);
}

function printAegisConfigDocs(sectionName) {
    const loadedEngine = getLoadedAegisConsoleEngine();
    const sectionsToPrint = sectionName ? [sectionName] : Object.keys(AEGIS_CONFIG_DOCS);

    sectionsToPrint.forEach(sectionKey => {
        const entries = AEGIS_CONFIG_DOCS[sectionKey];
        if (!entries) {
            printAegisStyledLine('warn', AEGIS_MANUAL_STYLES.warning, `[AEGIS MANUAL] Secao de config desconhecida: ${sectionKey}`);
            return;
        }

        printAegisTable(`[AEGIS MANUAL] Configuracao ${sectionKey}`, entries.map(item => ({
            Chave: item.chave,
            Padrao: item.padrao,
            Atual: loadedEngine ? formatAegisManualValue(readAegisPath(loadedEngine, `config.${item.chave}`)) : '(sem instancia carregada)',
            Descricao: item.descricao
        })), AEGIS_CONFIG_SECTION_STYLES[sectionKey] || AEGIS_MANUAL_STYLES.config);
    });
}

function printAegisStateDocs() {
    const loadedEngine = getLoadedAegisConsoleEngine();

    printAegisTable('[AEGIS MANUAL] Estado e runtime', AEGIS_STATE_DOCS.map(item => ({
        Campo: item.chave,
        Valor: loadedEngine ? formatAegisManualValue(readAegisPath(loadedEngine, item.chave)) : '(sem instancia carregada)',
        Descricao: item.descricao
    })), AEGIS_MANUAL_STYLES.state);

    if (!loadedEngine) {
        printAegisStyledLine('info', AEGIS_MANUAL_STYLES.info, '[AEGIS MANUAL] Nenhuma instancia carregada. Use AegisConsole.create() ou AegisConsole.start() para preencher os valores atuais.');
        return;
    }

    console.group('%c[AEGIS MANUAL] Resumo de runtime', AEGIS_MANUAL_STYLES.stateSummary);
    console.log('processId:', loadedEngine.processId);
    console.log('currentState:', loadedEngine.state.currentState);
    console.log('history length:', loadedEngine.state.history.length);
    console.log('discoveredItems length:', loadedEngine.state.discoveredItems.length);
    console.log('mitigationLog length:', loadedEngine.state.mitigationLog.length);
    console.groupEnd();
}

function printAegisExampleDocs() {
    printAegisTable('[AEGIS MANUAL] Exemplos de uso', AEGIS_EXAMPLE_DOCS.map(item => ({
        Caso: item.caso,
        Comando: item.comando,
        Objetivo: item.objetivo
    })), AEGIS_MANUAL_STYLES.examples);
}

function printAegisInstanceDetails() {
    const loadedEngine = getLoadedAegisConsoleEngine();
    if (!loadedEngine) {
        printAegisStyledLine('info', AEGIS_MANUAL_STYLES.info, '[AEGIS MANUAL] Nenhuma instancia carregada. Execute AegisConsole.create() ou AegisConsole.start() primeiro.');
        return null;
    }

    console.group('%c[AEGIS MANUAL] Instancia carregada', AEGIS_MANUAL_STYLES.instance);
    console.dir(loadedEngine);
    console.groupEnd();
    return loadedEngine;
}

function printAegisManual(topic = 'all') {
    const normalizedTopic = String(topic || 'all').toLowerCase();

    if (!AEGIS_MANUAL_TOPICS.includes(normalizedTopic)) {
        printAegisStyledLine('warn', AEGIS_MANUAL_STYLES.warning, `[AEGIS MANUAL] Topico desconhecido: ${topic}`);
        printAegisStyledLine('info', AEGIS_MANUAL_STYLES.info, `[AEGIS MANUAL] Topicos validos: ${AEGIS_MANUAL_TOPICS.join(', ')}`);
        return;
    }

    console.group('%c[AEGIS MANUAL] Visao geral', AEGIS_MANUAL_STYLES.overview);
    console.log('Classe principal:', 'globalThis.AegisCodexEngine');
    console.log('API de console:', 'globalThis.AegisConsole');
    console.log('Topicos validos:', AEGIS_MANUAL_TOPICS.join(', '));
    console.groupEnd();

    if (normalizedTopic === 'all' || normalizedTopic === 'api') {
        printAegisConsoleApiDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'workflow') {
        printAegisWorkflowDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'methods') {
        printAegisEngineMethodDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'config') {
        printAegisConfigDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'state') {
        printAegisStateDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'examples') {
        printAegisExampleDocs();
    }
    if (normalizedTopic === 'all' || normalizedTopic === 'instance') {
        printAegisInstanceDetails();
    }
}

globalThis.AegisCodexEngine = AegisCodexEngine;
globalThis.AegisConsole = {
    create(config = {}) {
        return resolveAegisConsoleEngine(config);
    },
    getInstance() {
        return resolveAegisConsoleEngine();
    },
    async start(config = {}) {
        return resolveAegisConsoleEngine(config).start();
    },
    async executePipeline(inputData = {}, config = {}) {
        return resolveAegisConsoleEngine(config).executePipeline(inputData);
    },
    status() {
        printAegisConsoleStatusReport();
    },
    scan() {
        return resolveAegisConsoleEngine().executeFullDiscoveryScan();
    },
    purge() {
        return resolveAegisConsoleEngine().purgeDetachedNodes();
    },
    history() {
        return resolveAegisConsoleEngine().getHistory();
    },
    methods() {
        printAegisConsoleApiDocs();
        printAegisEngineMethodDocs();
    },
    config(sectionName) {
        printAegisConfigDocs(sectionName);
    },
    state() {
        printAegisStateDocs();
    },
    inspect() {
        return printAegisInstanceDetails();
    },
    examples() {
        printAegisExampleDocs();
    },
    topics() {
        printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, `[AEGIS MANUAL] Topicos disponiveis: ${AEGIS_MANUAL_TOPICS.join(', ')}`);
        return [...AEGIS_MANUAL_TOPICS];
    },
    manual(topic = 'all') {
        printAegisManual(topic);
    },
    help(topic = 'all') {
        printAegisManual(topic);
    }
};

async function autoStartAegisConsoleRuntime() {
    const engine = resolveAegisConsoleEngine();
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.startup, '[AEGIS AUTO-START] Inicializando modo de bloqueio e bootstrap do runtime...');

    try {
        await engine.start();
        engine.state.autoStartCompleted = true;
        printAegisStyledLine('log', AEGIS_MANUAL_STYLES.success, '[AEGIS AUTO-START] Modo de bloqueio ativo e runtime inicializado.');
    } catch (error) {
        engine.state.autoStartCompleted = false;
        printAegisStyledLine('error', AEGIS_MANUAL_STYLES.error, `[AEGIS AUTO-START] Falha ao iniciar o runtime: ${error.message}`);
    }

    printAegisConsoleStatusReport();
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.success, '[AEGIS CONSOLE READY] AegisCodexEngine disponivel em globalThis.AegisCodexEngine');
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.success, '[AEGIS CONSOLE READY] API rapida disponivel em globalThis.AegisConsole');
    printAegisStyledLine('log', AEGIS_MANUAL_STYLES.info, '[AEGIS CONSOLE READY] Manual detalhado: AegisConsole.manual() | AegisConsole.help("config")');
}

void autoStartAegisConsoleRuntime();
