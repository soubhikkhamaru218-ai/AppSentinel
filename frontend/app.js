/* ==========================================================================
   APPSENTINEL // CYBERPUNK INTERFACE CONTROLLER
   SPA Routing, Scroll Animations, Correlation Engine
   ========================================================================== */

let currentScanData = null;
let attachedApkData = null;

// ─── CORRELATION PRESETS ────────────────────────────────────────────────────
const PRESETS = {
    bank: {
        message: "URGENT NOTICE: Your State Bank account has been temporarily blocked due to pending KYC verification. Immediately download and install our security patch APK from https://statebank-kyc-verify.net/patch.apk to avoid permanent suspension. Submit your 6-digit OTP code to reactivate.",
        identity: "State Bank",
        url: "https://statebank-kyc-verify.net/patch.apk",
        apk: { name: "statebank_security_patch.apk", size: "18.4 MB", hash: "e3b0c44298fc1c14", packageName: "com.quicksupport.remoteaccess.device", permissions: ["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES"] }
    }
};

function getApiBase() {
    if (window.APPSENTINEL_API_URL) return window.APPSENTINEL_API_URL;
    const stored = localStorage.getItem('appsentinel_api_url');
    if (stored) return stored;
    if (window.location.protocol.startsWith('http')) {
        const port = window.location.port;
        if (port === '8088' || port === '5500' || port === '3000' || port === '5173') {
            return 'http://localhost:8000';
        }
        return window.location.origin;
    }
    return 'http://localhost:8000';
}

let API_BASE = getApiBase();

function setApiBase(url) {
    if (!url) return;
    API_BASE = url.replace(/\/+$/, '');
    localStorage.setItem('appsentinel_api_url', API_BASE);
    checkBackendHealth();
}

function configureBackendUrl() {
    const entered = window.prompt("Configure AppSentinel Backend API URL:", API_BASE);
    if (entered && entered.trim()) {
        setApiBase(entered.trim());
    }
}

// ─── DOM READY ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initScrollNav();
    initMobileMenu();
    initScrollReveal();
    initHeroAnimation();
    initDropzone();
    initHashRouting();
    initUrlPreview();
    checkBackendHealth();
});

async function checkBackendHealth() {
    const statusText = document.getElementById('hudSystemStatus');
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        if (res.ok) {
            const data = await res.json();
            const mobsfRunning = data.services?.mobsf_running;
            const geminiConfigured = data.services?.gemini_ai_configured;
            const modelName = data.services?.ai_model || 'gemini-2.5-flash';
            if (statusText) {
                statusText.innerHTML = `SYSTEM STATUS: ONLINE // FASTAPI ACTIVE (${API_BASE}) &bull; AI: ${geminiConfigured ? modelName : 'NO KEY'} &bull; ANDROGUARD: READY &bull; MOBSF: ${mobsfRunning ? 'ONLINE' : 'STANDBY'}`;
                statusText.style.color = '#00ff88';
                statusText.title = "Click to configure backend URL";
                statusText.style.cursor = "pointer";
                statusText.onclick = configureBackendUrl;
            }
        } else {
            throw new Error(`HTTP ${res.status}`);
        }
    } catch (e) {
        if (statusText) {
            statusText.innerHTML = `SYSTEM STATUS: BACKEND OFFLINE // UNREACHABLE AT ${API_BASE} &bull; CLICK TO CONFIGURE`;
            statusText.style.color = '#ff4444';
            statusText.title = "Click to configure backend URL";
            statusText.style.cursor = "pointer";
            statusText.onclick = configureBackendUrl;
        }
    }
}

// ─── 1. SCROLL NAV ─────────────────────────────────────────────────────────
function initScrollNav() {
    const nav = document.querySelector('.site-nav');
    if (!nav) return;
    window.addEventListener('scroll', () => {
        nav.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });
}

// ─── 2. MOBILE MENU ────────────────────────────────────────────────────────
function initMobileMenu() {
    const btn = document.getElementById('mobileMenuBtn');
    const links = document.getElementById('mainNavLinks');
    if (btn && links) {
        btn.addEventListener('click', () => links.classList.toggle('mobile-open'));
    }
}

// ─── 3. SMOOTH SCROLL-REVEAL SYSTEM ────────────────────────────────────────
function initScrollReveal() {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        document.querySelectorAll('.scroll-reveal').forEach(el => el.classList.add('sr-visible'));
        return;
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const delay = parseInt(entry.target.dataset.srDelay) || 0;
                setTimeout(() => entry.target.classList.add('sr-visible'), delay);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('.scroll-reveal').forEach(el => observer.observe(el));
}

// Re-observe new elements when switching views (for views not yet seen)
function reobserveScrollReveals() {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const delay = parseInt(entry.target.dataset.srDelay) || 0;
                setTimeout(() => entry.target.classList.add('sr-visible'), delay);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    // Only observe elements that haven't been revealed yet
    document.querySelectorAll('.scroll-reveal:not(.sr-visible)').forEach(el => observer.observe(el));
}

// ─── 4. VIEW SWITCHER (SPA) ────────────────────────────────────────────────
const ALL_VIEWS = ['home', 'scan-message', 'scan-url', 'scan-apk', 'pipeline', 'report', 'rules'];

function switchView(viewName) {
    ALL_VIEWS.forEach(v => {
        const el = document.getElementById(`view-${v}`);
        if (el) el.classList.remove('active-view');
    });

    const target = document.getElementById(`view-${viewName}`);
    if (target) {
        target.classList.add('active-view');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // Update nav buttons
    document.querySelectorAll('.nav-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === viewName);
    });

    // Close mobile nav
    const navLinks = document.getElementById('mainNavLinks');
    if (navLinks) navLinks.classList.remove('mobile-open');

    // Hash update (skip pipeline — transient)
    if (viewName !== 'pipeline') {
        history.replaceState(null, '', `#${viewName}`);
    }

    // Re-observe scroll reveals for newly visible content
    requestAnimationFrame(reobserveScrollReveals);
}

function scrollToAnalyzers() {
    switchView('home');
    requestAnimationFrame(() => {
        const section = document.getElementById('analyzers');
        if (section) {
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
}

function initHashRouting() {
    const hash = window.location.hash.replace('#', '');
    if (hash && ALL_VIEWS.includes(hash)) {
        switchView(hash);
    } else {
        switchView('home');
    }
    window.addEventListener('hashchange', () => {
        const h = window.location.hash.replace('#', '');
        if (ALL_VIEWS.includes(h)) switchView(h);
    });
}

// ─── 5. HERO SVG ANIMATION ─────────────────────────────────────────────────
function initHeroAnimation() {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const visual = document.querySelector('.hero-visual');
    if (!visual) return;

    let done = false;
    const obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
            if (e.isIntersecting && !done) {
                done = true;
                runHeroAnim();
            }
        });
    }, { threshold: 0.4 });
    obs.observe(visual);
}

function runHeroAnim() {
    const nodes = { msg: '.node-message', url: '.node-url', id: '.node-identity', apk: '.node-apk' };
    const paths = { msg: '.path-message', url: '.path-url', id: '.path-identity', apk: '.path-apk' };

    const sequence = [
        { sel: nodes.msg, t: 150 }, { sel: nodes.url, t: 450 },
        { sel: nodes.id, t: 750 },  { sel: nodes.apk, t: 1050 },
        { sel: paths.msg, t: 1200 }, { sel: paths.url, t: 1400 },
        { sel: paths.id, t: 1600 },  { sel: paths.apk, t: 1800 },
    ];

    sequence.forEach(({ sel, t }) => {
        setTimeout(() => {
            const el = document.querySelector(sel);
            if (el) el.classList.add('active');
        }, t);
    });

    setTimeout(() => {
        const engine = document.querySelector('.central-engine');
        const status = document.querySelector('.engine-status');
        if (engine) engine.classList.add('active');
        if (status) { status.textContent = "EVIDENCE CORRELATED // READY"; status.setAttribute('fill', '#00ff88'); }
    }, 2600);
}

// ─── 6. REAL-TIME SIGNAL RADAR ──────────────────────────────────────────────
function handleMessageInput(text, prefix) {
    const countEl = document.getElementById(`${prefix}CharCount`);
    if (countEl) countEl.textContent = `${text.length} chars`;

    const lc = text.toLowerCase();
    const check = (keywords) => keywords.some(k => lc.includes(k));

    updateBadge(`${prefix}SigUrgency`,  check(['immediately', 'urgent', 'today', 'act now', 'deadline', 'last warning', '24 hours', 'asap']), 'DETECTED', 'NOT DETECTED', 'warn');
    updateBadge(`${prefix}SigThreat`,   check(['blocked', 'suspended', 'legal action', 'penalty', 'deactivated', 'freeze', 'terminated']), 'THREAT DETECTED', 'NOT DETECTED', 'alert');
    updateBadge(`${prefix}SigOtp`,      check(['otp', 'password', 'pin', 'cvv', 'verification code', 'passcode']), 'CREDENTIAL TARGET', 'NOT DETECTED', 'alert');
    updateBadge(`${prefix}SigFinancial`, check(['payment', 'transfer', 'fee', 'refund', 'upi', 'pay', '$']), 'FINANCIAL', 'NOT DETECTED', 'warn');
    updateBadge(`${prefix}SigInstall`,  check(['apk', 'install app', 'download app', 'security patch', 'sideload']), 'APP INSTALL', 'NOT DETECTED', 'alert');
}

function updateBadge(id, active, onText, offText, sev) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = active ? `signal-tag ${sev === 'alert' ? 'active-alert' : 'active-warn'}` : 'signal-tag inactive';
    el.textContent = active ? onText : offText;
}

// ─── 7. URL PREVIEW (Live domain parse for URL scanner) ─────────────────────
function initUrlPreview() {
    const urlInput = document.getElementById('urlScanUrl');
    if (!urlInput) return;
    urlInput.addEventListener('input', () => {
        const val = urlInput.value.trim();
        if (val.length < 5) {
            ['urlSigDomain', 'urlSigProtocol', 'urlSigKeywords', 'urlSigPath'].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.className = 'signal-tag inactive'; el.textContent = '—'; }
            });
            return;
        }
        try {
            const u = new URL(val.startsWith('http') ? val : `https://${val}`);
            setUrlBadge('urlSigDomain', u.hostname, 'active-warn');
            setUrlBadge('urlSigProtocol', u.protocol === 'https:' ? 'HTTPS ✓' : 'HTTP ⚠', u.protocol === 'https:' ? 'inactive' : 'active-warn');
            const suspicious = ['verify', 'kyc', 'patch', 'reschedule', 'login', 'update', 'secure'].some(k => u.hostname.includes(k) || u.pathname.includes(k));
            updateBadge('urlSigKeywords', suspicious, 'SUSPICIOUS', 'CLEAR', 'warn');
            setUrlBadge('urlSigPath', `DEPTH: ${u.pathname.split('/').filter(Boolean).length}`, 'inactive');
        } catch (e) {
            setUrlBadge('urlSigDomain', 'INVALID URL', 'active-alert');
        }
    });
}

function setUrlBadge(id, text, cls) {
    const el = document.getElementById(id);
    if (el) { el.className = `signal-tag ${cls}`; el.textContent = text; }
}

// ─── 8. APK UPLOAD / DROPZONE ───────────────────────────────────────────────
function initDropzone() {
    const dz = document.getElementById('apkDropzone');
    if (!dz) return;
    ['dragenter', 'dragover'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add('dragover'); }));
    ['dragleave', 'drop'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove('dragover'); }));
    dz.addEventListener('drop', ev => { if (ev.dataTransfer.files.length) processApk(ev.dataTransfer.files[0]); });
}

function handleApkSelect(event) {
    if (event.target.files.length) processApk(event.target.files[0]);
}

async function processApk(file) {
    const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
    let hash = 'computing...';
    try {
        const buf = await file.slice(0, 65536).arrayBuffer();
        const h = await crypto.subtle.digest('SHA-256', buf);
        hash = Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
    } catch (e) { hash = 'unavailable'; }

    attachedApkData = {
        name: file.name, size: `${sizeMb} MB`, hash,
        packageName: `com.untrusted.${file.name.replace('.apk', '').replace(/[^a-zA-Z0-9]/g, '_')}`,
        permissions: ['READ_PHONE_STATE', 'RECEIVE_BOOT_COMPLETED', 'INTERNET', 'REQUEST_INSTALL_PACKAGES'],
        rawFile: file
    };

    const badge = document.getElementById('fileSelectedBadge');
    const nameEl = document.getElementById('selectedFileName');
    if (badge && nameEl) { nameEl.textContent = `📦 ${file.name} (${sizeMb} MB)`; badge.style.display = 'flex'; }

    setUrlBadge('apkSigName', file.name, 'active-warn');
    setUrlBadge('apkSigSize', `${sizeMb} MB`, 'inactive');
    setUrlBadge('apkSigHash', hash + '...', 'inactive');
    setUrlBadge('apkSigStatus', 'READY FOR SCAN', 'active-warn');
}

function removeSelectedApk() {
    attachedApkData = null;
    const fi = document.getElementById('apkFileInput');
    if (fi) fi.value = '';
    const badge = document.getElementById('fileSelectedBadge');
    if (badge) badge.style.display = 'none';
    ['apkSigName', 'apkSigSize', 'apkSigHash'].forEach(id => setUrlBadge(id, '—', 'inactive'));
    setUrlBadge('apkSigStatus', 'AWAITING UPLOAD', 'inactive');
}

function resetForm(formId) {
    const f = document.getElementById(formId);
    if (f) f.reset();
    // Clear signal badges
    document.querySelectorAll(`#${formId} .signal-tag`).forEach(el => { el.className = 'signal-tag inactive'; el.textContent = 'NOT DETECTED'; });
}

let lastScanParams = null;
const SCAN_REQUEST_TIMEOUT_MS = 120000;

async function fetchScanFromApi(mode, { message, identity, url, apk }) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), SCAN_REQUEST_TIMEOUT_MS);

    try {
        let res = null;
        if (mode === 'message') {
            res = await fetch(`${API_BASE}/api/scan/message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message, identity }),
                signal: controller.signal
            });
        } else if (mode === 'url') {
            res = await fetch(`${API_BASE}/api/scan/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, identity, context_message: message }),
                signal: controller.signal
            });
        } else if (mode === 'apk') {
            if (apk && apk.rawFile) {
                const fd = new FormData();
                fd.append('file', apk.rawFile);
                fd.append('identity', identity || '');
                fd.append('context_message', message || '');
                res = await fetch(`${API_BASE}/api/scan/apk`, {
                    method: 'POST',
                    body: fd,
                    signal: controller.signal
                });
            } else if (apk) {
                res = await fetch(`${API_BASE}/api/scan/full`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message,
                        identity,
                        apk_filename: apk.name,
                        apk_hash: apk.hash,
                        apk_package_name: apk.packageName,
                        apk_permissions: apk.permissions || [],
                        apk_size: apk.size
                    }),
                    signal: controller.signal
                });
            } else {
                throw new Error("No APK file or package metadata provided for analysis.");
            }
        } else {
            throw new Error(`Unsupported scan mode: '${mode}'`);
        }

        if (!res) {
            throw new Error("Scan request could not be dispatched.");
        }

        if (!res.ok) {
            let errorDetail = `HTTP ${res.status} ${res.statusText}`;
            try {
                const errData = await res.json();
                if (errData && (errData.detail || errData.message || errData.error)) {
                    errorDetail = errData.detail || errData.message || errData.error;
                }
            } catch (_) {
                try {
                    const txt = await res.text();
                    if (txt) errorDetail = txt.substring(0, 200);
                } catch (__) {}
            }
            throw new Error(`Backend error (${res.status}): ${errorDetail}`);
        }

        const data = await res.json();
        if (!data || typeof data !== 'object' || !data.scan_id) {
            throw new Error("Invalid or malformed response received from backend (missing scan_id).");
        }
        return data;
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new Error(`Scan request timed out after ${Math.round(SCAN_REQUEST_TIMEOUT_MS / 1000)} seconds. The backend did not return a completed report in time.`);
        }
        if (err.message && err.message.toLowerCase().includes('failed to fetch')) {
            throw new Error(`Cannot reach AppSentinel backend at ${API_BASE}. Please verify that the server is running.`);
        }
        throw err;
    } finally {
        clearTimeout(timeoutId);
    }
}

function normalizeScanResult(apiRes) {
    const verdictLabel = typeof apiRes.verdict === 'object' && apiRes.verdict !== null
        ? (apiRes.verdict.label || 'LOW_CONCERN')
        : (apiRes.verdict || 'LOW_CONCERN');

    const rawActions = apiRes.actions && apiRes.actions.recommended
        ? apiRes.actions.recommended
        : (Array.isArray(apiRes.actions) ? apiRes.actions : []);

    const rawAvoid = apiRes.actions && apiRes.actions.avoid
        ? apiRes.actions.avoid
        : (apiRes.ai?.avoid_actions || []);

    const rawChain = (apiRes.correlation?.evidence_chain || apiRes.evidence_chain || []).map(item => ({
        node: item.node || item.title || 'Evidence Indicator',
        desc: item.desc || item.description || '',
        rule: item.rule || '',
        severity: item.severity || 'info'
    }));

    const rawFindings = rawChain.length
        ? rawChain.map(item => ({
            finding: item.node.replace(/^MobSF:\s*/, ''),
            explanation: item.desc,
            severity: item.severity.toLowerCase(),
            evidence_source: item.rule === 'MOBSF' ? 'mobsf' : 'correlation'
        }))
        : (apiRes.correlation?.findings || []).map(f => ({
            finding: typeof f === 'string' ? f : (f.title || f.finding || f.name || 'Security Finding'),
            explanation: typeof f === 'string' ? f : (f.description || f.desc || f.detail || ''),
            severity: (typeof f === 'object' && f.severity ? f.severity : 'medium').toLowerCase(),
            evidence_source: typeof f === 'object' && f.source ? f.source : 'correlation'
        }));

    const ai = apiRes.ai || {};
    const aiLegacy = apiRes.ai_explanation || {};
    const isAiOnline = ai.status === 'completed' || Boolean(aiLegacy.ai_available);
    const mobsfFindingCount = apiRes.analyzers?.mobsf?.security_findings?.length || 0;
    const aiUnavailableSummary = /429|quota|resource_exhausted/i.test(ai.reason || '')
        ? 'Gemini quota exceeded; no AI explanation was generated.'
        : 'AI explanation unavailable; deterministic scanner results are shown.';

    const headline = aiLegacy.headline || `${verdictLabel} // Verified Threat Assessment`;
    const fallbackSummary = ai.status === 'unavailable'
        ? `${aiUnavailableSummary} ${apiRes.explanation || 'The deterministic correlation engine completed its assessment.'}${mobsfFindingCount ? ` MobSF also reported ${mobsfFindingCount} technical APK security finding${mobsfFindingCount === 1 ? '' : 's'}; review the evidence below. LOW_CONCERN is not a safety certification.` : ''}`
        : (apiRes.explanation || 'Verification complete.');
    const summary = ai.summary || aiLegacy.summary || fallbackSummary;
    const whyMatters = Array.isArray(ai.why_it_matters)
        ? ai.why_it_matters.join(' ')
        : (ai.why_it_matters || aiLegacy.why_it_matters || '');

    const precautions = ai.recommended_actions?.length ? ai.recommended_actions : (rawActions.length ? rawActions : ['Exercise standard digital caution.']);
    const avoid = ai.avoid_actions?.length ? ai.avoid_actions : (rawAvoid.length ? rawAvoid : ['Do not disclose sensitive PINs or passwords.']);

    return {
        scanId: apiRes.scan_id || apiRes.scanId || 'AS-SCAN-CORR',
        timestamp: apiRes.timestamp || new Date().toISOString(),
        verdict: verdictLabel,
        confidence: apiRes.confidence || 0.75,
        vectorCount: apiRes.input_coverage?.supplied_count || apiRes.vector_count || 1,
        findingsCount: apiRes.findings_count || rawFindings.length,
        triggeredRules: (apiRes.correlation?.triggered_rules || apiRes.triggered_rules || []).map(r => r.id || r.code || r),
        inputs: apiRes.inputs || {},
        evidenceChain: rawChain,
        explanation: summary,
        actions: precautions,
        avoidActions: avoid,
        analyzers: apiRes.analyzers || {},
        pipeline: apiRes.pipeline || [],
        aiExplanation: {
            ai_available: isAiOnline,
            ai_status: ai.status || (aiLegacy.ai_available ? 'completed' : 'unavailable'),
            ai_reason: ai.reason || '',
            headline: headline,
            summary: summary,
            why_it_matters: whyMatters,
            why_this_result: aiLegacy.why_this_result || apiRes.explanation || `Deterministically validated against security rules.`,
            confidence_explanation: `Confidence: ${Math.round((apiRes.confidence || 0.75) * 100)}% based on verified indicators.`,
            what_we_found: rawFindings.length ? rawFindings : rawChain.map(c => ({
                finding: c.node,
                explanation: c.desc,
                severity: c.severity,
                evidence_source: 'correlation'
            })),
            technical_to_plain_language: ai.technical_to_plain_language || [],
            precautions: precautions,
            what_not_to_do: avoid,
            limitations: ai.limitations || apiRes.limitations || []
        },
        schema: apiRes.schema_output || apiRes
    };
}

function handleScanSubmit(event, mode) {
    if (event) event.preventDefault();

    let message = '', identity = '', url = '', apk = null;

    if (mode === 'message') {
        message = document.getElementById('msgScanMessage').value.trim();
        identity = document.getElementById('msgScanIdentity').value.trim();
        if (!message) return alert('Please paste the suspicious message.');
    } else if (mode === 'url') {
        url = document.getElementById('urlScanUrl').value.trim();
        identity = document.getElementById('urlScanIdentity').value.trim();
        message = document.getElementById('urlScanContext')?.value.trim() || '';
        if (!url) return alert('Please enter the suspicious URL.');
    } else if (mode === 'apk') {
        apk = attachedApkData;
        identity = document.getElementById('apkScanIdentity').value.trim();
        message = document.getElementById('apkScanContext')?.value.trim() || '';
        if (!apk) return alert('Please upload an APK file.');
    }

    lastScanParams = { mode, data: { message, identity, url, apk } };

    // Reset pipeline error card if previously displayed
    const errCard = document.getElementById('pipelineErrorCard');
    if (errCard) errCard.style.display = 'none';

    // Trigger API and render only request-level progress until the backend
    // returns authoritative analyzer statuses.
    const apiPromise = fetchScanFromApi(mode, { message, identity, url, apk });

    renderPipelineSteps([{ label: 'BACKEND ANALYSIS', status: 'running', reason: 'Request submitted to AppSentinel backend' }]);
    switchView('pipeline');

    const logEl = document.getElementById('pipelineLogOutput');
    const timerEl = document.getElementById('pipelineTimer');
    logEl.innerHTML = `<span>[REQUEST] Submitted ${escapeHtml(mode.toUpperCase())} scan to backend. Waiting for verified analyzer statuses...</span><br>`;
    const start = performance.now();
    const timerInterval = setInterval(() => {
        timerEl.textContent = `T+ ${((performance.now() - start) / 1000).toFixed(2)}s`;
    }, 100);

    (async () => {
        try {
            const apiData = await apiPromise;
            clearInterval(timerInterval);

            renderBackendPipeline(apiData.pipeline || []);
            logEl.innerHTML += `<span style="color:#00ff88; font-weight:bold;">[ANALYSIS COMPLETE] Backend response received.</span><br>`;
            logEl.scrollTop = logEl.scrollHeight;

            const result = normalizeScanResult(apiData);
            result.isDemo = false;
            currentScanData = result;

            setTimeout(() => {
                renderReport(result);
                switchView('report');
            }, 400);

        } catch (err) {
            clearInterval(timerInterval);

            renderPipelineSteps([{ label: 'BACKEND ANALYSIS', status: 'failed', reason: err.message }]);
            logEl.innerHTML += `<span style="color:var(--destructive); font-weight:bold;">[SCAN FAILED] ${escapeHtml(err.message)}</span><br>`;
            logEl.scrollTop = logEl.scrollHeight;

            if (errCard) {
                const titleEl = document.getElementById('pipelineErrorTitle');
                const msgEl = document.getElementById('pipelineErrorMessage');
                if (titleEl) titleEl.textContent = `Scan Execution Failed (${mode.toUpperCase()})`;
                if (msgEl) msgEl.textContent = err.message;
                errCard.style.display = 'block';
            }
        }
    })();
}

function retryLastScan() {
    if (!lastScanParams) return;
    const errCard = document.getElementById('pipelineErrorCard');
    if (errCard) errCard.style.display = 'none';
    handleScanSubmit(null, lastScanParams.mode);
}

function editLastScan() {
    if (!lastScanParams) return;
    const errCard = document.getElementById('pipelineErrorCard');
    if (errCard) errCard.style.display = 'none';
    switchView(`scan-${lastScanParams.mode}`);
}

function runExplicitDemoSimulation() {
    if (!lastScanParams) return;
    const errCard = document.getElementById('pipelineErrorCard');
    if (errCard) errCard.style.display = 'none';

    const simulated = runCorrelation(lastScanParams.data);
    simulated.isDemo = true;
    currentScanData = simulated;
    renderReport(simulated);
    switchView('report');
}

function renderPipelineSteps(steps) {
    const container = document.getElementById('pipelineStepsContainer');
    if (!container) return;
    container.innerHTML = steps.map((s, i) => `
        <div class="pipe-step ${pipelineClassForStatus(s.status || 'pending')}" id="pipeStep${i}">
            <div style="font-weight: 700; margin-bottom: 0.25rem;">PHASE 0${i + 1}</div>
            <div>${escapeHtml(s.label || s.name || 'ANALYZER')}</div>
            ${s.reason ? `<div style="font-size:0.75rem; color:var(--muted-foreground); margin-top:0.25rem;">${escapeHtml(s.reason)}</div>` : ''}
        </div>
    `).join('');
}

function renderBackendPipeline(pipeline) {
    const steps = pipeline.length
        ? pipeline.map(step => ({ label: step.name, status: step.status, reason: step.reason || '' }))
        : [{ label: 'BACKEND ANALYSIS', status: 'completed', reason: 'No detailed pipeline returned' }];
    renderPipelineSteps(steps);

    const logEl = document.getElementById('pipelineLogOutput');
    if (!logEl) return;
    steps.forEach(step => {
        const status = String(step.status || 'unknown').toUpperCase();
        const reason = step.reason ? ` // ${escapeHtml(step.reason)}` : '';
        logEl.innerHTML += `<span>[${escapeHtml(step.label)}] ${escapeHtml(status)}${reason}</span><br>`;
    });
    logEl.scrollTop = logEl.scrollHeight;
}

function pipelineClassForStatus(status) {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'completed') return 'completed';
    if (normalized === 'failed' || normalized === 'timed_out') return 'failed';
    if (normalized === 'running') return 'running';
    return 'pending';
}

// ─── 10. CORRELATION ENGINE (R1–R7) ────────────────────────────────────────
function runCorrelation({ message, identity, url, apk }) {
    const lm = (message || '').toLowerCase();
    const scanId = `AS-${Math.floor(10000 + Math.random() * 90000)}-CORR`;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    const hasUrgency = ['immediately', 'urgent', 'today', 'act now', 'deadline', '24 hours'].some(k => lm.includes(k));
    const hasThreat = ['blocked', 'suspended', 'legal action', 'penalty', 'deactivated'].some(k => lm.includes(k));
    const hasOtp = ['otp', 'password', 'pin', 'cvv', 'verification code'].some(k => lm.includes(k));
    const hasInstall = ['apk', 'install', 'download app', 'security patch'].some(k => lm.includes(k));
    const hasUrl = Boolean(url && url.length > 5);
    const hasApk = Boolean(apk);
    const domain = hasUrl ? extractDomain(url) : null;

    let rules = [], chain = [], findings = 0, verdict = 'LOW_CONCERN', conf = 0.72, explanation = '', actions = [];

    if (hasInstall && hasApk) { rules.push('R1'); findings += 2; chain.push({ node: 'APK Installation Coercion', desc: `Message instructs APK install. File '${apk.name}' has dangerous permissions.`, severity: 'high', rule: 'R1' }); }
    if (identity && hasUrl) {
        const match = domain.toLowerCase().includes(identity.toLowerCase().replace(/[^a-z0-9]/g, ''));
        if (!match) { rules.push('R2'); findings += 2; chain.push({ node: 'Infrastructure Mismatch', desc: `Claimed '${identity}' but host is '${domain}'.`, severity: 'high', rule: 'R2' }); }
    }
    if (identity && hasApk) {
        if (!apk.packageName.toLowerCase().includes(identity.toLowerCase().replace(/[^a-z0-9]/g, ''))) { rules.push('R3'); findings += 2; chain.push({ node: 'Package Mismatch', desc: `Claims '${identity}' but APK is '${apk.packageName}'.`, severity: 'high', rule: 'R3' }); }
    }
    if (hasOtp && (hasUrgency || hasThreat)) { rules.push('R4'); findings += 2; chain.push({ node: 'Social Engineering', desc: 'OTP/credential request with urgency/threat language.', severity: 'high', rule: 'R4' }); }
    if (hasUrl && domain && ['verify', 'kyc', 'patch', 'reschedule', 'portal', 'login'].some(k => domain.includes(k))) { rules.push('R5'); findings += 1; chain.push({ node: 'Suspicious Domain', desc: `'${domain}' uses deceptive keywords.`, severity: 'medium', rule: 'R5' }); }
    if (!hasUrl && !hasApk && !hasOtp && !hasInstall && !hasThreat) { rules.push('R7'); verdict = 'INSUFFICIENT_EVIDENCE'; conf = 0.50; chain.push({ node: 'Incomplete Evidence', desc: 'No verifiable technical markers found.', severity: 'info', rule: 'R7' }); }

    if (rules.includes('R1') && (rules.includes('R2') || rules.includes('R3') || rules.includes('R4'))) {
        verdict = 'HIGH_RISK'; conf = 0.92;
        explanation = `Multi-vector attack: impersonation of '${identity || 'a brand'}' + sideload coercion + credential harvesting.`;
        actions = ['DO NOT click the link or install the APK.', 'Delete the APK from your device immediately.', 'Never provide OTPs or passwords via third-party forms.', `Contact '${identity || 'the service'}' directly via their official app or website.`];
    } else if (rules.includes('R2') || rules.includes('R4') || rules.includes('R5')) {
        verdict = 'SUSPICIOUS'; conf = 0.84;
        explanation = `Strong phishing/social engineering signals. Infrastructure does not match claimed identity.`;
        actions = ['Avoid clicking the link.', 'Verify via official channels.', 'Report the sender as phishing.'];
    } else if (verdict === 'INSUFFICIENT_EVIDENCE') {
        explanation = 'Minimal technical indicators detected. Absence of threat signals ≠ safety.';
        actions = ['Confirm identity through another channel.', 'Do not disclose credentials.', 'Provide more evidence for a stronger verdict.'];
    } else {
        explanation = 'No coercive signals or unauthorized distribution detected.';
        actions = ['Proceed via official channels.', 'Keep security protections enabled.'];
    }

    let vc = 0;
    if (message) vc++; if (identity) vc++; if (hasUrl) vc++; if (hasApk) vc++;

    const aiExplanation = {
        ai_available: false,
        headline: verdict === 'HIGH_RISK'
            ? 'Critical scam indicators detected across multiple evidence vectors'
            : verdict === 'SUSPICIOUS'
            ? 'Suspicious inconsistencies detected between claimed identity and destination'
            : verdict === 'INSUFFICIENT_EVIDENCE'
            ? 'Insufficient technical evidence to verify safety'
            : 'No immediate scam signals detected in the provided evidence',
        summary: explanation,
        what_we_found: chain.map(c => ({
            finding: c.node,
            explanation: c.desc,
            severity: c.severity || 'medium',
            evidence_source: 'correlation'
        })),
        why_it_matters: verdict === 'HIGH_RISK'
            ? 'The combination of urgency, domain mismatch, or unofficial APK distribution is characteristic of targeted financial extortion and credential theft.'
            : 'These indicators deviate from safe practices and warrant extreme caution before proceeding.',
        why_this_result: `AppSentinel evaluated the cross-vector evidence against deterministic rules (${rules.join(', ') || 'R7'}).`,
        precautions: actions,
        what_not_to_do: [
            'Do NOT enter OTPs, PINs, or passwords on unverified sites.',
            'Do NOT install APK packages received via SMS, chat, or suspicious links.',
            'Do NOT forward verification codes to anyone claiming to be support.'
        ],
        confidence_explanation: `Assessment confidence is ${(conf * 100).toFixed(0)}% based on ${vc || 1} available evidence vectors.`,
        limitations: [
            'Static assessment evaluates signals known at scan time.',
            'Absence of threat indicators does NOT prove that an app or URL is safe.',
            'Automated scanners cannot verify sender identity beyond technical consistency.'
        ]
    };

    return {
        scanId, timestamp, verdict, confidence: conf, vectorCount: vc || 1, triggeredRules: rules,
        findingsCount: findings, inputs: { message, identity, url, apk },
        evidenceChain: chain, explanation, actions,
        aiExplanation,
        schema: {
            scan_id: scanId,
            timestamp,
            verdict: verdict.toLowerCase(),
            confidence: conf,
            triggered_rules: rules,
            evidence: chain,
            ai_explanation: aiExplanation,
            limitations: ['Static analysis cannot guarantee safety.']
        }
    };
}

function renderReport(d) {
    if (!d) return;

    // Distinguish explicit demo mode simulation from real verified scans
    const demoBanner = document.getElementById('demoModeBanner');
    if (demoBanner) {
        demoBanner.style.display = d.isDemo ? 'flex' : 'none';
    }

    setText('reportScanId', d.isDemo ? `${d.scanId} [SIMULATION-DEMO]` : d.scanId);
    setText('reportScanTitle', `Verification Report // ${d.inputs.identity || 'Unknown Claim'}`);

    const vc = document.getElementById('reportVerdictCard');
    const vb = document.getElementById('reportVerdictBadge');
    const vh = document.getElementById('reportVerdictHeading');
    const vs = document.getElementById('reportVerdictSubtitle');
    if (vc) vc.className = `verdict-master-card verdict-${d.verdict.toLowerCase().replace(/_/g, '-')}`;
    if (vb) vb.textContent = d.isDemo ? `${d.verdict} // SIMULATION` : d.verdict;

    const headings = {
        HIGH_RISK: 'CRITICAL THREAT VECTORS CORRELATED',
        SUSPICIOUS: 'DECEPTIVE SIGNALS DETECTED',
        INSUFFICIENT_EVIDENCE: 'INSUFFICIENT EVIDENCE // UNCERTAINTY',
        LOW_CONCERN: 'LOW CONCERN // NO COERCION SIGNALS'
    };
    const subs = {
        HIGH_RISK: 'Claimed identity contradicts infrastructure and package signatures.',
        SUSPICIOUS: 'Infrastructure mismatch and social engineering patterns found.',
        INSUFFICIENT_EVIDENCE: 'Not enough technical evidence. Absence of threat does not equal safety.',
        LOW_CONCERN: 'No unauthorized distribution or credential extortion signals detected.'
    };
    if (vh) vh.textContent = d.isDemo ? `${headings[d.verdict] || d.verdict} (OFFLINE SIMULATION)` : (headings[d.verdict] || '');
    if (vs) vs.textContent = d.isDemo ? `[SIMULATED - OFFLINE DEMO] ${subs[d.verdict] || ''}` : (subs[d.verdict] || '');

    setText('metricConfidence', `${Math.round(d.confidence * 100)}%`);
    setText('metricCoverage', `${d.vectorCount} / 4`);
    setText('metricRules', `${d.triggeredRules.length} RULES`);
    setText('metricFindings', `${d.findingsCount || (d.aiExplanation?.what_we_found?.length || 0)} SIGS`);

    // ─── AI EXPLANATION RENDERING ───
    const ai = d.aiExplanation;
    const aiBadge = document.getElementById('aiBadge');
    const aiTitle = document.querySelector('.ai-intel-title');
    const aiSubtitle = document.querySelector('.ai-intel-subtitle');
    if (aiBadge) {
        if (d.isDemo) {
            aiBadge.textContent = 'AI EXPLANATION // SIMULATION ENGINE (OFFLINE)';
            aiBadge.style.borderColor = 'var(--warning)';
            aiBadge.style.color = 'var(--warning)';
        } else if (ai && ai.ai_available) {
            aiBadge.textContent = 'AI EXPLANATION // GEMINI (REAL-TIME)';
            aiBadge.style.borderColor = 'var(--accent)';
            aiBadge.style.color = 'var(--accent)';
        } else {
            const quotaExceeded = /429|quota|resource_exhausted/i.test(ai?.ai_reason || '');
            aiBadge.textContent = quotaExceeded ? 'GEMINI UNAVAILABLE // QUOTA EXCEEDED' : 'GEMINI UNAVAILABLE // DETERMINISTIC FALLBACK';
            aiBadge.style.borderColor = 'var(--warning)';
            aiBadge.style.color = 'var(--warning)';
        }
    }
    if (aiTitle) aiTitle.textContent = ai?.ai_available
        ? 'REAL-TIME AI INTELLIGENCE EXPLANATION'
        : 'DETERMINISTIC ANALYSIS // AI EXPLANATION UNAVAILABLE';
    if (aiSubtitle) aiSubtitle.textContent = ai?.ai_available
        ? 'Synthesized from available scanner evidence; the deterministic correlation engine sets the verdict.'
        : 'Scanner evidence and rule-engine results are shown below; no AI-generated explanation was returned.';

    // ─── MULTI-VECTOR TELEMETRY STRIP ───
    const analyzers = d.analyzers || {};
    const pipeline = d.pipeline || [];

    function updateChip(chipId, statusId, isActive, statusText, isWarning, isDanger) {
        const chip = document.getElementById(chipId);
        const st = document.getElementById(statusId);
        if (!chip || !st) return;
        chip.className = 'telemetry-chip' + (isDanger ? ' chip-danger' : (isWarning ? ' chip-warning' : (isActive ? ' chip-active' : '')));
        st.textContent = statusText;
    }

    const hasUrl = Boolean(d.inputs?.url || analyzers.url);
    const hasMsg = Boolean(d.inputs?.message || analyzers.message);
    const hasApk = Boolean(d.inputs?.apk || analyzers.androguard || analyzers.mobsf);

    const urlStatus = (analyzers.url?.status || (hasUrl ? 'completed' : 'skipped')).toUpperCase();
    const msgStatus = (analyzers.message?.status || (hasMsg ? 'completed' : 'skipped')).toUpperCase();
    const androStatus = (analyzers.androguard?.status || (hasApk ? 'completed' : 'skipped')).toUpperCase();
    const mobsfStatus = (analyzers.mobsf?.status || (hasApk ? 'unknown' : 'skipped')).toUpperCase();

    updateChip('chipUrlScanner', 'chipUrlStatus', hasUrl, urlStatus, urlStatus === 'SUSPICIOUS', urlStatus === 'FAILED');
    updateChip('chipMsgScanner', 'chipMsgStatus', hasMsg, msgStatus, false, msgStatus === 'FAILED');
    updateChip('chipAndroguard', 'chipAndroStatus', hasApk, androStatus === 'COMPLETED' ? 'ACTIVE // ANDROGUARD PARSER' : androStatus, false, androStatus === 'FAILED');
    updateChip(
        'chipMobSF',
        'chipMobsfStatus',
        hasApk && mobsfStatus !== 'SKIPPED',
        mobsfStatus === 'UNAVAILABLE' ? 'OFFLINE // STANDBY' : mobsfStatus,
        ['UNAVAILABLE', 'NOT_CONFIGURED', 'TIMED_OUT', 'UNKNOWN'].includes(mobsfStatus),
        mobsfStatus === 'FAILED'
    );

    setText('aiHeadline', ai?.headline || d.explanation || 'Verification Complete');
    setText('aiSummary', ai?.summary || d.explanation || 'No summary available.');
    const verdictRationale = ai?.ai_available
        ? (ai.why_this_result || 'The deterministic engine correlated the available evidence.')
        : `No R1-R7 scam/coercion rules fired. MobSF reported ${(d.analyzers?.mobsf?.security_findings || []).length} technical APK finding(s); LOW_CONCERN does not certify the APK as safe.`;
    setText('aiWhyReason', `Verdict Rationale: ${verdictRationale}`);
    setText('aiConfidenceNote', ai?.ai_available
        ? `Certainty Context: ${ai.confidence_explanation}`
        : `Deterministic engine confidence: ${Math.round(d.confidence * 100)}%. ${ai?.ai_reason && /429|quota|resource_exhausted/i.test(ai.ai_reason) ? 'Gemini quota exceeded.' : 'AI explanation unavailable.'}`);

    // ─── JARGON DECODER (PLAIN-LANGUAGE EXPLANATIONS) ───
    const jargonSec = document.getElementById('aiJargonSection');
    const jargonGrid = document.getElementById('aiJargonGrid');
    const jargons = ai?.technical_to_plain_language || [];

    if (jargonSec && jargonGrid) {
        if (jargons.length > 0) {
            jargonSec.style.display = 'block';
            jargonGrid.innerHTML = jargons.map(j => `
                <div class="ai-jargon-card">
                    <div class="ai-jargon-term">🔍 ${escapeHtml(j.technical_term || j.term)}</div>
                    <p class="ai-jargon-meaning">${escapeHtml(j.plain_language || j.meaning || j.explanation)}</p>
                </div>
            `).join('');
        } else {
            jargonSec.style.display = 'none';
        }
    }

    // ─── FINDINGS GRID ───
    const findingsGrid = document.getElementById('aiFindingsGrid');
    const findingsCountEl = document.getElementById('aiFindingsCount');
    const rawFindings = ai?.what_we_found || [];

    if (findingsCountEl) {
        findingsCountEl.textContent = `${rawFindings.length} FINDING${rawFindings.length === 1 ? '' : 'S'}`;
    }

    if (findingsGrid) {
        if (rawFindings.length === 0) {
            findingsGrid.innerHTML = `
                <div class="ai-finding-card severity-info" style="grid-column: 1 / -1;">
                    <div class="ai-finding-header">
                        <span class="ai-finding-title">No Specific Anomalies Flagged</span>
                        <span class="ai-severity-badge severity-info">INFO</span>
                    </div>
                    <p class="ai-finding-desc">No dangerous permissions, credential prompts, or known malicious hashes were isolated in the provided data.</p>
                    <div class="ai-finding-footer">
                        <span class="ai-finding-source">SOURCE: APPSENTINEL ENGINE</span>
                    </div>
                </div>
            `;
        } else {
            findingsGrid.innerHTML = rawFindings.map(f => {
                const sev = (f.severity || 'info').toLowerCase();
                const source = (f.evidence_source || 'ANALYZER').toUpperCase().replace(/_/g, ' ');
                return `
                    <div class="ai-finding-card severity-${sev}">
                        <div class="ai-finding-header">
                            <span class="ai-finding-title">${escapeHtml(f.finding)}</span>
                            <span class="ai-severity-badge severity-${sev}">${sev.toUpperCase()}</span>
                        </div>
                        <p class="ai-finding-desc">${escapeHtml(f.explanation)}</p>
                        <div class="ai-finding-footer">
                            <span class="ai-finding-source">SOURCE: ${escapeHtml(source)}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // ─── WHAT THIS MEANS ───
    setText('aiMattersText', ai?.why_it_matters || (d.verdict === 'HIGH_RISK'
        ? 'These findings strongly indicate an attempt to deceive you into downloading unauthorized software or revealing private financial credentials.'
        : 'Carefully verify the organization through official bookmarks or telephone directories before taking any action.'));

    // ─── WHAT SHOULD I DO ───
    const actEl = document.getElementById('reportActionsList');
    const safeActions = ai?.precautions?.length ? ai.precautions : d.actions;
    if (actEl) {
        actEl.innerHTML = safeActions.map(a => `
            <div class="action-check-item">
                <span class="action-check-icon">✓</span>
                <span>${escapeHtml(a)}</span>
            </div>
        `).join('');
    }

    // ─── WHAT SHOULD I AVOID ───
    const avoidEl = document.getElementById('aiAvoidList');
    const avoidItems = ai?.what_not_to_do?.length ? ai.what_not_to_do : [
        'Do NOT share one-time passwords (OTP) or authentication codes with callers or chat agents.',
        'Do NOT install APK application files sent via WhatsApp, Telegram, or SMS.',
        'Do NOT provide debit card numbers, PINs, or net banking passwords on unverified sites.'
    ];
    if (avoidEl) {
        avoidEl.innerHTML = avoidItems.map(item => `
            <div class="ai-avoid-item">
                <span class="ai-avoid-icon">⚠</span>
                <span>${escapeHtml(item)}</span>
            </div>
        `).join('');
    }

    // ─── EVIDENCE CHAIN (deterministic) ───
    const chainEl = document.getElementById('reportEvidenceChain');
    if (chainEl) {
        chainEl.innerHTML = (d.evidenceChain || []).map((item, i) => `
            <div class="chain-step-node">
                <div style="font-family: var(--font-heading); font-size: 0.95rem; color: #fff; margin-bottom: 0.3rem;">[NODE 0${i + 1}] ${escapeHtml(item.node)}</div>
                <div style="font-size: 0.85rem; color: var(--foreground); line-height: 1.5;">${escapeHtml(item.desc)}</div>
            </div>
        `).join('');
    }

    // ─── LIMITATIONS ───
    const limEl = document.getElementById('aiLimitationsList');
    const limitations = ai?.limitations?.length ? ai.limitations : [
        'Static analysis evaluates evidence at scan time and cannot detect dynamic payloads loaded post-install.',
        'Absence of threat signals does not guarantee absolute safety.',
        'Always verify unknown requests directly through verified official channels.'
    ];
    if (limEl) {
        limEl.innerHTML = limitations.map(lim => `<li>${escapeHtml(lim)}</li>`).join('');
    }

    // ─── TECHNICAL EVIDENCE DRAWER ───
    const schemaEl = document.getElementById('rawSchemaDisplay');
    if (schemaEl) schemaEl.textContent = JSON.stringify(d.schema, null, 2);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function setText(id, text) { const el = document.getElementById(id); if (el) el.textContent = text; }

function toggleTechDrawer() {
    const c = document.getElementById('techDrawerContent');
    const icon = document.getElementById('drawerToggleIcon');
    if (c) { c.classList.toggle('open'); icon.textContent = c.classList.contains('open') ? '▲ COLLAPSE' : '▼ EXPAND'; }
}

function exportReportJson() {
    if (!currentScanData) return;
    const exportData = {
        ...(currentScanData.schema || currentScanData),
        simulated_offline_demo: Boolean(currentScanData.isDemo),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${currentScanData.scanId}${currentScanData.isDemo ? '-SIMULATED-DEMO' : ''}.json`;
    a.click(); URL.revokeObjectURL(a.href);
}

function copyReportSummary() {
    if (!currentScanData) return;
    const d = currentScanData;
    const ai = d.aiExplanation;
    const headline = ai?.headline || d.explanation;
    const summary = ai?.summary || d.explanation;
    const actions = (ai?.precautions || d.actions).map(a => `- ${a}`).join('\n');
    const avoid = (ai?.what_not_to_do || []).map(a => `! ${a}`).join('\n');
    const txt = `APPSENTINEL REPORT\nID: ${d.scanId}\nVERDICT: ${d.verdict} (${Math.round(d.confidence * 100)}%)\nHEADLINE: ${headline}\nSUMMARY: ${summary}\n\nACTIONS TO TAKE:\n${actions}\n\nACTIONS TO AVOID:\n${avoid}`;
    navigator.clipboard.writeText(txt).then(() => alert('Copied to clipboard!'));
}

// ─── 12. RULE SIMULATOR ────────────────────────────────────────────────────
const simState = { msg: true, url: true, apk: true, otp: true };

function toggleSimSignal(sig) {
    simState[sig] = !simState[sig];
    const btn = document.getElementById(`simToggle${sig.charAt(0).toUpperCase() + sig.slice(1)}`);
    if (btn) btn.classList.toggle('active', simState[sig]);

    let triggered = [];
    if (simState.msg && simState.apk) triggered.push('R1');
    if (simState.url) triggered.push('R2');
    if (simState.apk) triggered.push('R3');
    if (simState.msg && simState.otp) triggered.push('R4');

    let verdict = 'LOW_CONCERN';
    if (triggered.includes('R1') && (triggered.includes('R2') || triggered.includes('R4'))) verdict = 'HIGH_RISK';
    else if (triggered.includes('R2') || triggered.includes('R4')) verdict = 'SUSPICIOUS';
    else if (triggered.length === 0) { verdict = 'INSUFFICIENT_EVIDENCE'; triggered.push('R7'); }

    const badge = document.getElementById('simVerdictBadge');
    if (badge) { badge.textContent = verdict; badge.className = `verdict-badge verdict-${verdict.toLowerCase().replace(/_/g, '-')}`; }
    setText('simTriggeredRules', `TRIGGERED: ${triggered.join(', ')}`);
}

// ─── UTILS ──────────────────────────────────────────────────────────────────
function extractDomain(u) {
    try { return new URL(u.startsWith('http') ? u : `https://${u}`).hostname; }
    catch { return u || ''; }
}
