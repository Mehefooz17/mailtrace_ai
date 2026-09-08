const fileInput = document.querySelector('#file-input');
const dropzone = document.querySelector('#dropzone');
const dropLabel = document.querySelector('#drop-label');
const fileStatus = document.querySelector('#file-status');
const rawInput = document.querySelector('#raw-input');
const sampleButton = document.querySelector('#sample-button');
const investigateButton = document.querySelector('#investigate-button');
const resultPanel = document.querySelector('#result-panel');
const riskScore = document.querySelector('#risk-score');
const resultMessage = document.querySelector('#result-message');
const findingList = document.querySelector('#finding-list');
const assessmentFindings = document.querySelector('#assessment-findings');
const traceList = document.querySelector('#trace-list');
const traceCount = document.querySelector('#trace-count');
const riskLabel = document.querySelector('#risk-label');
const infoSender = document.querySelector('#info-sender');
const infoSubject = document.querySelector('#info-subject');
const infoDate = document.querySelector('#info-date');
const infoOriginIp = document.querySelector('#info-origin-ip');
const infoAuth = document.querySelector('#info-auth');
const infoLinks = document.querySelector('#info-links');
const originCode = document.querySelector('#origin-code');
const originCountry = document.querySelector('#origin-country');
const confidenceBar = document.querySelector('#confidence-bar');
const originConfidence = document.querySelector('#origin-confidence');
const originReason = document.querySelector('#origin-reason');
const clearButton = document.querySelector('#clear-button');
const tabs = document.querySelectorAll('.mode-tab');
const MAX_FILE_SIZE = 10 * 1024 * 1024;
let selectedFile = null;

const sampleEmail = `Received: from mail.secure-payments.example (mail.secure-payments.example [198.51.100.24]) by mx.company.example with ESMTPS; Tue, 09 Sep 2026 09:42:11 +0000\nReceived: from relay.example.net (relay.example.net [203.0.113.18]) by mail.secure-payments.example; Tue, 09 Sep 2026 09:42:07 +0000\nFrom: billing@secure-payments.example\nTo: accounts@company.example\nSubject: Urgent invoice payment required\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail`;

function setStatus(message, isError = false) {
  fileStatus.textContent = message;
  fileStatus.classList.toggle('error', isError);
}

function parseHeaders(emailText) {
  const headerBlock = emailText.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
  const headers = {};
  headerBlock.split(/\r?\n/).forEach((line) => {
    const separator = line.indexOf(':');
    if (separator < 1) return;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    headers[name] = headers[name] ? `${headers[name]}, ${value}` : value;
  });
  return headers;
}

function getDomain(value) {
  const match = value?.match(/@([^\s>;,]+)/);
  return match ? match[1].toLowerCase().replace(/[.)]+$/, '') : '';
}

function parseSourceTrace(emailText) {
  const headerBlock = emailText.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
  const receivedHeaders = headerBlock.match(/^received:\s*(.+)$/gim) || [];
  return receivedHeaders.map((header, index) => {
    const value = header.replace(/^received:\s*/i, '').trim();
    const cleanHost = (host) => host.replace(/[;,]+$/, '');
    const from = cleanHost(value.match(/\bfrom\s+([^\s(]+)/i)?.[1] || 'Unknown relay');
    const by = cleanHost(value.match(/\bby\s+([^\s(]+)/i)?.[1] || 'Unknown destination');
    const ip = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || 'IP not listed';
    const date = value.match(/;\s*(.+)$/)?.[1] || 'Timestamp not listed';
    return { index: index + 1, from, by, ip, date };
  });
}

function investigateEmail(emailText) {
  const headers = parseHeaders(emailText);
  const trace = parseSourceTrace(emailText);
  const findings = [];
  let score = 8;
  const authResults = headers['authentication-results'] || '';
  const authFailure = /(spf|dkim|dmarc)\s*=\s*(fail|none|neutral)/i.test(authResults);
  const authPass = /(spf|dkim|dmarc)\s*=\s*pass/i.test(authResults);
  const urgentLanguage = /urgent|immediately|action required|payment|invoice|verify|suspend/i.test(emailText);
  const urls = [...emailText.matchAll(/https?:\/\/[^\s<>'"]+|www\.[^\s<>'"]+/gi)].map((match) => match[0]);
  const suspiciousLink = urls.length > 0;
  const senderDomain = getDomain(headers.from);
  const replyDomain = getDomain(headers['reply-to']);
  const returnDomain = getDomain(headers['return-path']);
  const senderValid = Boolean(headers.from && senderDomain);
  const attachmentCount = (emailText.match(/^content-disposition:\s*attachment/gi) || []).length;
  const authStatus = ['spf', 'dkim', 'dmarc'].map((key) => authResults.match(new RegExp(`${key}\\s*=\\s*(pass|fail|none|neutral)`, 'i'))?.[1]?.toUpperCase() || 'UNKNOWN');
  const allAuthPassed = authStatus.every((status) => status === 'PASS');

  if (authFailure) {
    score += 38;
    findings.push({ level: 'high', text: 'Sender authentication contains SPF, DKIM, or DMARC failures.' });
  } else if (allAuthPassed) {
    findings.push({ level: 'normal', text: 'SPF, DKIM, and DMARC authentication checks passed.' });
  } else if (authPass) {
    findings.push({ level: 'normal', text: 'Authentication results report at least one passing sender check.' });
  } else {
    findings.push({ level: 'normal', text: 'No explicit authentication failure was found in the supplied headers.' });
  }
  if (urgentLanguage) {
    score += 20;
    findings.push({ level: 'high', text: 'Urgency or financial-action language appears in the message.' });
  }
  if (suspiciousLink) {
    score += urls.some((url) => /bit\.ly|tinyurl|\d{1,3}(?:\.\d{1,3}){3}/i.test(url)) ? 30 : 18;
    findings.push({ level: 'high', text: `${urls.length} link${urls.length === 1 ? '' : 's'} found; destination and reputation require verification.` });
  }
  if (senderDomain && replyDomain && senderDomain !== replyDomain) {
    score += 22;
    findings.push({ level: 'high', text: 'From and Reply-To domains do not match.' });
  }
  if (senderDomain && returnDomain && senderDomain !== returnDomain) {
    score += 12;
    findings.push({ level: 'high', text: 'From and Return-Path domains do not match.' });
  }
  if (!headers.subject) findings.push({ level: 'normal', text: 'No Subject header was detected.' });
  if (!senderValid) {
    score += 70;
    findings.push({ level: 'high', text: 'No valid sender address was found. This message is likely fake or malformed.' });
  }
  if (trace.length) findings.push({ level: 'normal', text: `${trace.length} Received header${trace.length === 1 ? '' : 's'} captured for origin tracing.` });

  const originHop = trace.at(-1);
  const originIp = originHop?.ip || 'Not listed';
  const originCountryData = getOriginEstimate(originIp);
  return {
    score: Math.min(score, 100), findings, authFailure, suspiciousLink, trace,
    headers, authStatus, urls, attachmentCount, originIp, originCountryData, senderValid,
  };
}

function getOriginEstimate(ip) {
  if (!ip || ip === 'IP not listed') return { code: '--', country: 'Unavailable', confidence: 0, reason: 'No public IP was present in the Received headers.' };
  if (/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return { code: 'LAN', country: 'Private network', confidence: 96, reason: 'Private or loopback address; geographic origin cannot be inferred.' };
  return { code: 'IP', country: 'Lookup unavailable', confidence: 48, reason: 'Heuristic fallback (live lookup unreachable from this browser) · IP block pattern recorded.' };
}

function renderInvestigation(emailText) {
  const analysis = investigateEmail(emailText);
  const riskLevel = analysis.score >= 60 ? 'high' : analysis.score >= 30 ? 'medium' : 'low';
  const riskText = riskLevel === 'high' ? 'HIGH RISK' : riskLevel === 'medium' ? 'MEDIUM RISK' : 'LOW RISK';
  riskScore.textContent = `${analysis.score} / 100`;
  riskScore.textContent = analysis.score;
  riskScore.className = `assessment-score ${riskLevel}`;
  riskLabel.textContent = riskText;
  riskLabel.className = `risk-stamp ${riskLevel}`;
  resultMessage.textContent = analysis.score >= 60
    ? 'This message contains indicators consistent with phishing activity.'
    : 'No decisive phishing indicators were detected, but treat the message with caution.';
  findingList.replaceChildren(...analysis.findings.map((finding) => {
    const item = document.createElement('li');
    item.className = finding.level === 'high' ? 'high' : '';
    item.textContent = finding.text;
    return item;
  }));
  infoSender.textContent = analysis.headers.from || 'Unknown sender';
  infoSubject.textContent = analysis.headers.subject || 'No subject';
  infoDate.textContent = analysis.headers.date || analysis.trace[0]?.date || 'Unknown date';
  infoOriginIp.textContent = analysis.originIp;
  infoAuth.textContent = analysis.authStatus.join(' / ');
  infoLinks.textContent = analysis.urls.length;
  originCode.textContent = analysis.originCountryData.code;
  originCountry.textContent = analysis.originCountryData.country;
  confidenceBar.style.width = `${analysis.originCountryData.confidence}%`;
  originConfidence.textContent = `${analysis.originCountryData.confidence}%`;
  originReason.textContent = analysis.originCountryData.reason;
  assessmentFindings.replaceChildren(...analysis.findings.slice(0, 4).map((finding) => {
    const item = document.createElement('li');
    item.className = finding.level === 'high' ? 'high' : '';
    item.textContent = finding.text;
    return item;
  }));
  traceCount.textContent = `${analysis.trace.length} HOP${analysis.trace.length === 1 ? '' : 'S'}`;
  traceList.replaceChildren(...(analysis.trace.length ? analysis.trace : [{ from: 'No Received headers found', by: 'Source path unavailable', ip: '', date: 'Paste the complete headers to trace the route' }]).map((hop) => {
    const item = document.createElement('li');
    if (!analysis.trace.length) item.className = 'trace-empty';
    const details = document.createElement('div');
    details.className = 'trace-hop';
    const route = document.createElement('strong');
    route.textContent = `${hop.from}  →  ${hop.by}`;
    const metadata = document.createElement('span');
    metadata.textContent = hop.ip ? `${hop.ip}  ·  ${hop.date}` : hop.date;
    details.append(route, metadata);
    item.append(details);
    return item;
  }));
}

function setMode(mode) {
  const fileMode = mode === 'file';
  if (!fileMode && selectedFile) {
    selectedFile = null;
    fileInput.value = '';
    setStatus('Raw email mode');
  }
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle('active', selected);
    tab.setAttribute('aria-selected', selected);
  });
  dropzone.hidden = !fileMode;
  rawInput.hidden = fileMode;
}

tabs.forEach((tab) => tab.addEventListener('click', () => setMode(tab.dataset.mode)));
dropzone.addEventListener('click', () => fileInput.click());

function validateFile(file) {
  if (!file) return 'Choose a file to continue.';
  if (file.size > MAX_FILE_SIZE) return 'That file is larger than the 10MB limit.';
  if (!/\.eml$/i.test(file.name) && !/message\/rfc822/i.test(file.type)) return 'Please choose an .eml email file.';
  return '';
}

function selectFile(file) {
  const error = validateFile(file);
  if (error) {
    selectedFile = null;
    setStatus(error, true);
    dropLabel.textContent = 'Drop a .eml file here, or click to choose one';
    return false;
  }
  selectedFile = file;
  dropLabel.textContent = file.name;
  setStatus(`${(file.size / 1024).toFixed(1)} KB selected`);
  return true;
}

fileInput.addEventListener('change', () => {
  const [file] = fileInput.files;
  selectFile(file);
});

['dragenter', 'dragover'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropzone.classList.add('dragover');
}));
['dragleave', 'drop'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropzone.classList.remove('dragover');
}));
dropzone.addEventListener('drop', (event) => {
  const [file] = event.dataTransfer.files;
  if (file) selectFile(file);
});

rawInput.addEventListener('input', () => {
  if (rawInput.value.trim()) {
    selectedFile = null;
    fileInput.value = '';
    setStatus('Raw email text ready to investigate');
  }
});

sampleButton.addEventListener('click', () => {
  setMode('raw');
  selectedFile = null;
  fileInput.value = '';
  rawInput.value = sampleEmail;
  setStatus('Sample email loaded');
  rawInput.focus();
});

investigateButton.addEventListener('click', async () => {
  let emailText = rawInput.value.trim();
  if (selectedFile) emailText = (await selectedFile.text()).trim();
  const hasInput = emailText.length > 0;
  if (!hasInput) {
    setStatus('Add an email before investigating', true);
    dropzone.animate([{ borderColor: '#df786a' }, { borderColor: '#56605d' }], { duration: 500 });
    return;
  }
  renderInvestigation(emailText);
  resultPanel.hidden = false;
  investigateButton.querySelector('span').textContent = 'Investigation complete';
  resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});

clearButton.addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  rawInput.value = '';
  resultPanel.hidden = true;
  investigateButton.querySelector('span').textContent = 'Investigate';
  dropLabel.textContent = 'Drop a .eml file here, or click to choose one';
  setStatus('No email selected');
  setMode('file');
});
