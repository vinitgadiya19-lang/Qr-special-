/**
 * QR Shield - Frontend Threat & Phishing Detection Engine
 * 
 * Core Design Principles:
 * 1. 100% Client-Side: Decodes QR codes using jsQR in the browser canvas.
 * 2. Zero-Network Rule: Never fetches, pings, or opens any decoded URL.
 * 3. Heuristic Rules: Transparent, explainable rule checks with plain-language reasons.
 * 4. High Contrast & Accessible: Big readable verdict badges for everyday users.
 */

// ============================================================================
// Global State & UI Element References
// ============================================================================

let cameraStream = null;
let cameraAnimationId = null;

// Tab controls
const tabUpload = document.getElementById('tab-upload');
const tabCamera = document.getElementById('tab-camera');
const tabPaste = document.getElementById('tab-paste');
const panelUpload = document.getElementById('panel-upload');
const panelCamera = document.getElementById('panel-camera');
const panelPaste = document.getElementById('panel-paste');

// Upload & Drag/Drop
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const qrCanvas = document.getElementById('qr-canvas');
const qrCanvasContext = qrCanvas.getContext('2d');

// Camera controls
const cameraVideo = document.getElementById('camera-video');
const btnStartCamera = document.getElementById('btn-start-camera');
const btnStopCamera = document.getElementById('btn-stop-camera');
const cameraError = document.getElementById('camera-error');
const uploadError = document.getElementById('upload-error');
const pasteError = document.getElementById('paste-error');

/**
 * Non-blocking in-UI notification banner helper replacing alert().
 */
function showFeedbackError(targetElem, message) {
  if (!targetElem) return;
  targetElem.textContent = message;
  targetElem.hidden = false;
  setTimeout(() => {
    targetElem.hidden = true;
  }, 4500);
}

// Results & Verdict UI
const resultsSection = document.getElementById('results-section');
const verdictBanner = document.getElementById('verdict-banner');
const verdictIcon = document.getElementById('verdict-icon');
const verdictBadge = document.getElementById('verdict-badge');
const verdictHeadline = document.getElementById('verdict-headline');
// Threat Level elements (id="threat-score" / id="threat-severity" / id="threat-label")
const threatScoreElem = document.getElementById('threat-score');
const threatSeverityElem = document.getElementById('threat-severity');
const threatLabelElem = document.getElementById('threat-label');
const actionGuidance = document.getElementById('action-guidance');
const guidanceIcon = document.getElementById('guidance-icon');
const guidanceTitle = document.getElementById('guidance-title');
const guidanceDescription = document.getElementById('guidance-description');
const decodedTextBox = document.getElementById('decoded-text-box');
const reasonsList = document.getElementById('reasons-list');
const upiDetailsCard = document.getElementById('upi-details-card');
const upiAmountInfo = document.getElementById('upi-amount-info');
const upiGrid = document.getElementById('upi-grid');
const upiWarningBox = document.getElementById('upi-warning-box');
const wifiDetailsCard = document.getElementById('wifi-details-card');
const wifiWarningBox = document.getElementById('wifi-warning-box');
const wifiGrid = document.getElementById('wifi-grid');
const btnCopy = document.getElementById('btn-copy');
const btnReset = document.getElementById('btn-reset');
const btnOpenLink = document.getElementById('btn-open-link');
const btnOpenLinkText = document.getElementById('btn-open-link-text');
const btnSimpleOpenLink = document.getElementById('btn-simple-open-link');
const btnSimpleOpenLinkText = document.getElementById('btn-simple-open-text');

// Simple Mode for Elderly / Senior Users
const toggleSimpleMode = document.getElementById('toggle-simple-mode');
const simpleModeBanner = document.getElementById('simple-mode-banner');
const btnDisableSimpleMode = document.getElementById('btn-disable-simple-mode');
const simpleResultsSection = document.getElementById('simple-results-section');
const simpleIcon = document.getElementById('simple-icon');
const simpleBadge = document.getElementById('simple-badge');
const simpleTitle = document.getElementById('simple-title');
const simpleMessage = document.getElementById('simple-message');
const simpleSubnote = document.getElementById('simple-subnote');
const btnSimpleReset = document.getElementById('btn-simple-reset');
const btnViewDetails = document.getElementById('btn-view-details');

// Default to Simple Mode for a friendly first-time experience, or restore saved choice
let isSimpleMode = localStorage.getItem('qr_shield_simple_mode') === null ? true : localStorage.getItem('qr_shield_simple_mode') === 'true';

// Cache the last rendered analysis so mode toggling can update instantly
let lastRawData = null;
let lastAnalysis = null;

// Theme Mode (Dark and Bright)
const themeToggleBtn = document.getElementById('theme-toggle-btn');
const themeToggleLabel = document.getElementById('theme-toggle-label');

function getSavedTheme() {
  const saved = localStorage.getItem('qr_shield_theme');
  if (saved === 'light' || saved === 'dark') return saved;
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

let activeTheme = getSavedTheme();

function applyTheme(theme) {
  activeTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('qr_shield_theme', theme);
  if (themeToggleLabel) {
    themeToggleLabel.textContent = theme === 'dark' ? 'Bright' : 'Dark';
  }
  if (themeToggleBtn) {
    themeToggleBtn.setAttribute('title', `Switch to ${theme === 'dark' ? 'Bright' : 'Dark'} mode`);
    themeToggleBtn.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'Bright' : 'Dark'} mode`);
  }
}

// Apply theme on script initialization
applyTheme(activeTheme);

if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', () => {
    applyTheme(activeTheme === 'dark' ? 'light' : 'dark');
  });
}

// Heuristic Threat Intelligence Configuration
// ============================================================================

// Known public URL shortening services commonly used to obscure phishing links
const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rb.gy', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'shorte.st',
  'v.gd', 'bc.vc', 'clck.ru', 's.id', 'trib.al', 'qr.net', 'post.ly'
]);

// High-risk keywords commonly found in phishing lures and financial scams
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'kyc', 'reward', 'rewards',
  'cashback', 'lottery', 'winner', 'update', 'claim', 'bonus', 'free',
  'otp', 'banking', 'secure-account', 'unblock', 'aadhaar', 'pan-card',
  'refund', 'gift', 'prize', 'urgent', 'suspend', 'authenticate'
];

// Legitimate domains often targeted by lookalike homoglyphs / typosquatting
const SENSITIVE_BRANDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay', 'google',
  'bhim', 'amazon', 'flipkart', 'apple', 'microsoft', 'paypal', 'uidai'
];

// ============================================================================
// Core Rule-Based Threat Analysis Engine
// ============================================================================

/**
 * Analyzes the raw string decoded from a QR code using local heuristic checks.
 * Under NO circumstances does this function perform any network fetch or ping.
 * 
 * @param {string} rawData - The raw string extracted from the QR code.
 * @returns {Object} Analysis results containing verdict, score, checklist, and UPI details.
 */
function analyzeDecodedPayload(rawData) {
  const trimmed = (rawData || '').trim();
  let score = 100;
  const checks = [];
  let isUpi = false;
  let upiParams = null;

  // Check 1: Empty or Invalid Data
  if (!trimmed) {
    return {
      verdict: 'DANGER',
      score: 0,
      headline: 'Empty or corrupt payload detected.',
      guidance: {
        title: 'Do not trust this code',
        desc: 'The QR code contains no readable data or was incorrectly formatted.',
        level: 'danger'
      },
      checks: [{
        name: 'Payload Validity',
        status: 'danger',
        penalty: 100,
        reason: 'The QR code contains empty or unreadable content.'
      }],
      upi: null
    };
  }

  // Check 2: UPI Payment Protocol (Dedicated Indian UPI Handling)
  // When the decoded text starts with upi://pay:
  if (trimmed.toLowerCase().startsWith('upi://pay')) {
    isUpi = true;
    upiParams = parseUpiPayload(trimmed);

    // Primary clear message:
    const upiHeadline = 'This is a UPI payment QR. Scanning it is used to SEND money, never to receive money.';

    // Prominent guidance message:
    const upiGuidance = {
      title: 'Only pay if you trust this person or business',
      desc: 'Check that the payee name matches who you expect before entering your UPI PIN.',
      level: 'payment'
    };

    // Checklist explanations
    checks.push({
      name: 'UPI Payment Nature',
      status: 'pass',
      penalty: 0,
      reason: 'This is a UPI payment QR. Scanning it is used to SEND money, never to receive money.'
    });

    checks.push({
      name: 'Payee Verification Guidance',
      status: 'pass',
      penalty: 0,
      reason: 'Only pay if you trust this person or business. Check that the payee name matches who you expect before entering your UPI PIN.'
    });

    // Check if an amount is pre-filled
    if (upiParams.am && parseFloat(upiParams.am) > 0) {
      upiParams.amountNote = `This QR asks you to pay ₹${upiParams.am}. Make sure that is the amount you expect.`;
      checks.push({
        name: 'Pre-filled Payment Amount',
        status: 'warning',
        penalty: 0,
        reason: `This QR asks you to pay ₹${upiParams.am}. Make sure that is the amount you expect.`
      });
    }

    // Keep a small, separate "Be careful" note (yellow, not red) only if the note or payee name contains scam words:
    // such as reward, claim, lottery, refund or KYC.
    // Do NOT change the main verdict to Danger because of it.
    const UPI_SCAM_KEYWORDS = ['reward', 'claim', 'lottery', 'refund', 'kyc'];
    const upiSearchText = `${upiParams.pn} ${upiParams.tn}`.toLowerCase();
    const matchedScamWords = UPI_SCAM_KEYWORDS.filter(word => {
      const regex = new RegExp(`(^|[-_./?\\s=&])${word}([-_./?\\s=&]|$)`, 'i');
      return regex.test(upiSearchText);
    });

    if (matchedScamWords.length > 0) {
      const wordsList = matchedScamWords.join(', ');
      upiParams.warningNote = `The note or payee name contains words commonly associated with scams (${wordsList}). Scammers often promise rewards, refunds, or KYC verification to trick people into sending money.`;
      checks.push({
        name: 'Notice: Suspicious Words Found',
        status: 'warning', // yellow, NOT danger!
        penalty: 0,
        reason: `Be careful: The note or payee name mentions "${wordsList}". Scammers often use fake rewards, refunds, or KYC promises to trick people into sending money.`
      });
    }

    // Return neutral blue "Payment QR" verdict immediately
    return {
      verdict: 'Payment QR',
      score: 100,
      headline: upiHeadline,
      guidance: upiGuidance,
      checks: checks,
      upi: upiParams,
      wifi: null
    };
  }

  // Check 3: WiFi Configuration QR Code (Starts with WIFI:)
  if (trimmed.toUpperCase().startsWith('WIFI:')) {
    const wifiParams = parseWifiPayload(trimmed);

    // Primary clear messages:
    const wifiHeadline = 'Scanning this QR will connect your phone to this WiFi network. Only join networks you trust, such as your home, college or a place you know.';

    const wifiGuidance = {
      title: 'Verify Network Before Connecting',
      desc: 'Scanning this QR will connect your phone to this WiFi network. Only join networks you trust, such as your home, college or a place you know.',
      level: 'payment' // neutral blue styling
    };

    // Checklist explanations (Pure WiFi checks - no web checks run)
    checks.push({
      name: 'WiFi Connection Notice',
      status: 'pass',
      penalty: 0,
      reason: 'Scanning this QR will connect your phone to this WiFi network. Only join networks you trust, such as your home, college or a place you know.'
    });

    if (wifiParams.securityType === 'nopass') {
      checks.push({
        name: 'Unprotected Open Network',
        status: 'warning',
        penalty: 0,
        reason: 'This network has no password, so other people on it may be able to see your traffic.'
      });
    } else if (wifiParams.securityType === 'WEP') {
      checks.push({
        name: 'Weak Security Protocol',
        status: 'warning',
        penalty: 0,
        reason: 'WEP is an outdated, weak security type.'
      });
    } else {
      checks.push({
        name: 'Wireless Encryption',
        status: 'pass',
        penalty: 0,
        reason: `Uses ${escapeHtml(wifiParams.security || 'WPA')} encryption to secure traffic over the air.`
      });
    }

    if (wifiParams.hidden) {
      checks.push({
        name: 'Hidden Network (SSID)',
        status: 'pass',
        penalty: 0,
        reason: 'This network does not publicly broadcast its SSID name.'
      });
    }

    // Return neutral blue "WiFi QR" verdict immediately without running any URL or domain checks
    return {
      verdict: 'WiFi QR',
      score: 100,
      headline: wifiHeadline,
      guidance: wifiGuidance,
      checks: checks,
      upi: null,
      wifi: wifiParams
    };
  }

  // Parse as URL if not pure UPI or if it's a web URL
  let parsedUrl = null;
  try {
    // If text does not start with a scheme, check if it looks like a domain or web link
    if (/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(trimmed) && !trimmed.includes('://')) {
      parsedUrl = new URL('http://' + trimmed);
    } else {
      parsedUrl = new URL(trimmed);
    }
  } catch (e) {
    // Not a valid URL (plain text, phone number, WiFi configuration, etc.)
    if (!isUpi) {
      return {
        verdict: 'CAUTION',
        score: 70,
        headline: 'Plain text or non-web format detected',
        guidance: {
          title: 'Review plain text carefully',
          desc: 'This QR code contains plain text rather than a web link. Verify its content before acting on it.',
          level: 'caution'
        },
        checks: [{
          name: 'Format Type',
          status: 'warning',
          penalty: 30,
          reason: 'This QR code does not contain a standard web URL or UPI link.'
        }],
        upi: null
      };
    }
  }

  if (parsedUrl && !isUpi) {
    const rawLower = trimmed.toLowerCase();
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const search = parsedUrl.search.toLowerCase();

    // Check 3: HTTP vs HTTPS Scheme
    // How it works: Ensures transport encryption is enforced; HTTP permits MITM attacks.
    if (parsedUrl.protocol === 'http:') {
      checks.push({
        name: 'Insecure Protocol (HTTP)',
        status: 'danger',
        penalty: 30,
        reason: 'This website does not use encryption (HTTPS), so your data can be intercepted by hackers on the network.'
      });
      score -= 30;
    } else if (parsedUrl.protocol === 'https:') {
      checks.push({
        name: 'Secure Protocol (HTTPS)',
        status: 'pass',
        penalty: 0,
        reason: 'The link uses standard encrypted communication (HTTPS).'
      });
    } else {
      const proto = parsedUrl.protocol.toLowerCase();
      if (['javascript:', 'data:', 'vbscript:', 'file:'].includes(proto)) {
        checks.push({
          name: 'Dangerous Executable Scheme',
          status: 'danger',
          penalty: 100,
          reason: `The link uses an executable script or file scheme (${parsedUrl.protocol}) which can execute malicious code or access local files.`
        });
        score = 0;
      } else {
        checks.push({
          name: 'Non-Standard Web Protocol',
          status: 'warning',
          penalty: 25,
          reason: `The link uses a non-standard protocol (${parsedUrl.protocol}) which may trigger unintended device actions.`
        });
        score -= 25;
      }
    }

    // Check 4: Raw IP Address as Host
    // How it works: Matches IPv4 addresses or IPv6 brackets to identify unbranded servers.
    const isIpv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(hostname);
    const isIpv6 = /^\[?[a-fA-F0-9:]+\]?$/.test(hostname) && hostname.includes(':');
    if (isIpv4 || isIpv6) {
      checks.push({
        name: 'Raw IP Address Host',
        status: 'danger',
        penalty: 40,
        reason: 'This link points directly to a raw server IP address instead of a registered domain name, a common trick used by scammers.'
      });
      score -= 40;
    } else {
      checks.push({
        name: 'Domain Name Resolution',
        status: 'pass',
        penalty: 0,
        reason: 'The address uses a standard domain name instead of a bare numerical IP.'
      });
    }

    // Check 5: URL Shorteners
    // How it works: Matches host against curated list of shortening services masking real target.
    if (KNOWN_SHORTENERS.has(hostname) || hostname.endsWith('.bit.ly')) {
      checks.push({
        name: 'URL Shortener Detected',
        status: 'warning',
        penalty: 30,
        reason: 'This link uses a URL shortener which conceals the real website destination until after you click it.'
      });
      score -= 30;
    }

    // Check 6: Userinfo Obfuscation ("@" in URL)
    // How it works: Browsers interpret everything before '@' as basic-auth credentials, disguising the true host.
    // E.g., https://google.com@evil-site.com will open evil-site.com!
    if (trimmed.includes('@')) {
      checks.push({
        name: 'URL Obfuscation with "@" Symbol',
        status: 'danger',
        penalty: 45,
        reason: 'This link uses an "@" symbol to trick you into thinking it leads to a reputable site while actually redirecting elsewhere.'
      });
      score -= 45;
    }

    // Check 7: Too Many Subdomains
    // How it works: Splits hostname by dots; >= 4 segments indicates excessive nesting used to mimic sub-brands.
    const hostParts = hostname.split('.').filter(Boolean);
    if (hostParts.length >= 4 && !isIpv4) {
      checks.push({
        name: 'Excessive Subdomains',
        status: 'warning',
        penalty: 25,
        reason: `This domain has ${hostParts.length - 2} subdomain levels, which scammers frequently use to imitate legitimate bank or government portals.`
      });
      score -= 25;
    }

    // Check 8: Lookalike / Punycode / Internationalized Domain Name (IDN) Phishing
    // How it works: Detects 'xn--' prefix representing ASCII-encoded non-Latin lookalike characters.
    const hasPunycode = hostname.includes('xn--');
    const hasZeroWidth = /[\u200B-\u200D\uFEFF]/.test(trimmed);
    if (hasPunycode || hasZeroWidth) {
      checks.push({
        name: 'Punycode / Homoglyph Domain',
        status: 'danger',
        penalty: 45,
        reason: 'This web address contains encoded or lookalike characters designed to secretly spoof a familiar website name.'
      });
      score -= 45;
    }

    // Check 9: Suspicious Phishing Keywords
    // How it works: Scans the path, query string, and domain for urgency or financial lure terms.
    const fullUrlLower = rawLower;
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => {
      // Avoid false positive on simple query parameter names unless relevant
      const regex = new RegExp(`(^|[-_./?=&])${keyword}([-_./?=&]|$)`, 'i');
      return regex.test(fullUrlLower);
    });

    if (foundKeywords.length > 0) {
      const displayKeywords = foundKeywords.slice(0, 3).map(k => `"${k}"`).join(', ');
      checks.push({
        name: 'Suspicious / Phishing Keywords',
        status: foundKeywords.length >= 2 ? 'danger' : 'warning',
        penalty: foundKeywords.length >= 2 ? 35 : 20,
        reason: `The address contains high-risk keywords (${displayKeywords}) commonly seen in phishing scams targeting credentials or money.`
      });
      score -= (foundKeywords.length >= 2 ? 35 : 20);
    }

    // Check 10: Brand Impersonation / Typosquatting in Hostname
    // How it works: Checks if sensitive brand names (e.g. sbi, paytm) appear as an irregular substring
    const matchedBrand = SENSITIVE_BRANDS.find(brand => {
      // Check if hostname contains brand name but does not end with the official apex domain
      if (hostname.includes(brand)) {
        const isOfficial = hostname.endsWith(`.${brand}.com`) || 
                           hostname.endsWith(`.${brand}.co.in`) || 
                           hostname.endsWith(`.${brand}.in`) ||
                           hostname === `${brand}.com` ||
                           hostname === `${brand}.co.in` ||
                           hostname === `${brand}.in`;
        return !isOfficial;
      }
      return false;
    });

    if (matchedBrand) {
      checks.push({
        name: 'Potential Brand Impersonation',
        status: 'danger',
        penalty: 35,
        reason: `The domain references "${matchedBrand}" on an unofficial domain, indicating potential impersonation fraud.`
      });
      score -= 35;
    }

    // Check 11: Unusually Long URL (> 120 chars)
    // How it works: Excessive length is used to push scam domains past the mobile address bar preview.
    if (trimmed.length > 120) {
      checks.push({
        name: 'Unusually Long Web Address',
        status: 'warning',
        penalty: 15,
        reason: `The address is ${trimmed.length} characters long, a technique often used to hide the true destination beyond the screen's view.`
      });
      score -= 15;
    } else {
      checks.push({
        name: 'URL Length',
        status: 'pass',
        penalty: 0,
        reason: 'The web address is within standard length limits.'
      });
    }
  }

  // Ensure score is bounded between 0 and 100
  score = Math.max(0, Math.min(100, score));

  // Determine Overall Verdict based on final score
  let verdict = 'SAFE';
  let headline = 'Low risk detected from standard heuristic patterns.';
  let guidance = {
    title: 'Likely Safe to Proceed',
    desc: 'No major phishing, IP hosting, shortener, or scam triggers were found. Always confirm the destination matches your intention.',
    level: 'safe'
  };

  if (score < 50) {
    verdict = 'DANGER';
    headline = 'High likelihood of phishing, credential theft, or financial fraud!';
    guidance = {
      title: 'DO NOT TRUST OR OPEN THIS QR CODE',
      desc: 'Multiple critical security warnings were triggered. Scanning or following this link could compromise your device, passwords, or bank account.',
      level: 'danger'
    };
  } else if (score < 85) {
    verdict = 'CAUTION';
    headline = 'Suspicious elements detected — proceed with extreme vigilance.';
    guidance = {
      title: 'Exercise Caution Before Proceeding',
      desc: 'This QR code contains obfuscated or non-standard elements (such as shorteners or missing encryption). Confirm the sender identity before trusting it.',
      level: 'caution'
    };
  }

  return {
    verdict,
    score,
    headline,
    guidance,
    checks,
    upi: isUpi ? upiParams : null
  };
}

/**
 * Parses UPI URI query parameters (e.g., upi://pay?pa=...&pn=...)
 * 
 * @param {string} upiUri - The raw UPI string.
 * @returns {Object} Key-value pair of UPI parameters.
 */
function parseUpiPayload(upiUri) {
  const result = { pa: '', pn: '', mc: '', am: '', cu: 'INR', tn: '', amountNote: '', warningNote: '' };
  try {
    const qIndex = upiUri.indexOf('?');
    if (qIndex !== -1) {
      const queryString = upiUri.substring(qIndex + 1);
      const params = new URLSearchParams(queryString);
      result.pa = params.get('pa') || '';
      result.pn = params.get('pn') || '';
      result.mc = params.get('mc') || '';
      result.am = params.get('am') || '';
      result.cu = params.get('cu') || 'INR';
      result.tn = params.get('tn') || '';
    }
  } catch (e) {
    console.error('Error parsing UPI URI:', e);
  }
  return result;
}

/**
 * Parses WiFi QR code strings (e.g., WIFI:S:MyNetwork;T:WPA;P:secret123;H:false;;)
 * 
 * @param {string} wifiStr - The raw WiFi QR payload.
 * @returns {Object} Extracted WiFi parameters including ssid, security, password, hidden.
 */
function parseWifiPayload(wifiStr) {
  const raw = wifiStr.replace(/^WIFI:/i, '');
  const result = {
    ssid: '',
    security: '',
    securityType: '',
    password: '',
    hidden: false,
    warningNote: ''
  };

  // Standard WiFi QR format uses semicolon-separated key:value pairs
  const regex = /([STPH]):((?:\\;|[^;])*)/gi;
  let match;
  while ((match = regex.exec(raw)) !== null) {
    const key = match[1].toUpperCase();
    let val = match[2].replace(/\\([\\;:])/g, '$1'); // unescape \; and \:
    if (key === 'S') result.ssid = val;
    else if (key === 'T') result.security = val;
    else if (key === 'P') result.password = val;
    else if (key === 'H') result.hidden = (val.toLowerCase() === 'true' || val === '1');
  }

  const secUpper = (result.security || '').toUpperCase();
  if (!secUpper || secUpper === 'NOPASS') {
    result.securityType = 'nopass';
  } else if (secUpper === 'WEP') {
    result.securityType = 'WEP';
  } else if (secUpper.includes('WPA')) {
    result.securityType = 'WPA';
  } else {
    result.securityType = result.security || 'nopass';
  }

  // Plain-language warning messages:
  if (result.securityType === 'nopass') {
    result.warningNote = 'This network has no password, so other people on it may be able to see your traffic.';
  } else if (result.securityType === 'WEP') {
    result.warningNote = 'WEP is an outdated, weak security type.';
  }

  return result;
}

// ============================================================================
// UI Rendering & Verdict Presentation
// ============================================================================

/**
 * Displays the analysis results in the DOM with high visual clarity.
 * 
 * @param {string} rawData - The raw scanned string.
 * @param {Object} analysis - The evaluation object from analyzeDecodedPayload.
 */
function renderAnalysisResults(rawData, analysis) {
  // Cache data for instant toggling between Simple and Detailed modes
  lastRawData = rawData;
  lastAnalysis = analysis;

  // Update Raw Decoded Text Display (Never creates a clickable active link!)
  decodedTextBox.textContent = rawData;

  // Update Verdict Banner
  const isNeutral = analysis.verdict === 'Payment QR' || analysis.verdict === 'WiFi QR';
  const verdictBannerClass = isNeutral ? 'verdict-payment' : `verdict-${analysis.verdict.toLowerCase()}`;
  verdictBanner.className = `verdict-banner ${verdictBannerClass}`;
  verdictBadge.textContent = analysis.verdict;
  verdictHeadline.textContent = analysis.headline;

  // Update Threat Level Display
  // Threat level = 100 - safety score, so higher threat = higher %, always matches verdict.
  // WiFi QR and Payment QR are neutral — no threat percentage applies to them.
  if (analysis.verdict === 'WiFi QR') {
    if (threatScoreElem) threatScoreElem.textContent = 'WiFi';
    if (threatSeverityElem) threatSeverityElem.textContent = '';
    if (threatLabelElem) threatLabelElem.textContent = 'Network QR';
    verdictIcon.textContent = '📶';
  } else if (analysis.verdict === 'Payment QR') {
    if (threatScoreElem) threatScoreElem.textContent = 'UPI';
    if (threatSeverityElem) threatSeverityElem.textContent = '';
    if (threatLabelElem) threatLabelElem.textContent = 'Payment Mode';
    verdictIcon.textContent = '💳';
  } else {
    // Compute threat level: inverse of safety score.
    // Safe verdict:   safety score 85-100 → threat 0-15%  (shown as 0-20% "Low")
    // Caution verdict: safety score 50-84 → threat 16-50% (shown as 21-60% "Medium")
    // Danger verdict:  safety score 0-49  → threat 51-100% (shown as 61-100% "High")
    const threatPct = 100 - Math.max(0, Math.min(100, analysis.score));
    let severityWord = 'Low';
    if (threatPct > 60) severityWord = 'High';
    else if (threatPct > 20) severityWord = 'Medium';

    if (threatScoreElem) threatScoreElem.textContent = `${threatPct}%`;
    if (threatSeverityElem) threatSeverityElem.textContent = severityWord;
    if (threatLabelElem) threatLabelElem.textContent = 'THREAT LEVEL';

    if (analysis.verdict === 'SAFE') {
      verdictIcon.textContent = '🛡️';
    } else if (analysis.verdict === 'CAUTION') {
      verdictIcon.textContent = '⚠️';
    } else {
      verdictIcon.textContent = '🚨';
    }
  }

  // Update Action Guidance
  actionGuidance.className = `action-guidance ${analysis.guidance.level}`;
  guidanceTitle.textContent = analysis.guidance.title;
  guidanceDescription.textContent = analysis.guidance.desc;

  if (analysis.verdict === 'WiFi QR') {
    guidanceIcon.textContent = '📶';
  } else if (analysis.guidance.level === 'payment') {
    guidanceIcon.textContent = '💳';
  } else if (analysis.guidance.level === 'danger') {
    guidanceIcon.textContent = '🛑';
  } else if (analysis.guidance.level === 'caution') {
    guidanceIcon.textContent = '⚠️';
  } else {
    guidanceIcon.textContent = '✅';
  }

  // Populate Checklist Items
  reasonsList.innerHTML = '';
  analysis.checks.forEach(check => {
    const item = document.createElement('div');
    item.className = `reason-item ${check.status}`;

    let icon = '✓';
    let badgeLabel = 'Pass';
    if (check.status === 'danger') {
      icon = '✕';
      badgeLabel = 'Critical Risk';
    } else if (check.status === 'warning') {
      icon = '!';
      badgeLabel = 'Notice';
    }

    item.innerHTML = `
      <div class="reason-icon" aria-hidden="true">${icon}</div>
      <div class="reason-content">
        <div class="reason-title">
          <span>${escapeHtml(check.name)}</span>
          <span class="reason-badge">${badgeLabel}</span>
        </div>
        <p class="reason-text">${escapeHtml(check.reason)}</p>
      </div>
    `;
    reasonsList.appendChild(item);
  });

  // Render UPI Parameters if applicable
  if (analysis.upi) {
    upiDetailsCard.hidden = false;

    // Show pre-filled amount note if present
    if (analysis.upi.amountNote && upiAmountInfo) {
      upiAmountInfo.hidden = false;
      upiAmountInfo.innerHTML = `<span>ℹ️</span> <span>${escapeHtml(analysis.upi.amountNote)}</span>`;
    } else if (upiAmountInfo) {
      upiAmountInfo.hidden = true;
      upiAmountInfo.innerHTML = '';
    }

    // Parsed details: payee name (pn), payee UPI ID (pa), amount (am, formatted with ₹), note (tn).
    // If a field is missing, show "Not provided".
    const payeeName = analysis.upi.pn && analysis.upi.pn.trim() ? analysis.upi.pn.trim() : 'Not provided';
    const payeeVpa = analysis.upi.pa && analysis.upi.pa.trim() ? analysis.upi.pa.trim() : 'Not provided';
    const amountVal = analysis.upi.am && analysis.upi.am.trim() ? `₹${analysis.upi.am.trim()}` : 'Not provided';
    const noteVal = analysis.upi.tn && analysis.upi.tn.trim() ? analysis.upi.tn.trim() : 'Not provided';

    upiGrid.innerHTML = `
      <div class="upi-item">
        <div class="upi-item-label">Payee Name (pn)</div>
        <div class="upi-item-value">${escapeHtml(payeeName)}</div>
      </div>
      <div class="upi-item">
        <div class="upi-item-label">Payee UPI ID (pa)</div>
        <div class="upi-item-value">${escapeHtml(payeeVpa)}</div>
      </div>
      <div class="upi-item">
        <div class="upi-item-label">Amount (am)</div>
        <div class="upi-item-value">${escapeHtml(amountVal)}</div>
      </div>
      <div class="upi-item">
        <div class="upi-item-label">Note (tn)</div>
        <div class="upi-item-value">${escapeHtml(noteVal)}</div>
      </div>
    `;

    // Small, separate "Be careful" note (yellow, not red) if scam words found:
    if (analysis.upi.warningNote && upiWarningBox) {
      upiWarningBox.hidden = false;
      upiWarningBox.innerHTML = `<span>⚠️</span> <div><strong>Be careful:</strong> ${escapeHtml(analysis.upi.warningNote)}</div>`;
    } else if (upiWarningBox) {
      upiWarningBox.hidden = true;
      upiWarningBox.innerHTML = '';
    }
  } else {
    upiDetailsCard.hidden = true;
    if (upiAmountInfo) upiAmountInfo.hidden = true;
    if (upiWarningBox) upiWarningBox.hidden = true;
    upiGrid.innerHTML = '';
  }

  // Render WiFi Parameters if applicable
  if (analysis.wifi) {
    wifiDetailsCard.hidden = false;

    // Show warning notice if nopass or WEP
    if (analysis.wifi.warningNote && wifiWarningBox) {
      wifiWarningBox.hidden = false;
      wifiWarningBox.innerHTML = `<span>⚠️</span> <div><strong>Security Notice:</strong> ${escapeHtml(analysis.wifi.warningNote)}</div>`;
    } else if (wifiWarningBox) {
      wifiWarningBox.hidden = true;
      wifiWarningBox.innerHTML = '';
    }

    const netName = analysis.wifi.ssid ? analysis.wifi.ssid : 'Not provided';
    const secType = analysis.wifi.security ? analysis.wifi.security : (analysis.wifi.securityType === 'nopass' ? 'nopass' : 'Not specified');
    const isHidden = analysis.wifi.hidden ? 'Yes (Hidden network)' : 'No (Visible network)';

    // Password masking with toggle
    const hasPass = Boolean(analysis.wifi.password && analysis.wifi.password.trim().length > 0);
    let passHtml = '';
    if (hasPass) {
      const dots = '•'.repeat(Math.min(12, Math.max(8, analysis.wifi.password.length)));
      passHtml = `
        <div class="wifi-pass-wrap">
          <span id="wifi-pass-display" class="wifi-pass-text" data-revealed="false" data-raw="${escapeHtml(analysis.wifi.password)}">${dots}</span>
          <button type="button" id="btn-toggle-wifi-pass" class="btn btn-sm btn-outline">
            👁️ Show password
          </button>
        </div>
      `;
    } else if (analysis.wifi.securityType === 'nopass') {
      passHtml = `<span style="color: var(--text-dim);">No password (Open network)</span>`;
    } else {
      passHtml = `<span style="color: var(--text-dim);">Not provided</span>`;
    }

    wifiGrid.innerHTML = `
      <div class="wifi-item">
        <div class="wifi-item-label">Network Name (SSID)</div>
        <div class="wifi-item-value">${escapeHtml(netName)}</div>
      </div>
      <div class="wifi-item">
        <div class="wifi-item-label">Security Type</div>
        <div class="wifi-item-value">${escapeHtml(secType)}</div>
      </div>
      <div class="wifi-item">
        <div class="wifi-item-label">Hidden Network</div>
        <div class="wifi-item-value">${escapeHtml(isHidden)}</div>
      </div>
      <div class="wifi-item">
        <div class="wifi-item-label">Password</div>
        <div class="wifi-item-value">${passHtml}</div>
      </div>
    `;

    // Bind password toggle event listener
    const btnToggle = document.getElementById('btn-toggle-wifi-pass');
    const passDisplay = document.getElementById('wifi-pass-display');
    if (btnToggle && passDisplay) {
      btnToggle.addEventListener('click', () => {
        const isRevealed = passDisplay.getAttribute('data-revealed') === 'true';
        const rawPass = passDisplay.getAttribute('data-raw');
        if (isRevealed) {
          passDisplay.textContent = '•'.repeat(Math.min(12, Math.max(8, rawPass.length)));
          passDisplay.setAttribute('data-revealed', 'false');
          btnToggle.textContent = '👁️ Show password';
        } else {
          passDisplay.textContent = rawPass;
          passDisplay.setAttribute('data-revealed', 'true');
          btnToggle.textContent = '🙈 Hide password';
        }
      });
    }
  } else {
    wifiDetailsCard.hidden = true;
    if (wifiWarningBox) wifiWarningBox.hidden = true;
    wifiGrid.innerHTML = '';
  }

  // Update Open Link button state based on safety verdict
  updateOpenLinkButtons(rawData, analysis);

  // Populate the Simple Mode Card for Elders
  renderSimpleModeCard(rawData, analysis);

  // Present the view according to the active mode
  if (isSimpleMode) {
    if (simpleResultsSection) {
      simpleResultsSection.hidden = false;
      simpleResultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    resultsSection.hidden = true;
  } else {
    if (simpleResultsSection) simpleResultsSection.hidden = true;
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

/**
 * Updates the 'Open Link' button state based on the calculated risk level.
 * The button functions ONLY when risk level is Safe or Medium (Caution).
 * In High Risk (Danger / scam), the button is strictly disabled and locked.
 */
function updateOpenLinkButtons(rawData, analysis) {
  if (!btnOpenLink) return;

  const trimmed = (rawData || '').trim();

  // Evaluate risk level:
  // Threat percentage > 60%, or verdict is DANGER, or UPI note with matched scam keywords
  const isHighRisk = (analysis.verdict === 'DANGER') ||
                     (analysis.upi && Boolean(analysis.upi.warningNote)) ||
                     (analysis.score !== undefined && (100 - Math.max(0, Math.min(100, analysis.score))) > 60);

  // Check if the payload is an openable URL destination
  const isHttpUrl = /^https?:\/\//i.test(trimmed);
  const isBareDomain = /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(trimmed) && !trimmed.includes(' ');
  const isUpiScheme = /^upi:\/\/pay/i.test(trimmed);
  const hasOpenableTarget = isHttpUrl || isBareDomain || isUpiScheme;

  let targetUrl = '';
  if (isHttpUrl || isUpiScheme) {
    targetUrl = trimmed;
  } else if (isBareDomain) {
    targetUrl = 'https://' + trimmed;
  }

  if (isHighRisk) {
    // HIGH RISK: Strictly blocked and disabled
    btnOpenLink.removeAttribute('href');
    btnOpenLink.setAttribute('aria-disabled', 'true');
    btnOpenLink.classList.add('disabled');
    btnOpenLink.setAttribute('title', 'Blocked for your safety: This QR code is flagged as High Risk / Phishing.');
    if (btnOpenLinkText) btnOpenLinkText.textContent = 'Link Blocked (High Risk)';

    if (btnSimpleOpenLink) {
      btnSimpleOpenLink.removeAttribute('href');
      btnSimpleOpenLink.setAttribute('aria-disabled', 'true');
      btnSimpleOpenLink.classList.add('disabled');
      btnSimpleOpenLink.setAttribute('title', 'Blocked: High danger detected.');
      if (btnSimpleOpenLinkText) btnSimpleOpenLinkText.textContent = '🚫 Blocked (High Risk)';
    }
  } else if (hasOpenableTarget) {
    // SAFE OR MEDIUM RISK: Link is enabled and safe to open
    btnOpenLink.setAttribute('href', targetUrl);
    btnOpenLink.removeAttribute('aria-disabled');
    btnOpenLink.classList.remove('disabled');
    btnOpenLink.setAttribute('title', `Open ${targetUrl} in a new tab`);
    if (btnOpenLinkText) {
      btnOpenLinkText.textContent = isUpiScheme ? 'Open Payment Link' : 'Open Link';
    }

    if (btnSimpleOpenLink) {
      btnSimpleOpenLink.setAttribute('href', targetUrl);
      btnSimpleOpenLink.removeAttribute('aria-disabled');
      btnSimpleOpenLink.classList.remove('disabled');
      btnSimpleOpenLink.setAttribute('title', `Open ${targetUrl}`);
      if (btnSimpleOpenLinkText) {
        btnSimpleOpenLinkText.textContent = isUpiScheme ? 'Open Payment Link' : 'Open Link';
      }
    }
  } else {
    // Non-link payload (e.g., WiFi, plain text)
    btnOpenLink.removeAttribute('href');
    btnOpenLink.setAttribute('aria-disabled', 'true');
    btnOpenLink.classList.add('disabled');
    btnOpenLink.setAttribute('title', 'No web link detected in this QR code.');
    if (btnOpenLinkText) btnOpenLinkText.textContent = 'No Link to Open';

    if (btnSimpleOpenLink) {
      btnSimpleOpenLink.removeAttribute('href');
      btnSimpleOpenLink.setAttribute('aria-disabled', 'true');
      btnSimpleOpenLink.classList.add('disabled');
      btnSimpleOpenLink.setAttribute('title', 'No web link to open.');
      if (btnSimpleOpenLinkText) btnSimpleOpenLinkText.textContent = 'No Web Link';
    }
  }
}

/**
 * Renders the high-visibility, simple verdict card for elderly / senior users.
 * Uses high contrast and large green / yellow / red status colors with clear plain language.
 */
function renderSimpleModeCard(rawData, analysis) {
  if (!simpleResultsSection) return;

  let cardClass = 'simple-safe';
  let icon = '🛡️';
  let badge = 'SAFE';
  let title = 'SAFE TO USE';
  let message = 'This QR code looks completely safe. No viruses, fake websites, or scams were found.';
  let subnoteHtml = '';

  if (analysis.verdict === 'DANGER') {
    cardClass = 'simple-danger';
    icon = '🛑';
    badge = 'DANGER WARNING';
    title = 'DANGER - DO NOT SCAN!';
    message = 'STOP! This QR code is dangerous and high-risk. It is likely a scam or fake website trying to steal your money, passwords, or personal details.';
    const dangerChecks = (analysis.checks || []).filter(c => c.status === 'danger');
    if (dangerChecks.length > 0) {
      const reasons = dangerChecks.map(c => `• ${escapeHtml(c.reason)}`).join('<br>');
      subnoteHtml = `<strong style="color: #fca5a5;">Why you should not trust this:</strong><br><span style="margin-top: 4px; display: inline-block;">${reasons}</span>`;
    }
  } else if (analysis.verdict === 'CAUTION') {
    cardClass = 'simple-caution';
    icon = '⚠️';
    badge = 'BE CAREFUL';
    title = 'PROCEED WITH CAUTION';
    message = 'Be careful! This link conceals its destination or needs caution. Do not enter any passwords or payment information unless you know the sender.';
    const warnChecks = (analysis.checks || []).filter(c => c.status === 'warning' || c.status === 'danger');
    if (warnChecks.length > 0) {
      const reasons = warnChecks.map(c => `• ${escapeHtml(c.reason)}`).join('<br>');
      subnoteHtml = `<strong style="color: #fde68a;">Things to watch out for:</strong><br><span style="margin-top: 4px; display: inline-block;">${reasons}</span>`;
    }
  } else if (analysis.verdict === 'Payment QR') {
    const hasScamNotice = analysis.upi && analysis.upi.warningNote;
    if (hasScamNotice) {
      cardClass = 'simple-danger';
      icon = '🛑';
      badge = 'PAYMENT SCAM ALERT';
      title = 'DANGER: SUSPICIOUS PAYMENT QR';
      message = 'Warning! This payment request mentions suspicious words (reward, refund, or KYC). Scammers frequently use fake rewards to trick people into sending money.';
    } else {
      cardClass = 'simple-caution';
      icon = '💸';
      badge = 'PAYMENT QR';
      title = 'MONEY WILL BE SENT';
      message = 'Scanning this QR code will SEND money from your bank account to another person. Remember: You NEVER receive money by scanning a QR code!';
    }
    const payee = (analysis.upi && analysis.upi.pn && analysis.upi.pn.trim()) ? analysis.upi.pn.trim() : 'Unknown Person or Business';
    const amount = (analysis.upi && analysis.upi.am && analysis.upi.am.trim()) ? `₹${analysis.upi.am.trim()}` : 'Amount chosen by you';
    subnoteHtml = `
      <div style="font-size: 1.2rem; margin-bottom: 6px;">
        👤 <strong>Who receives your money:</strong> <span style="color: #ffffff; text-decoration: underline;">${escapeHtml(payee)}</span>
      </div>
      <div style="font-size: 1.2rem; margin-bottom: 6px;">
        💰 <strong>Amount to pay:</strong> <span style="color: #fbbf24; font-weight: 800;">${escapeHtml(amount)}</span>
      </div>
      <div style="margin-top: 8px; font-size: 0.95rem; color: #fef08a;">
        ⚠️ <em>Only proceed and enter your UPI PIN if you intentionally want to pay this person.</em>
      </div>
    `;
  } else if (analysis.verdict === 'WiFi QR') {
    const isWeak = analysis.wifi && (analysis.wifi.securityType === 'nopass' || analysis.wifi.securityType === 'WEP');
    if (isWeak) {
      cardClass = 'simple-caution';
      icon = '⚠️';
      badge = 'OPEN WI-FI WARNING';
      title = 'UNSECURED WI-FI NETWORK';
      message = 'This Wi-Fi network has no password or weak protection. Anyone nearby may be able to see what you do online.';
    } else {
      cardClass = 'simple-safe';
      icon = '📶';
      badge = 'SAFE WI-FI';
      title = 'SAFE WI-FI NETWORK';
      message = 'This QR code connects your device to a secure, password-protected Wi-Fi network.';
    }
    const ssid = (analysis.wifi && analysis.wifi.ssid) ? analysis.wifi.ssid : 'Unknown Network';
    subnoteHtml = `📶 <strong>Wi-Fi Name (SSID):</strong> <strong style="color: #ffffff;">${escapeHtml(ssid)}</strong>`;
  } else {
    // SAFE
    cardClass = 'simple-safe';
    icon = '🛡️';
    badge = 'SAFE TO USE';
    title = 'SAFE TO USE';
    message = 'This QR code is completely safe. No fake websites, phishing links, or scams were found.';
  }

  simpleResultsSection.className = `simple-card ${cardClass}`;
  if (simpleIcon) simpleIcon.textContent = icon;
  if (simpleBadge) simpleBadge.textContent = badge;
  if (simpleTitle) simpleTitle.textContent = title;
  if (simpleMessage) simpleMessage.textContent = message;
  if (simpleSubnote) {
    if (subnoteHtml) {
      simpleSubnote.innerHTML = subnoteHtml;
      simpleSubnote.hidden = false;
    } else {
      simpleSubnote.hidden = true;
      simpleSubnote.innerHTML = '';
    }
  }
}

/**
 * Utility helper to prevent HTML injection into reasons or raw boxes.
 */
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ============================================================================
// QR Code Image Processing via Local jsQR
// ============================================================================

/**
 * Decodes a QR code from an image element using multi-scale fallback scanning.
 * - Initial attempt: If image width > 1000px, downscales to 1000px width.
 * - Fallbacks: If initial attempt fails, retries at 600px, 1400px, 800px, and native original size.
 * - Only returns null after all scale attempts fail.
 * 
 * @param {HTMLImageElement} img - The loaded image element.
 * @returns {string|null} The decoded text or null if not found.
 */
function decodeQrFromImage(img) {
  // Check if jsQR is loaded
  if (typeof jsQR === 'undefined') {
    console.error('The jsQR decoding library is not loaded. Please ensure jsQR.js is in the same folder.');
    showFeedbackError(uploadError, 'QR decoding engine is initializing or unavailable. Please reload the page.');
    return null;
  }

  const origWidth = img.naturalWidth || img.width;
  const origHeight = img.naturalHeight || img.height;
  if (!origWidth || !origHeight) return null;

  // Build target candidate widths to test in order of priority:
  // 1. Initial attempt: downscale to 1000px width if larger, otherwise use native width
  const initialWidth = origWidth > 1000 ? 1000 : origWidth;
  const candidateWidths = [initialWidth];

  // 2. Fallbacks to retry: 600px, 1400px, 800px, native original size
  const fallbacks = [600, 1400, 800, origWidth];
  for (const w of fallbacks) {
    if (!candidateWidths.includes(w) && w > 0) {
      candidateWidths.push(w);
    }
  }

  // Iterate through candidate scales until a valid QR code is found
  for (const targetW of candidateWidths) {
    const scale = targetW / origWidth;
    const width = Math.max(1, Math.round(origWidth * scale));
    const height = Math.max(1, Math.round(origHeight * scale));

    qrCanvas.width = width;
    qrCanvas.height = height;
    qrCanvasContext.drawImage(img, 0, 0, width, height);

    try {
      const imageData = qrCanvasContext.getImageData(0, 0, width, height);
      const code = jsQR(imageData.data, width, height, {
        inversionAttempts: 'attemptBoth'
      });
      if (code && code.data && code.data.trim().length > 0) {
        return code.data.trim();
      }
    } catch (err) {
      console.warn(`Decoding attempt at ${width}x${height} failed:`, err);
    }
  }

  // All scale attempts failed
  return null;
}

/**
 * Decodes a single video frame from an active camera feed.
 * 
 * @param {HTMLVideoElement} video - The playing camera video element.
 * @returns {string|null} The decoded text or null.
 */
function decodeQrFromVideo(video) {
  if (typeof jsQR === 'undefined') return null;

  const width = video.videoWidth;
  const height = video.videoHeight;
  if (!width || !height) return null;

  qrCanvas.width = width;
  qrCanvas.height = height;
  qrCanvasContext.drawImage(video, 0, 0, width, height);

  try {
    const imageData = qrCanvasContext.getImageData(0, 0, width, height);
    const code = jsQR(imageData.data, width, height, {
      inversionAttempts: 'attemptBoth'
    });
    return code && code.data ? code.data.trim() : null;
  } catch (err) {
    return null;
  }
}

/**
 * Handles an image file received via upload or clipboard paste.
 * 
 * @param {File|Blob} file - The image file to decode.
 * @param {HTMLElement} [errorTarget=uploadError] - The target error banner element.
 */
function handleImageFile(file, errorTarget = uploadError) {
  if (!file || !file.type.startsWith('image/')) {
    showFeedbackError(errorTarget, 'Please provide a valid image file (PNG, JPG, WEBP).');
    return;
  }

  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      const decodedText = decodeQrFromImage(img);
      if (decodedText) {
        const analysis = analyzeDecodedPayload(decodedText);
        renderAnalysisResults(decodedText, analysis);
      } else {
        showFeedbackError(errorTarget, 'No QR code detected in this image. Please ensure the QR code is clearly visible, well-lit, and not overly distorted.');
      }
    };
    img.onerror = function() {
      showFeedbackError(errorTarget, 'Failed to load image file. Please try another image.');
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

// ============================================================================
// Camera Live Scanner Implementation
// ============================================================================

async function startCameraScanner() {
  cameraError.hidden = true;
  cameraError.innerHTML = '';

  // Determine if running in a secure context (HTTPS or localhost)
  const isLocalhost = location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.hostname === '::1';
  const isHttps = location.protocol === 'https:';
  const isSecure = window.isSecureContext || isLocalhost || isHttps;

  // Modern browsers strictly require HTTPS or localhost for navigator.mediaDevices
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    cameraError.hidden = false;
    if (location.protocol === 'file:') {
      cameraError.innerHTML = '<strong>Camera Restricted on file://</strong><br>' +
        'Chrome and modern browsers restrict live camera access on direct <code>file://</code> URLs for security.<br>' +
        '👉 You can still <strong>Upload an Image</strong> or <strong>Paste a Screenshot (Ctrl+V)</strong> anytime!<br>' +
        '<small>To use camera, run a local server: <code>python -m http.server 8080</code> and open <code>http://localhost:8080</code></small>';
    } else if (!isSecure) {
      cameraError.innerHTML = '<strong>Insecure Origin:</strong> Camera access requires HTTPS or localhost.';
    } else {
      cameraError.innerHTML = '<strong>Camera Not Supported:</strong> Your browser does not support mediaDevices API.';
    }
    return;
  }

  try {
    // Attempt 1: Request rear camera (environment-facing) on mobile devices
    try {
      cameraStream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 }
        }
      });
    } catch (facingErr) {
      // Attempt 2: Fallback to standard camera (e.g. desktop/laptop webcam)
      cameraStream = await navigator.mediaDevices.getUserMedia({
        video: true
      });
    }

    cameraVideo.srcObject = cameraStream;
    cameraVideo.setAttribute('playsinline', 'true');
    await cameraVideo.play();

    btnStartCamera.disabled = true;
    btnStopCamera.disabled = false;

    // Start frame-by-frame scanning loop with requestAnimationFrame
    scanCameraFrame();
  } catch (err) {
    console.error('Camera access error:', err);
    cameraError.hidden = false;

    if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
      cameraError.innerHTML = '<strong>Camera Permission Denied:</strong> Camera access was blocked. Please allow camera permissions in your browser address bar.';
    } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
      cameraError.innerHTML = '<strong>No Camera Found:</strong> No webcam or camera device was found on this system.';
    } else {
      cameraError.innerHTML = `<strong>Camera Access Failed:</strong> ${escapeHtml(err.message || err.name || 'Unknown error')}`;
    }
    stopCameraScanner();
  }
}

function stopCameraScanner() {
  if (cameraAnimationId) {
    cancelAnimationFrame(cameraAnimationId);
    cameraAnimationId = null;
  }

  if (cameraStream) {
    cameraStream.getTracks().forEach(track => {
      try { track.stop(); } catch (e) {}
    });
    cameraStream = null;
  }

  if (cameraVideo) {
    cameraVideo.srcObject = null;
  }

  btnStartCamera.disabled = false;
  btnStopCamera.disabled = true;
}

function scanCameraFrame() {
  if (!cameraStream) return;

  if (cameraVideo.readyState === cameraVideo.HAVE_ENOUGH_DATA) {
    const decodedText = decodeQrFromVideo(cameraVideo);
    if (decodedText) {
      // Successfully recognized QR code
      stopCameraScanner();
      const analysis = analyzeDecodedPayload(decodedText);
      renderAnalysisResults(decodedText, analysis);
      return;
    }
  }

  // Continue scanning next animation frame while camera is running
  if (cameraStream) {
    cameraAnimationId = requestAnimationFrame(scanCameraFrame);
  }
}

// ============================================================================
// Event Listeners & Input Handlers
// ============================================================================

// Tab Switching
function switchTab(targetTab) {
  [tabUpload, tabCamera, tabPaste].forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  [panelUpload, panelCamera, panelPaste].forEach(p => {
    p.classList.remove('active');
    p.hidden = true;
  });

  if (targetTab === 'upload') {
    tabUpload.classList.add('active');
    tabUpload.setAttribute('aria-selected', 'true');
    panelUpload.classList.add('active');
    panelUpload.hidden = false;
    stopCameraScanner();
  } else if (targetTab === 'camera') {
    tabCamera.classList.add('active');
    tabCamera.setAttribute('aria-selected', 'true');
    panelCamera.classList.add('active');
    panelCamera.hidden = false;
  } else if (targetTab === 'paste') {
    tabPaste.classList.add('active');
    tabPaste.setAttribute('aria-selected', 'true');
    panelPaste.classList.add('active');
    panelPaste.hidden = false;
    stopCameraScanner();
  }
}

tabUpload.addEventListener('click', () => switchTab('upload'));
tabCamera.addEventListener('click', () => switchTab('camera'));
tabPaste.addEventListener('click', () => switchTab('paste'));

// File Input & Drag/Drop
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files[0]) {
    handleImageFile(e.target.files[0]);
    e.target.value = ''; // Reset input so same file can be reselected
  }
});

['dragenter', 'dragover'].forEach(eventName => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('dragover');
  });
});

['dragleave', 'drop'].forEach(eventName => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('dragover');
  });
});

dropZone.addEventListener('drop', (e) => {
  const dt = e.dataTransfer;
  if (dt && dt.files && dt.files[0]) {
    handleImageFile(dt.files[0]);
  }
});

// Camera Buttons
btnStartCamera.addEventListener('click', startCameraScanner);
btnStopCamera.addEventListener('click', stopCameraScanner);

// Clipboard Paste Handler (Ctrl+V anywhere on window or inside paste zone)
window.addEventListener('paste', (e) => {
  const clipboardData = e.clipboardData || (e.originalEvent && e.originalEvent.clipboardData);
  if (!clipboardData) return;

  const items = clipboardData.items;
  let imageFound = false;

  if (items) {
    for (let i = 0; i < items.length; i++) {
      if (items[i].type && items[i].type.indexOf('image') !== -1) {
        const blob = items[i].getAsFile();
        if (blob) {
          handleImageFile(blob, pasteError);
          imageFound = true;
          break;
        }
      }
    }
  }

  if (!imageFound) {
    // If text was pasted, check if user pasted a URL or UPI text directly
    const pastedText = clipboardData.getData ? clipboardData.getData('text') : '';
    if (pastedText && pastedText.trim().length > 0) {
      const analysis = analyzeDecodedPayload(pastedText.trim());
      renderAnalysisResults(pastedText.trim(), analysis);
    } else {
      // If the user was focused on the paste panel, show feedback
      const pastePanel = document.getElementById('panel-paste');
      if (pastePanel && !pastePanel.hidden) {
        showFeedbackError(pasteError, 'No QR code image or text found in clipboard. Please copy a QR screenshot first.');
      }
    }
  }
});

// Copy Decoded Text Button
btnCopy.addEventListener('click', async () => {
  const text = decodedTextBox.textContent;
  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
    const originalText = btnCopy.innerHTML;
    btnCopy.innerHTML = `<span>✓ Copied!</span>`;
    setTimeout(() => {
      btnCopy.innerHTML = originalText;
    }, 2000);
  } catch (err) {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btnCopy.textContent = 'Copied!';
    setTimeout(() => {
      btnCopy.textContent = 'Copy Text';
    }, 2000);
  }
});

// Reset / Scan Another Button (Standard View)
btnReset.addEventListener('click', () => {
  if (simpleResultsSection) simpleResultsSection.hidden = true;
  resultsSection.hidden = true;
  decodedTextBox.textContent = '';
  reasonsList.innerHTML = '';
  if (upiDetailsCard) upiDetailsCard.hidden = true;
  if (upiAmountInfo) upiAmountInfo.hidden = true;
  if (upiWarningBox) upiWarningBox.hidden = true;
  if (wifiDetailsCard) wifiDetailsCard.hidden = true;
  if (wifiWarningBox) wifiWarningBox.hidden = true;
  if (btnOpenLink) {
    btnOpenLink.removeAttribute('href');
    btnOpenLink.classList.remove('disabled');
    btnOpenLink.removeAttribute('aria-disabled');
    if (btnOpenLinkText) btnOpenLinkText.textContent = 'Open Link';
  }
  stopCameraScanner();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// Simple Mode Reset Button (Elderly View)
if (btnSimpleReset) {
  btnSimpleReset.addEventListener('click', () => {
    if (simpleResultsSection) simpleResultsSection.hidden = true;
    resultsSection.hidden = true;
    decodedTextBox.textContent = '';
    reasonsList.innerHTML = '';
    if (upiDetailsCard) upiDetailsCard.hidden = true;
    if (upiAmountInfo) upiAmountInfo.hidden = true;
    if (upiWarningBox) upiWarningBox.hidden = true;
    if (wifiDetailsCard) wifiDetailsCard.hidden = true;
    if (wifiWarningBox) wifiWarningBox.hidden = true;
    if (btnSimpleOpenLink) {
      btnSimpleOpenLink.removeAttribute('href');
      btnSimpleOpenLink.classList.remove('disabled');
      btnSimpleOpenLink.removeAttribute('aria-disabled');
      if (btnSimpleOpenLinkText) btnSimpleOpenLinkText.textContent = 'Open Link';
    }
    stopCameraScanner();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

// Intercept click on disabled Open Link buttons to prevent any accidental navigation
function attachOpenLinkSafetyCheck(btn) {
  if (!btn) return;
  btn.addEventListener('click', (e) => {
    if (btn.classList.contains('disabled') || btn.getAttribute('aria-disabled') === 'true' || !btn.getAttribute('href')) {
      e.preventDefault();
      e.stopPropagation();
      btn.style.animation = 'shake 0.35s ease';
      setTimeout(() => { btn.style.animation = ''; }, 350);
    }
  });
}
attachOpenLinkSafetyCheck(btnOpenLink);
attachOpenLinkSafetyCheck(btnSimpleOpenLink);

// Simple Mode "Show Full Technical Report" Button
if (btnViewDetails) {
  btnViewDetails.addEventListener('click', () => {
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

// Simple Mode Toggle Handler
function updateSimpleModeUI() {
  if (toggleSimpleMode) {
    toggleSimpleMode.checked = isSimpleMode;
  }
  if (simpleModeBanner) {
    simpleModeBanner.hidden = !isSimpleMode;
  }
  // If an analysis was already performed, re-render into the newly chosen mode
  if (lastRawData && lastAnalysis && (!simpleResultsSection.hidden || !resultsSection.hidden)) {
    renderAnalysisResults(lastRawData, lastAnalysis);
  }
}

if (toggleSimpleMode) {
  toggleSimpleMode.addEventListener('change', () => {
    isSimpleMode = toggleSimpleMode.checked;
    localStorage.setItem('qr_shield_simple_mode', isSimpleMode ? 'true' : 'false');
    updateSimpleModeUI();
  });
}

if (btnDisableSimpleMode) {
  btnDisableSimpleMode.addEventListener('click', () => {
    isSimpleMode = false;
    localStorage.setItem('qr_shield_simple_mode', 'false');
    updateSimpleModeUI();
  });
}

// Initialize Simple Mode UI on load
updateSimpleModeUI();

// Demo Test Presets Handler
document.querySelectorAll('.demo-preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const payload = btn.getAttribute('data-payload');
    if (payload) {
      stopCameraScanner();
      const analysis = analyzeDecodedPayload(payload);
      renderAnalysisResults(payload, analysis);
    }
  });
});

// Cleanup camera on unload
window.addEventListener('beforeunload', () => {
  stopCameraScanner();
});

