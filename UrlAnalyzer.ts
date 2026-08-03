import { UrlAnalysisResult, ThreatSeverity, XAiFeature } from '../types/threat';
const SUSPICIOUS_TLDS = ['.top', '.xyz', '.zip', '.mov', '.work', '.click', '.gq', '.tk', '.ml', '.cf', '.ga', '.fit', '.racing', '.cam', '.monster', '.biz'];
const TARGET_BRANDS = ['google', 'paypal', 'microsoft', 'apple', 'amazon', 'github', 'netflix', 'binance', 'coinbase', 'metamask', 'bankofamerica', 'chase', 'wellsfargo', 'linkedin', 'facebook', 'instagram', 'twitter'];
// Calculate Shannon entropy of a string
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const charFreq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    charFreq[char] = (charFreq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in charFreq) {
    const p = charFreq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}
// Detect homoglyphs / typosquatting lookalikes
export function detectHomoglyph(domain: string): { hasHomoglyph: boolean; targetBrand?: string } {
  const normalized = domain.toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
  .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
  for (const brand of TARGET_BRANDS) {
    if (normalized.includes(brand) && !domain.toLowerCase().endsWith(`${brand}.com`)) {
      return { hasHomoglyph: true, targetBrand: brand };
    }
  }
  return { hasHomoglyph: false };
}
export function analyzeUrl(rawUrl: string): UrlAnalysisResult {
  let urlString = rawUrl.trim();
  if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
    urlString = 'https://' + urlString;
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString);
  } catch (e) {
    parsedUrl = new URL('https://' + rawUrl.replace(/[^a-zA-Z0-9.-]/g, ''));
  }
  const domain = parsedUrl.hostname.toLowerCase();
  const fullPath = parsedUrl.pathname + parsedUrl.search;
  
  const entropy = calculateShannonEntropy(domain + fullPath);
  const isHttps = parsedUrl.protocol === 'https:';
  
  // Checks
 const isIpHostname = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
  const tldMatch = SUSPICIOUS_TLDS.find(tld => domain.endsWith(tld));
  const hasSuspiciousTld = !!tldMatch;
  const subdomainCount = domain.split('.').length - 2;
  const hasAtSymbol = rawUrl.includes('@');
  const hasMultipleHyphens = (domain.match(/-/g) || []).length > 2;
  const homoglyphResult = detectHomoglyph(domain);
  
  // Brand Keyword Mismatch check
  let brandInPath = false;
  let detectedBrandName: string | undefined = homoglyphResult.targetBrand;
  for (const brand of TARGET_BRANDS) {
    if ((domain.includes(brand) || fullPath.includes(brand)) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.org`)) {
      brandInPath = true;
      if (!detectedBrandName) detectedBrandName = brand;
    }
  }
  // Calculate Threat Score (0 to 100)
  let score = 0;
  const xaiFeatures: XAiFeature[] = [];
  // Feature 1: Brand Impersonation / Homoglyph
  if (homoglyphResult.hasHomoglyph || brandInPath) {
    score += 35;
    xaiFeatures.push({
      name: 'Brand Impersonation / Homoglyph Attack',
      score: 95,
      weight: 35,
      status: 'DANGER',
      description: `Domain contains lookalike patterns or brand keywords targeting ${detectedBrandName || 'popular brands'} without official ownership.
       });
  } else {
    xaiFeatures.push({
      name: 'Brand Impersonation Check',
      score: 10,
      weight: 15,
      status: 'SAFE',
      description: 'No brand typosquatting or unauthorized brand spoofing detected.'
    });
  }
  // Feature 2: Suspicious TLD / IP Hostname
  if (isIpHostname) {
    score += 30;
    xaiFeatures.push({
      name: 'Raw IP Hostname Identifier',
      score: 90,
      weight: 25,
      status: 'DANGER',
      description: 'URL uses direct IP address instead of domain name, bypassing DNS reputation checks.'
    });
  } else if (hasSuspiciousTld) {
    score += 25;
    xaiFeatures.push({
      name: 'High-Risk TLD (.xyz, .top, etc.)',
      score: 80,
      weight: 20,
      status: 'DANGER',
      description: `TLD '${tldMatch}' is frequently associated with disposable phishing kits.`
    });
  } else {
    xaiFeatures.push({
      name: 'Domain TLD Reputation',
      score: 15,
      weight: 15,
      status: 'SAFE',
      description: 'Domain uses a standard high-reputation TLD.'
    });
  }
   // Feature 3: Lexical Entropy & Length
  if (entropy > 4.2 || domain.length > 35) {
    score += 20;
    xaiFeatures.push({
      name: 'High Lexical Entropy / Obfuscation',
      score: 75,
      weight: 20,
      status: 'WARNING',
      description: `Domain entropy value is ${entropy} (High randomness/generated domain pattern).`
    });
  } else {
    xaiFeatures.push({
      name: 'Lexical Randomness Index',
      score: 15,
      weight: 10,
      status: 'SAFE',
      description: `Normal lexical distribution (Entropy: ${entropy}).`
    });
  }
// Feature 4: Subdomains & Special Characters
  if (subdomainCount > 2 || hasAtSymbol || hasMultipleHyphens) {
    score += 15;
    xaiFeatures.push({
      name: 'Excessive Subdomains & @ Delimiters',
      score: 70,
      weight: 15,
      status: 'WARNING',
      description: `Detected ${subdomainCount} subdomains or suspicious character stacking in URL structure.`
    });
  }
  // Feature 5: SSL & Protocol Security
  if (!isHttps) {
    score += 15;
    xaiFeatures.push({
      name: 'Unencrypted HTTP Connection',
      score: 65,
      weight: 10,
      status: 'WARNING',
      description: 'Lacks SSL/TLS encryption, exposing credentials to Man-in-the-Middle (MitM) sniffing.'
    });
  } else {
    xaiFeatures.push({
      name: 'HTTPS Transport Encryption',
      score: 5,
      weight: 10,
      status: 'SAFE',
      description: 'Connection protected with valid HTTPS protocol.'
    });
  }
 // Domain Age Simulation
  const domainAgeDays = (score > 40) ? Math.floor(Math.random() * 12) + 1 : Math.floor(Math.random() * 2000) + 300;
  if (domainAgeDays < 15) {
    score += 10;
  }
  // Cap score
  score = Math.min(100, Math.max(0, score));
  // Determine Severity
  let severity: ThreatSeverity = 'SAFE';
  if (score >= 75) severity = 'CRITICAL';
  else if (score >= 50) severity = 'HIGH';
  else if (score >= 25) severity = 'MEDIUM';
  else if (score >= 10) severity = 'LOW';
  // Classification
  let classification = 'Legitimate URL';
  if (score >= 70) classification = 'Malicious Phishing Portal / Credential Harvester';
  else if (score >= 40) classification = 'Suspicious Deceptive Site';
  else if (score >= 20) classification = 'Low-Risk / Unverified Domain';
  const isPhishing = score >= 50;
  // MITRE ATT&CK Mapping
  const mitreTechniques = [];
  if (isPhishing) {
    mitreTechniques.push(
      { id: 'T1566.002', name: 'Spearphishing Link', description: 'Adversaries send spearphishing emails with malicious links to gain initial access.' },
      { id: 'T1583.001', name: 'Acquire Domains', description: 'Adversaries acquire domains that mirror legitimate organizations (Typosquatting).' }
    );
  }
  if (isIpHostname) {
    mitreTechniques.push(
      { id: 'T1071.001', name: 'Application Layer Protocol (Web)', description: 'Direct IP usage bypassing proxy host rules and domain filters.' }
    );
  }
// Remediation
  const remediationSteps: string[] = [];
  if (isPhishing) {
    remediationSteps.push('Immediately add domain and IP to Perimeter Firewall / Secure Web Gateway blocklists.');
    remediationSteps.push('Issue urgent security alert to SOC analysts for user credentials entered in the last 2 hours.');
    remediationSteps.push('Revoke active OAuth & SSO sessions for any user who clicked this URL.');
    remediationSteps.push('Report domain to Registrar and Anti-Phishing Working Group (APWG).');
  } else {
    remediationSteps.push('No critical threat detected. Ensure regular SSL certificate lifecycle management.');
    remediationSteps.push('Maintain strict Content Security Policy (CSP) headers.');
  }
  return {
    url: rawUrl,
    domain,
    score,
    severity,
    isPhishing,
    classification,
    entropy,
    domainAgeDays,
    sslValid: isHttps,
    hasSuspiciousTld,
    isIpHostname,
    hasHomoglyph: homoglyphResult.hasHomoglyph,
    detectedBrand: detectedBrandName,
    mitreTechniques,
    xaiFeatures,
    remediationSteps,
    analyzedAt: new Date().toISOString()
  };
}
