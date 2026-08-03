import { EmailAnalysisResult, ThreatSeverity, XAiFeature } from '../types/threat';
import { analyzeUrl } from './urlAnalyzer';
const URGENCY_PATTERNS = [
  'urgent', 'action required', 'immediate response', 'account suspended',
  'terminated within 24 hours', 'verify now', 'security alert', 'unauthorized access',
  'final notice', 'suspended', 'locked out', 'update payment method'
];
const FINANCIAL_PATTERNS = [
  'wire transfer', 'invoice overdue', 'swift code', 'payroll update', 'direct deposit',
  'bitcoin', 'crypto payout', 'remittance', 'tax refund', 'bank account details',
  'gift card', 'reimbursement'
];
const CREDENTIAL_PATTERNS = [
  'click here to login', 're-enter your password', 'verify credentials',
  'reset password link', 'office 365 login', 'microsoft account authentication',
  'confirm your pin', 'sso portal'
];
export function analyzeEmail(headersText: string, bodyText: string): EmailAnalysisResult {
  const fullText = (headersText + ' ' + bodyText).toLowerCase();
  // 1. Extract Headers
  const fromMatch = headersText.match(/From:\s*(.*?)(?:\r?\n|$)/i);
  const returnPathMatch = headersText.match(/Return-Path:\s*<?(.*?)>?(?:\r?\n|$)/i);
  const subjectMatch = headersText.match(/Subject:\s*(.*?)(?:\r?\n|$)/i);
  const spfMatch = headersText.match(/spf=(pass|fail|neutral|softfail)/i);
  const dkimMatch = headersText.match(/dkim=(pass|fail|neutral)/i);
  const dmarcMatch = headersText.match(/dmarc=(pass|fail|neutral)/i);
  const sender = fromMatch ? fromMatch[1].trim() : 'Unknown Sender';
  const returnPath = returnPathMatch ? returnPathMatch[1].trim() : 'Unknown Return Path';
  const subject = subjectMatch ? subjectMatch[1].trim() : 'No Subject';
  const spfStatus = (spfMatch ? spfMatch[1].toUpperCase() : 'FAIL') as 'PASS' | 'FAIL' | 'NEUTRAL';
  const dkimStatus = (dkimMatch ? dkimMatch[1].toUpperCase() : 'FAIL') as 'PASS' | 'FAIL' | 'NEUTRAL';
  const dmarcStatus = (dmarcMatch ? dmarcMatch[1].toUpperCase() : 'FAIL') as 'PASS' | 'FAIL' | 'NEUTRAL';
  // Extract Domains for Spoofing Check
  const extractDomain = (str: string) => {
    const match = str.match(/@([a-zA-Z0-9.-]+)/);
    return match ? match[1].toLowerCase() : '';
  };
    const senderDomain = extractDomain(sender);
  const returnDomain = extractDomain(returnPath);
  const spoofedSender = senderDomain && returnDomain ? (senderDomain !== returnDomain) : true;
  // 2. Body & Header NLP Triggers
  const urgentKeywordsFound = URGENCY_PATTERNS.filter(p => fullText.includes(p));
  const financialTriggersFound = FINANCIAL_PATTERNS.filter(p => fullText.includes(p));
  const credentialHarvestingFlags = CREDENTIAL_PATTERNS.filter(p => fullText.includes(p));
  // 3. Extract Links
  const urlRegex = /(https?:\/\/[^\s"'<>]+)/gi;
  const extractedUrls = bodyText.match(urlRegex) || [];
  const extractedLinks = extractedUrls.map(url => {
    const result = analyzeUrl(url);
    return {
      url,
      isMalicious: result.isPhishing || result.score > 40
    };
  });
 const maliciousLinkCount = extractedLinks.filter(l => l.isMalicious).length;
  // 4. Calculate Risk Score
  let score = 0;
  const xaiFeatures: XAiFeature[] = [];
  // Feature: Sender Authentication & Spoofing
  if (spfStatus === 'FAIL' || dkimStatus === 'FAIL' || dmarcStatus === 'FAIL' || spoofedSender) {
    score += 35;
    xaiFeatures.push({
      name: 'Email Header & Domain Spoofing',
      score: 90,
      weight: 35,
      status: 'DANGER',
      description: `Header validation failed (SPF: ${spfStatus}, DKIM: ${dkimStatus}, DMARC: ${dmarcStatus}). Sender domain '${senderDomain}' mismatch with Return-Path '${returnDomain}'.`
    });
  } else {
    xaiFeatures.push({
      name: 'SPF / DKIM / DMARC Header Alignment',
      score: 10,
      weight: 20,
      status: 'SAFE',
      description: 'Email headers passed standard SPF, DKIM, and DMARC alignment checks.'
    });
  } // Feature: Malicious Links in Body
  if (maliciousLinkCount > 0) {
    score += 35;
    xaiFeatures.push({
      name: 'Embedded Malicious / Phishing Links',
      score: 95,
      weight: 35,
      status: 'DANGER',
      description: `Detected ${maliciousLinkCount} high-risk or deceptive URLs in email body.`
    });
  }
  // Feature: NLP Urgency & Psychological Coercion
  if (urgentKeywordsFound.length > 0) {
    score += 15;
    xaiFeatures.push({
      name: 'NLP Urgency & Psychological Pressure',
      score: 75,
      weight: 15,
      status: 'WARNING',
      description: `Found ${urgentKeywordsFound.length} high-urgency pressure terms (${urgentKeywordsFound.slice(0, 3).join(', ')}).`
    });
  }
  // Feature: Financial / Credential Triggers
  if (financialTriggersFound.length > 0 || credentialHarvestingFlags.length > 0) {
    score += 15;
    xaiFeatures.push({
      name: 'Credential & Wire Transfer Intent',
      score: 80,
      weight: 15,
      status: 'WARNING',
      description: `Detected financial or credential harvesting triggers (${[...financialTriggersFound, ...credentialHarvestingFlags].slice(0, 3).join(', ')}).`
       });
  }
  score = Math.min(100, Math.max(0, score));
  // Determine Severity
  let severity: ThreatSeverity = 'SAFE';
  if (score >= 75) severity = 'CRITICAL';
  else if (score >= 50) severity = 'HIGH';
  else if (score >= 25) severity = 'MEDIUM';
  else if (score >= 10) severity = 'LOW';
  // Intent Category
  let intentCategory: EmailAnalysisResult['intentCategory'] = 'Legitimate Email';
  if (financialTriggersFound.length > 0 && spoofedSender) {
    intentCategory = 'Business Email Compromise (BEC)';
  } else if (credentialHarvestingFlags.length > 0 || maliciousLinkCount > 0) {
    intentCategory = 'Credential Harvesting';
  } else if (financialTriggersFound.length > 0) {
    intentCategory = 'Financial Fraud';
  } else if (score >= 60) {
    intentCategory = 'Malware Delivery';
  }
  const remediationSteps: string[] = [];
  if (score >= 50) {
    remediationSteps.push('Quarantine message in Exchange/Google Workspace Mail Gateway immediately.');
      remediationSteps.push('Add sender domain and relay IP address to global blocklist.');
    remediationSteps.push('Trigger password reset for target user if links were clicked.');
    remediationSteps.push('Purge identical messages across all employee inboxes.');
  } else {
    remediationSteps.push('Email appears clean. Verify sender identity if unexpected attachments are received.');
  }
  return {
    subject,
    sender,
    returnPath,
    spfStatus,
    dkimStatus,
    dmarcStatus,
    spoofedSender,
    urgentKeywordsFound,
    financialTriggersFound,
    credentialHarvestingFlags,
    extractedLinks,
    overallScore: score,
    severity,
    intentCategory,
    xaiFeatures,
    remediationSteps,
    analyzedAt: new Date().toISOString()
  };
}
