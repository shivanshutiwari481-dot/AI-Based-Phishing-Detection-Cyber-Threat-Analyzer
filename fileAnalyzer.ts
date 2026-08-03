import { FileAnalysisResult, ThreatSeverity, XAiFeature } from '../types/threat';
import { calculateShannonEntropy } from './urlAnalyzer';
const DANGEROUS_EXTENSIONS = ['.exe', '.vbs', '.js', '.bat', '.ps1', '.cmd', '.scr', '.hta', '.jar', '.dll', '.iso', '.lnk'];
const SUSPICIOUS_CODE_KEYWORDS = [
  'eval(', 'exec(', 'powershell -nop -w hidden', 'WScript.Shell',
  'VirtualAlloc', 'CreateRemoteThread', 'URLDownloadToFile', 'base64_decode',
  'cmd.exe /c', 'Net.WebClient', 'Invoke-Expression', 'bypass-executionpolicy'
];
// Helper to convert ArrayBuffer to Hex String
function buf2hex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
// Generate simple mock MD5 for client display
function simpleHash(str: string, seed = 0): string {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
   h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hex = (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
  return hex.padStart(32, 'e');
}
export async function analyzeFile(file: File): Promise<FileAnalysisResult> {
  const arrayBuffer = await file.arrayBuffer();
  const fileText = new TextDecoder('utf-8', { fatal: false }).decode(arrayBuffer);
  
  // Calculate SHA-256 via Web Crypto
  let sha256 = '';
  try {
    const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
    sha256 = buf2hex(hashBuf);
  } catch (e) {
    sha256 = simpleHash(file.name + file.size) + simpleHash(file.name, 42);
  }
  
  const md5 = simpleHash(file.name + file.size);
  const entropy = calculateShannonEntropy(fileText.substring(0, 5000));
  
  const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
  const isDangerousExt = DANGEROUS_EXTENSIONS.includes(ext);

  // Check Suspicious Functions
  const suspiciousFunctions = SUSPICIOUS_CODE_KEYWORDS.filter(kw => fileText.includes(kw));
  // YARA Rule Simulation
  const yaraMatches: FileAnalysisResult['yaraMatches'] = [];
  if (suspiciousFunctions.includes('powershell -nop -w hidden') || suspiciousFunctions.includes('Invoke-Expression')) {
    yaraMatches.push({
      rule: 'SUSP_PowerShell_Obfuscated_Downloader',
      description: 'Matches PowerShell execution with hidden window flags and inline downloader script.',
      severity: 'CRITICAL'
    });
  }
  if (suspiciousFunctions.includes('VirtualAlloc') || suspiciousFunctions.includes('CreateRemoteThread')) {
    yaraMatches.push({
      rule: 'MALW_Process_Injection_API',
      description: 'Detects Win32 API primitives commonly used for reflective DLL injection & shellcode execution.',
      severity: 'CRITICAL'
    });
  }if (entropy > 6.8) {
    yaraMatches.push({
      rule: 'SUSP_High_Entropy_Packed_Payload',
      description: 'File entropy > 6.8 indicates encrypted payload or packed malware binary.',
      severity: 'HIGH'
    });
  }
  // Calculate Risk Score
  let score = 0;
  const xaiFeatures: XAiFeature[] = [];
  if (isDangerousExt) {
    score += 35;
    xaiFeatures.push({
      name: 'High-Risk File Extension',
      score: 85,
      weight: 35,
      status: 'DANGER',
      description: `Extension '${ext}' is capable of direct command execution on client OS.`
    });
    } else {
    xaiFeatures.push({
      name: 'File Format Verification',
      score: 10,
      weight: 20,
      status: 'SAFE',
      description: `Standard file extension '${ext}'.`
    });
  }
  if (yaraMatches.length > 0) {
    score += 40;
    xaiFeatures.push({
      name: 'YARA Signature Matches',
      score: 95,
      weight: 30,
      status: 'DANGER',
      description: `Triggered ${yaraMatches.length} YARA signatures (${yaraMatches.map(m => m.rule).join(', ')}).`
    });
  }
  if (entropy > 6.5) {
    score += 20;
    xaiFeatures.push({
      name: 'High Binary Entropy (Packing/Encryption)',
      score: 80,
      weight: 20,
      status: 'WARNING',
      description: `Shannon entropy is ${entropy} out of 8.0, signaling payload packing or obfuscation.`
    });
     } else {
    xaiFeatures.push({
      name: 'Entropy & Density Analysis',
      score: 15,
      weight: 15,
      status: 'SAFE',
      description: `Normal entropy level (${entropy}/8.0).`
    });
  }
  score = Math.min(100, Math.max(0, score));
  let severity: ThreatSeverity = 'SAFE';
  if (score >= 75) severity = 'CRITICAL';
  else if (score >= 50) severity = 'HIGH';
  else if (score >= 25) severity = 'MEDIUM';
  else if (score >= 10) severity = 'LOW';
  const remediationSteps: string[] = [];
  if (score >= 40) {
    remediationSteps.push('Quarantine file in isolated EDR sandbox for dynamic detonation.');
    remediationSteps.push(`Block SHA-256 hash ${sha256.substring(0, 16)}... on endpoint agent.`);
    remediationSteps.push('Submit file sample to SOC threat intelligence repository.');
  } else {
    remediationSteps.push('File analysis shows clean indicators of compromise.');
  }
   return {
    filename: file.name,
    sizeBytes: file.size,
    fileType: file.type || ext.replace('.', '').toUpperCase() || 'UNKNOWN',
    entropy,
    md5,
    sha256,
    riskScore: score,
    severity,
    detectedSignatures: yaraMatches.map(m => m.rule),
    yaraMatches,
    suspiciousFunctions,
    xaiFeatures,
    remediationSteps,
    analyzedAt: new Date().toISOString()
  };
}
