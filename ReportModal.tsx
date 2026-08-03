import React, { useState } from 'react';
import { X, FileText, Copy, Check, Download, Github } from 'lucide-react';
interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
}
export const ReportModal: React.FC<ReportModalProps> = ({ isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);
  if (!isOpen) return null;
  const reportMarkdown = `# FORENSIC INCIDENT AUDIT REPORT - AEGIS CYBER AI
**System Version:** v2.4 (Enterprise Edition)
**Report Date:** ${new Date().toUTCString()}
**Lead SOC Developer / Maintainer:** shivanshutiwari481 (https://github.com/shivanshutiwari481)
---
## 1. Executive Summary
During real-time threat intelligence monitoring, Aegis AI detected multi-vector phishing indicators including brand homoglyph lookalikes, email header SPF/DMARC spoofing, and high-entropy executable scripts.
## 2. Analyzed Indicators of Compromise (IOCs)
- **Target URL Vector:** \`https://paypal-update-login-security.top/verify?user=admin\`
  - **Risk Score:** 85/100 (CRITICAL)
  - **Classification:** Malicious Phishing Portal / Credential Harvester
  - **Entropy Value:** 4.45 / 8.0
  - **MITRE TTP Mapping:** T1566.002 (Spearphishing Link), T1583.001 (Acquire Domains)
- **Email Spoofing Header:** \`no-reply@office365-verify-portal.top\`
  - **SPF Status:** FAIL | **DKIM:** FAIL | **DMARC:** FAIL
- **Payload Hash:** \`a1b2c3d4e5f67890123456789abcdef0\` (SHA-256)
## 3. Explainable AI (XAI) Feature Breakdown
1. **Brand Impersonation & Homoglyph Attack (Weight: 35%):** Lookalike patterns targeting PayPal domain structure.
2. **High-Risk TLD (.top) (Weight: 25%):** TLD associated with automated phishing kits.
3. **Unencrypted Transport (Weight: 15%):** Lack of TLS certificate validation.

## 4. Recommended Automated Remediation (SOAR)
1. Immediately block \`paypal-update-login-security.top\` on perimeter Secure Web Gateway (SWG) and DNS Sinkhole.
2. Force credential reset and revoke active SSO sessions for affected users.
3. Submit IOC signature to global threat intelligence sharing feed.
---
*Generated automatically by Aegis AI Phishing & Cyber Threat Analysis System.*
*Repository & Author: [shivanshutiwari481](https://github.com/shivanshutiwari481)*
`;
 const handleCopy = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  const handleDownload = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Aegis_Forensic_Incident_Report_${Date.now()}.md`;
    a.click();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="glass-panel-glow w-full max-w-3xl rounded-xl p-6 relative max-h-[90vh] flex flex-col font-mono text-xs">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              FORENSIC INCIDENT AUDIT REPORT GENERATOR
            </h3>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-slate-100 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Developer Credit */}
        <div className="my-3 p-2.5 rounded bg-slate-900/90 border border-slate-800 flex items-center justify-between text-[11px]">
          <span className="text-slate-400">GitHub Developer:</span>
          <a
            href="https://github.com/shivanshutiwari481"
            target="_blank"
            rel="noreferrer"
            className="text-cyan-300 font-bold hover:underline flex items-center gap-1"
          >
            <span>shivanshutiwari481</span>
            <Github className="w-3.5 h-3.5" />
          </a>
        </div>
        {/* Markdown View */}
        <div className="flex-1 overflow-y-auto my-2 p-4 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
          {reportMarkdown}
        </div>
        {/* Footer Actions */}
        <div className="pt-4 border-t border-slate-800 flex items-center justify-end space-x-3">
          <button
            onClick={handleCopy}
            className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold flex items-center space-x-1.5 transition-all"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-cyan-400" />}
            <span>{copied ? 'COPIED TO CLIPBOARD' : 'COPY MARKDOWN'}</span>
          </button>
          <button
            onClick={handleDownload}
            className="px-4 py-2 rounded bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold flex items-center space-x-1.5 shadow-md shadow-cyan-900/50 transition-all"
          >
             <Download className="w-4 h-4" />
            <span>DOWNLOAD .MD REPORT</span>
          </button>
        </div>
      </div>
    </div>
  );
};
