import { useState, useEffect } from 'react';
import { analyzeEmail } from '../services/emailAnalyzer';
import { EmailAnalysisResult } from '../types/threat';
import { ExplainableAI } from './ExplainableAI';
import { Mail, CheckCircle2, XCircle, AlertTriangle, Send, FileCode, ShieldAlert, Cpu } from 'lucide-react';

const SAMPLE_EMAILS = [
  {
    name: 'Credential Harvesting Phish (O365)',
    headers: `From: Security Team <no-reply@office365-verify-portal.top>\nReturn-Path: <bounce@phish-server.xyz>\nSubject: URGENT: Your Office 365 Password Expires Today\nAuthentication-Results: spf=fail dkim=fail dmarc=fail`,
    body: `Dear Employee,\n\nYour Office 365 account password will expire in 2 hours. Failure to update your credentials will result in immediate account suspension.\n\nClick here to login and extend your access: https://paypal-update-login-security.top/verify?user=admin\n\nRegards,\nIT Security Desk`
  },
  {
    name: 'BEC Wire Transfer Fraud',
    headers: `From: CEO John Smith <ceo@company-exec-pay.com>\nReturn-Path: <hacker@bulletproof-relay.net>\nSubject: Urgent Wire Transfer Request - Confidential\nAuthentication-Results: spf=fail dkim=neutral dmarc=fail`,
    body: `Hi Finance Team,\n\nI am currently in an urgent meeting with our acquisition partners. Please process a SWIFT wire transfer of $45,800 to the following vendor account immediately before 4 PM today:\n\nBank Account Details:\nRouting: 021000021\nAccount: 9840129311\n\nDo not call me as I am unable to answer. Confirm once processed.\n\nBest,\nJohn Smith`
  },
  {
    name: 'Legitimate Corporate Email',
    headers: `From: HR Team <hr@github.com>\nReturn-Path: <hr@github.com>\nSubject: Monthly Newsletter & Team Updates\nAuthentication-Results: spf=pass dkim=pass dmarc=pass`,
    body: `Hi Team,\n\nPlease find the updates for this month on our portal. Have a great weekend!\n\nBest regards,\nHR Department`
  }
];

export const EmailScanner = () => {
  const [headers, setHeaders] = useState(SAMPLE_EMAILS[0].headers);
  const [body, setBody] = useState(SAMPLE_EMAILS[0].body);
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const res = analyzeEmail(headers, body);
      setResult(res);
      setIsScanning(false);
    }, 500);
  };

  useEffect(() => {
    handleScan();
  }, []);

  return (
    <div className="space-y-6">
      {/* Input Header & Body Form */}
      <div className="glass-panel-glow rounded-xl p-6">
        <div className="flex items-center space-x-2 mb-3">
          <Mail className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
            EMAIL HEADER ALIGNMENT & NLP INTENT INSPECTOR
          </h2>
        </div>
        <p className="text-xs text-slate-400 font-mono mb-4">
          Paste email headers and body content to analyze SPF/DKIM/DMARC alignment, spoofed sender domains, and psychological coercion NLP flags.
        </p>

        {/* Sample Selectors */}
        <div className="flex flex-wrap gap-2 mb-4">
          <span className="text-xs font-mono text-slate-400 self-center">Load Preset Phishing Email:</span>
          {SAMPLE_EMAILS.map((sample, idx) => (
            <button
              key={idx}
              onClick={() => {
                setHeaders(sample.headers);
                setBody(sample.body);
                setTimeout(() => {
                  const res = analyzeEmail(sample.headers, sample.body);
                  setResult(res);
                }, 100);
              }}
              className="px-3 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-slate-300 transition-all"
            >
              {sample.name}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Raw Headers Input */}
          <div className="space-y-2">
            <label className="text-xs font-mono text-cyan-300 flex items-center gap-1">
              <FileCode className="w-3.5 h-3.5" />
              Raw Email Headers (From, Return-Path, Auth-Results):
            </label>
            <textarea
              rows={6}
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              className="w-full p-3 bg-slate-900/90 border border-slate-700 focus:border-cyan-400 rounded-lg text-xs font-mono text-cyan-100 outline-none resize-none"
            />
          </div>

          {/* Email Body Input */}
          <div className="space-y-2">
            <label className="text-xs font-mono text-cyan-300 flex items-center gap-1">
              <Mail className="w-3.5 h-3.5" />
              Email Body Text & Extracted Links:
            </label>
            <textarea
              rows={6}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="w-full p-3 bg-slate-900/90 border border-slate-700 focus:border-cyan-400 rounded-lg text-xs font-mono text-slate-200 outline-none resize-none"
            />
          </div>
        </div>

        <button
          onClick={handleScan}
          disabled={isScanning}
          className="mt-4 px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-mono font-semibold text-xs rounded-lg shadow-md shadow-cyan-900/50 flex items-center space-x-2 transition-all"
        >
          <Send className="w-4 h-4" />
          <span>INSPECT EMAIL THREAT VECTORS</span>
        </button>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Main Status Header */}
          <div className={`rounded-xl p-6 border transition-all ${
            result.severity === 'CRITICAL' || result.severity === 'HIGH'
              ? 'glass-panel-danger'
              : 'glass-panel-glow'
          }`}>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
              <div className="space-y-2 flex-1">
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 text-xs font-mono font-bold rounded-full border ${
                    result.severity === 'CRITICAL' ? 'bg-pink-950 text-pink-300 border-pink-500' : 'bg-emerald-950 text-emerald-300 border-emerald-500'
                  }`}>
                    {result.severity} THREAT
                  </span>
                  <span className="text-xs font-mono text-slate-400">Intent Category:</span>
                  <span className="text-xs font-mono text-pink-300 font-bold">{result.intentCategory}</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs pt-2">
                  <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">SPF Alignment:</span>
                    <span className={`font-bold ${result.spfStatus === 'PASS' ? 'text-emerald-400' : 'text-pink-400'}`}>
                      {result.spfStatus}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">DKIM Signature:</span>
                    <span className={`font-bold ${result.dkimStatus === 'PASS' ? 'text-emerald-400' : 'text-pink-400'}`}>
                      {result.dkimStatus}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">DMARC Policy:</span>
                    <span className={`font-bold ${result.dmarcStatus === 'PASS' ? 'text-emerald-400' : 'text-pink-400'}`}>
                      {result.dmarcStatus}
                    </span>
                  </div>
                </div>

                {result.spoofedSender && (
                  <div className="p-3 rounded bg-pink-950/60 border border-pink-500/40 text-pink-300 font-mono text-xs flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-pink-400 shrink-0" />
                    <span>SPOOFED SENDER ALERT: Display From domain does not match Return-Path SMTP envelope.</span>
                  </div>
                )}
              </div>

              {/* Score Display */}
              <div className="flex flex-col items-center justify-center p-4 bg-slate-900/80 rounded-xl border border-slate-800 shrink-0 min-w-[170px]">
                <span className="text-xs font-mono text-slate-400 mb-1">Phishing Score</span>
                <div className={`text-4xl font-mono font-extrabold ${result.overallScore >= 50 ? 'text-pink-400 text-danger-glow' : 'text-emerald-400'}`}>
                  {result.overallScore}<span className="text-sm font-normal text-slate-500">/100</span>
                </div>
              </div>
            </div>
          </div>

          <ExplainableAI features={result.xaiFeatures} overallScore={result.overallScore} />
        </div>
      )}
    </div>
  );
};
