import React, { useState, useEffect } from 'react';
import { analyzeUrl } from '../services/urlAnalyzer';
import { UrlAnalysisResult } from '../types/threat';
import { ExplainableAI } from './ExplainableAI';
import { Search, AlertTriangle, ShieldCheck, Globe, Lock, Cpu, ExternalLink, Zap, Copy, Check } from 'lucide-react';
const PRESET_URLS = [
  { label: 'Phishing PayPal Homoglypt', url: 'https://paypal-update-login-security.top/verify?user=admin' },
  { label: 'Homograph Google Lookalike', url: 'https://g00gle-account-verification.xyz/auth' },
  { label: 'Suspicious Raw IP', url: 'http://185.220.101.4/office365/login.php' },
  { label: 'Legitimate Official Domain', url: 'https://github.com/shivanshutiwari481' },
];
export const UrlScanner: React.FC<{ initialUrl?: string }> = ({ initialUrl }) => {
  const [inputUrl, setInputUrl] = useState(initialUrl || 'https://paypal-update-login-security.top/verify?user=admin');
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [copied, setCopied] = useState(false);
  const handleScan = (targetUrl?: string) => {
    const urlToScan = targetUrl || inputUrl;
    if (!urlToScan) return;
    setIsScanning(true);
    setTimeout(() => {
      const res = analyzeUrl(urlToScan);
      setResult(res);
      setIsScanning(false);
    }, 600);
  };
  useEffect(() => {
    if (initialUrl) {
      setInputUrl(initialUrl);
      handleScan(initialUrl);
    } else {
      handleScan('https://paypal-update-login-security.top/verify?user=admin');
    }
  }, [initialUrl]);
  return (
    <div className="space-y-6">
      {/* Input Search Box */}
      <div className="glass-panel-glow rounded-xl p-6">
        <div className="flex items-center space-x-2 mb-3">
          <Search className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
            AI URL Phishing & Homograph Analyzer
          </h2>
        </div>
        <p className="text-xs text-slate-400 font-mono mb-4">
          Enter target URL or select preset threat vectors to inspect lexical entropy, domain homoglyphs, brand impersonation, and SSL parameters.
        </p>
         <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="e.g. https://paypal-security-update.top/login"
              className="w-full px-4 py-3 bg-slate-900/90 border border-slate-700 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 rounded-lg text-sm font-mono text-cyan-200 outline-none transition-all placeholder:text-slate-600"
            />
                    <Globe className="absolute right-3 top-3.5 w-4 h-4 text-slate-500 pointer-events-none" />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={isScanning}
            className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-mono font-semibold text-sm rounded-lg shadow-md shadow-cyan-900/50 flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <Zap className="w-4 h-4 animate-spin text-cyan-300" />
                <span>EXTRACTING FEATURES...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>RUN AI SCAN</span>
              </>
            )}
          </button>
        </div>
        {/* Quick Presets */}
        <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-slate-800">
          <span className="text-xs font-mono text-slate-400 flex items-center mr-2">Sample IOC Vectors:</span>
          {PRESET_URLS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => {
                setInputUrl(preset.url);
                handleScan(preset.url);
              }}
                className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800/80 hover:bg-cyan-950/80 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-slate-300 transition-all"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>
      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6">
          {/* Main Risk Score Card */}
          <div className={`rounded-xl p-6 border transition-all ${
            result.severity === 'CRITICAL' || result.severity === 'HIGH'
              ? 'glass-panel-danger'
              : result.severity === 'MEDIUM'
              ? 'glass-panel border-amber-500/30'
              : 'glass-panel-glow'
          }`}>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
              {/* Left Details */}
              <div className="space-y-2 flex-1">
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 text-xs font-mono font-bold rounded-full border ${
                    result.severity === 'CRITICAL'
                      ? 'bg-pink-950 text-pink-300 border-pink-500'
                      : result.severity === 'HIGH'
                      ? 'bg-red-950 text-red-300 border-red-500'
                      : result.severity === 'MEDIUM'
                      ? 'bg-amber-950 text-amber-300 border-amber-500'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-500'
                  }`}>
                      {result.severity} THREAT SEVERITY
                  </span>
                  <span className="text-xs font-mono text-slate-400">Classified as:</span>
                  <span className="text-xs font-mono text-cyan-300 font-bold">{result.classification}</span>
                </div>
                <div className="break-all font-mono text-sm text-slate-100 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-500">Target URL:</span>{' '}
                  <span className="text-pink-400 font-semibold">{result.url}</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Domain:</span>
                    <span className="text-slate-200 font-semibold truncate block">{result.domain}</span>
                  </div>
                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Shannon Entropy:</span>
                    <span className={`font-semibold ${result.entropy > 4.2 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {result.entropy} / 8.0
                       </span>
                  </div>
                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">SSL Certificate:</span>
                    <span className={`font-semibold ${result.sslValid ? 'text-emerald-400' : 'text-pink-400'}`}>
                      {result.sslValid ? 'HTTPS Valid' : 'Insecure HTTP'}
                    </span>
                  </div>
                  <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Domain Age Sim:</span>
                    <span className={`font-semibold ${result.domainAgeDays < 30 ? 'text-pink-400' : 'text-cyan-400'}`}>
                      {result.domainAgeDays} Days
                    </span>
                  </div>
                </div>
              </div>
              {/* Right Gauge */}
              <div className="flex flex-col items-center justify-center p-4 bg-slate-900/80 rounded-xl border border-slate-800 shrink-0 min-w-[180px]">
                <span className="text-xs font-mono text-slate-400 mb-1">AI Risk Score</span>
                <div className={`text-4xl font-mono font-extrabold ${
                  result.score >= 70 ? 'text-pink-500 text-danger-glow' : result.score >= 40 ? 'text-amber-400' : 'text-emerald-400 text-cyber-glow'
     }`}>
                  {result.score}<span className="text-sm font-normal text-slate-500">/100</span>
                </div>
                <div className="w-32 bg-slate-800 h-2 rounded-full mt-3 overflow-hidden border border-slate-700">
                  <div
                    className={`h-full rounded-full transition-all ${
                      result.score >= 70 ? 'bg-pink-500' : result.score >= 40 ? 'bg-amber-400' : 'bg-emerald-400'
                    }`}
                    style={{ width: `${result.score}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>
          {/* Explainable AI (XAI) Section */}
          <ExplainableAI features={result.xaiFeatures} overallScore={result.score} />
          {/* MITRE ATT&CK & Remediation Playbook */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* MITRE ATT&CK Mapping */}
            <div className="glass-panel rounded-xl p-6 space-y-4">
              <h3 className="text-sm font-mono font-bold text-cyan-300 flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span>MITRE ATT&CK® TTP MAPPING</span>
              </h3>
              {result.mitreTechniques.length > 0 ? (
                <div className="space-y-3 font-mono text-xs">
                  {result.mitreTechniques.map((tech, idx) => (
                    <div key={idx} className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
                      <div className="flex items-center justify-between">
                        <span className="text-pink-400 font-bold">{tech.id}</span>
                        <span className="text-slate-300 font-semibold">{tech.name}</span>
                      </div>
                      <p className="text-slate-400 text-[11px] mt-1">{tech.description}</p>
                    </div>
                  ))}
                </div>
           ) : (
                <p className="text-xs font-mono text-slate-400">No malicious TTP match triggered.</p>
              )}
            </div>
            {/* Incident Remediation Playbook */}
            <div className="glass-panel rounded-xl p-6 space-y-4">
              <h3 className="text-sm font-mono font-bold text-emerald-400 flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>AUTOMATED SOAR REMEDIATION STEPS</span>
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {result.remediationSteps.map((step, idx) => (
                  <div key={idx} className="flex items-start space-x-2 p-2.5 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-cyan-400 font-bold shrink-0">{idx + 1}.</span>
                    <span className="text-slate-300">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
