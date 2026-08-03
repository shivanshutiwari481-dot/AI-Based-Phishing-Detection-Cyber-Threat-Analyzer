import React, { useState } from 'react';
import { scanBatchIocs } from '../services/iocScanner';
import { IocBatchResult } from '../types/threat';
import { Activity, Download, ListFilter, Search } from 'lucide-react';

const SAMPLE_BATCH = `paypal-update-login-security.top
185.220.101.4
a1b2c3d4e5f67890123456789abcdef0
http://185.220.101.4/office365/login.php
https://github.com/shivanshutiwari481-dot
45.154.255.89
g00gle-account-verification.xyz`;

export const BatchScanner: React.FC = () => {
  const [inputText, setInputText] = useState(SAMPLE_BATCH);
  const [results, setResults] = useState<IocBatchResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const handleBatchScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const res = scanBatchIocs(inputText);
      setResults(res);
      setIsScanning(false);
    }, 400);
  };

  const handleExportCsv = () => {
    if (results.length === 0) return;
    const headers = 'IOC,Type,Risk Score,Severity,Category,Source\n';
    const rows = results.map(r => `"${r.ioc}","${r.type}",${r.score},"${r.severity}","${r.category}","${r.source}"`).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOC_Batch_Threat_Report_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div className="space-y-6">
      <div className="glass-panel-glow rounded-xl p-6">
        <div className="flex items-center space-x-2 mb-3">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
            BATCH IOC (IP, DOMAIN, HASH) THREAT SCANNER
          </h2>
        </div>
        <p className="text-xs text-slate-400 font-mono mb-4">
          Paste a bulk list of IOC indicators (one per line) to instantly evaluate threat severity and export forensic CSV audits.
        </p>

        <textarea
          rows={6}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          className="w-full p-3 bg-slate-900/90 border border-slate-700 focus:border-cyan-400 rounded-lg text-xs font-mono text-cyan-200 outline-none resize-none"
        />

        <div className="flex items-center space-x-3 mt-4">
          <button
            onClick={handleBatchScan}
            disabled={isScanning}
            className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-mono font-semibold text-xs rounded-lg shadow-md shadow-cyan-900/50 flex items-center space-x-2 transition-all"
          >
            <Search className="w-4 h-4" />
            <span>RUN BATCH AI ANALYSIS</span>
          </button>

          {results.length > 0 && (
            <button
              onClick={handleExportCsv}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-xs rounded-lg border border-slate-700 flex items-center space-x-2 transition-all"
            >
              <Download className="w-4 h-4" />
              <span>EXPORT CSV AUDIT</span>
            </button>
          )}
        </div>
      </div>

      {results.length > 0 && (
        <div className="glass-panel rounded-xl p-6 font-mono text-xs">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-slate-200">BATCH SCAN RESULTS ({results.length} INDICATORS)</h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="p-3">INDICATOR (IOC)</th>
                  <th className="p-3">TYPE</th>
                  <th className="p-3">SEVERITY</th>
                  <th className="p-3">SCORE</th>
                  <th className="p-3">CATEGORY / INTEL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {results.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="p-3 font-semibold text-pink-300 break-all">{item.ioc}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                        {item.type}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        item.severity === 'CRITICAL'
                          ? 'bg-pink-950 text-pink-300 border-pink-500/40'
                          : item.severity === 'HIGH'
                          ? 'bg-red-950 text-red-300 border-red-500/40'
                          : item.severity === 'MEDIUM'
                          ? 'bg-amber-950 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                      }`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-cyan-300">{item.score}/100</td>
                    <td className="p-3 text-slate-400">{item.category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
