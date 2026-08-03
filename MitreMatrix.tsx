import React from 'react';
import { Layers, ExternalLink, ShieldAlert, Cpu } from 'lucide-react';
const MITRE_TACTICS = [
  {
    tactic: 'Initial Access (TA0001)',
    techniques: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', description: 'Malicious Office macro or executable attachment.' },
      { id: 'T1566.002', name: 'Spearphishing Link', description: 'Deceptive URL leading to credential harvester.' },
      { id: 'T1190', name: 'Exploit Public Application', description: 'Exploiting unpatched web servers or VPN endpoints.' }
    ]
  },
  {
    tactic: 'Execution (TA0002)',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell Execution', description: 'Running obfuscated inline PowerShell commands.' },
      { id: 'T1204.002', name: 'User Execution: Malicious File', description: 'Tricking user into opening payload file.' }
    ]
  },
  {
    tactic: 'Resource Development (TA0042)',
    techniques: [
      { id: 'T1583.001', name: 'Acquire Domains', description: 'Registering typosquatting / homoglyph domains.' },
      { id: 'T1588.002', name: 'Obtain SSL Certificates', description: 'Using free Let\'s Encrypt SSL for phish portals.' }
    ]
  },
  {
    tactic: 'Command & Control (TA0011)',
    techniques: [
      { id: 'T1071.001', name: 'Web Protocols (HTTP/HTTPS)', description: 'Exfiltrating credentials or beaconing over port 443.' },
      { id: 'T1090', name: 'Proxy & Tunneling', description: 'Routing traffic through TOR or residential proxies.' }
    ]
  }
];
export const MitreMatrix: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="glass-panel-glow rounded-xl p-6">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
              MITRE ATT&CK® ENTERPRISE FRAMEWORK MATRIX
            </h2>
          </div>
          <a
            href="https://attack.mitre.org"
            target="_blank"
            rel="noreferrer"
            className="text-xs font-mono text-cyan-300 hover:underline flex items-center gap-1"
          >
            <span>Official Framework Docs</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
        <p className="text-xs text-slate-400 font-mono">
          Correlate detected phishing heuristics and payload vectors directly against official MITRE Tactics, Techniques, and Procedures (TTPs).
        </p>
      </div>
       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        {MITRE_TACTICS.map((tac, idx) => (
          <div key={idx} className="glass-panel rounded-xl p-4 space-y-3 border-t-2 border-t-cyan-400">
            <h3 className="font-bold text-cyan-300 border-b border-slate-800 pb-2 text-[11px]">
              {tac.tactic}
            </h3>
            <div className="space-y-2.5">
              {tac.techniques.map((tech, tIdx) => (
                <div key={tIdx} className="p-3 bg-slate-900/80 rounded border border-slate-800 hover:border-cyan-500/40 transition-all">
                  <div className="flex items-center justify-between text-pink-400 font-bold mb-1">
                    <span>{tech.id}</span>
                  </div>
                  <div className="text-slate-200 font-semibold mb-1">{tech.name}</div>
                  <p className="text-[11px] text-slate-400">{tech.description}</p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
