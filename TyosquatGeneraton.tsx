import React, { useState } from 'react';
import { Shield, Sparkles, Copy, Check, ExternalLink } from 'lucide-react';
export const TyposquatGenerator: React.FC = () => {
  const [brand, setBrand] = useState('paypal');
  const [results, setResults] = useState<string[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
const handleGenerate = () => {
    const cleanBrand = brand.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!cleanBrand) return;
    const lookalikes = [
      `${cleanBrand}-security-update.com`,
      `${cleanBrand}-verify-account.top`,
      `${cleanBrand.replace(/o/g, '0').replace(/l/g, '1')}.xyz`,
      `login-${cleanBrand}-auth.net`,
      `support-${cleanBrand}-portal.com`,
      `${cleanBrand}-official-login.info`,
      `${cleanBrand.replace(/a/g, '4')}-account-security.club`
    ];
    setResults(lookalikes);
  };
  const handleCopy = (domain: string, idx: number) => {
    navigator.clipboard.writeText(domain);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 1500);
  };
  return (
        <div className="glass-panel rounded-xl p-6 space-y-4">
      <div className="flex items-center space-x-2">
        <Sparkles className="w-5 h-5 text-amber-400" />
        <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wide">
          BRAND TYPOSQUATTING & HOMOGLYPH VECTOR GENERATOR
        </h3>
      </div>
      <p className="text-xs font-mono text-slate-400">
        Generate potential lookalike and typosquatted domain variations to pre-emptively register or block in DNS filters.
      </p>
      <div className="flex items-center space-x-3">
        <input
          type="text"
          value={brand}
          onChange={(e) => setBrand(e.target.value)}
          placeholder="e.g. paypal, google, company"
          className="flex-1 px-4 py-2 bg-slate-900 border border-slate-700 focus:border-cyan-400 rounded-lg text-xs font-mono text-cyan-200 outline-none"
        />
        <button
          onClick={handleGenerate}
          className="px-4 py-2 bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 border border-slate-700 text-slate-200 font-mono text-xs rounded-lg transition-all"
        >
 GENERATE LOOKALIKES
        </button>
      </div>
      {results.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-2 font-mono text-xs">
          {results.map((domain, idx) => (
            <div key={idx} className="flex items-center justify-between p-2.5 bg-slate-900/80 rounded border border-slate-800">
              <code className="text-pink-300">{domain}</code>
              <button
                onClick={() => handleCopy(domain, idx)}
                className="p-1 text-slate-400 hover:text-cyan-300"
              >
                {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
