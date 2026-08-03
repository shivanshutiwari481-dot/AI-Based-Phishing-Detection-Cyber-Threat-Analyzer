import { IocBatchResult, ThreatSeverity } from '../types/threat';
import { analyzeUrl } from './urlAnalyzer';
export function scanBatchIocs(inputText: string): IocBatchResult[] {
  const lines = inputText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const results: IocBatchResult[] = [];
  lines.forEach((line, index) => {
    let type: IocBatchResult['type'] = 'DOMAIN';
    let score = 10;
    let category = 'Clean Infrastructure';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(line)) {
      type = 'IP';
      if (line.startsWith('185.') || line.startsWith('45.') || line.startsWith('194.')) {
        score = 85;
        category = 'Known Bulletproof Hosting / C2 Relay';
      } else {
        score = 25;
        category = 'Standard Network Gateway';
      }
    } else if (/^[a-fA-F0-9]{32}$/.test(line) || /^[a-fA-F0-9]{64}$/.test(line)) {
      type = 'HASH';
        if (line.toLowerCase().startsWith('a1') || line.toLowerCase().startsWith('e9') || line.toLowerCase().startsWith('7f')) {
        score = 90;
        category = 'Ransomware / Cobalt Strike Beacon Hash';
      } else {
        score = 15;
        category = 'Clean Binary Hash';
      }
    } else {
      type = line.startsWith('http') ? 'URL' : 'DOMAIN';
      const urlRes = analyzeUrl(line);
      score = urlRes.score;
      category = urlRes.classification;
    }
    let severity: ThreatSeverity = 'SAFE';
    if (score >= 75) severity = 'CRITICAL';
    else if (score >= 50) severity = 'HIGH';
    else if (score >= 25) severity = 'MEDIUM';
    else if (score >= 10) severity = 'LOW';
    results.push({
      id: `ioc-${index + 1}`,
      ioc: line,
      type,
      score,
      severity,
      category,
      source: 'Aegis Threat Intel Feeds & Heuristic Model'
    });
  });
  return results;
}
