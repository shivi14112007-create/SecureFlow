
import { ScanFinding } from './scanner';

export type PolicyResult = 'PASS' | 'REVIEW REQUIRED' | 'BLOCKED';

export class ArmorIQPolicyEngine {
  evaluateFindings(findings: ScanFinding[]): PolicyResult {
    if (findings.some(f => f.severity === 'CRITICAL')) {
      return 'BLOCKED';
    }
    
    if (findings.some(f => f.severity === 'HIGH' || f.severity === 'MEDIUM')) {
      return 'REVIEW REQUIRED';
    }

    return 'PASS';
  }

  getRiskTrend(): number {
    return Math.random() * 100;
  }
}

export const iq = new ArmorIQPolicyEngine();
