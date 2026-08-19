import type { RiskAssessment, SinkRisk, TurnRiskState } from '../types.js'
const points: Record<SinkRisk['type'], number> = { 'credential-access': 40, network: 40, 'download-execute': 50, shell: 40, 'destructive-filesystem': 30, none: 0 }
export function evaluateRisk(state: TurnRiskState, sinks: SinkRisk[]): RiskAssessment {
  const reasons: string[] = []; let score = state.hasUntrustedContext ? 20 : 0
  if (state.hasUntrustedContext) reasons.push('untrusted context present')
  if (state.injectionSignals.length) { score += 30; reasons.push(...state.injectionSignals.map(signal => `injection: ${signal.evidence}`)) }
  for (const sink of sinks) { score += points[sink.type]; reasons.push(`sink: ${sink.type}`) }
  score = Math.min(score, 100)
  const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW'
  const decision = score >= 80 ? 'BLOCK' : score >= 60 ? 'ASK' : 'ALLOW'
  return { score, level, decision, reasons }
}
