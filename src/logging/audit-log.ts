import type { RiskAssessment, SinkRisk, TurnRiskState } from '../types.js'
export function formatAuditLog(toolName: string, args: unknown, state: TurnRiskState, sinks: SinkRisk[], assessment: RiskAssessment): string {
  const target = typeof args === 'string' ? args : JSON.stringify(args)
  const decision = assessment.decision === 'BLOCK' ? 'BLOCKED' : assessment.decision === 'ASK' ? 'ASKED' : 'ALLOWED'
  return ['⚠ DSH Injection Guard', '', 'Possible indirect prompt injection detected.', '', 'Untrusted context:', ...state.sources.filter(s => s.trust === 'UNTRUSTED').map(s => `  source: ${s.label}`), '', 'Injection signals:', ...state.injectionSignals.map(s => `  - ${s.evidence}`), '', 'Sensitive action:', `  tool: ${toolName}`, `  target: ${target}`, `  sink: ${sinks.map(s => s.type).join(', ') || 'none'}`, '', 'Risk:', `  ${assessment.level} (${assessment.score}/100)`, '', 'Decision:', `  ${decision}`].join('\n')
}
