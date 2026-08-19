import type { RiskAssessment, SinkRisk, TurnRiskState } from '../types.js'

const sensitiveKey = /(?:api[-_ ]?key|access[-_ ]?key|token|password|secret|private[-_ ]?key|authorization|cookie|credential)/i
const sensitiveAssignment = /((?:["']?(?:api[-_ ]?key|access[-_ ]?key|token|password|secret|private[-_ ]?key|authorization|cookie|credential)["']?)\s*[:=]\s*["']?)([^\s,;&"']+)/gi

function redact(value: unknown, key = ''): unknown {
  if (sensitiveKey.test(key)) return '[REDACTED]'
  if (typeof value === 'string') {
    const redacted = value.replace(sensitiveAssignment, '$1[REDACTED]')
    return redacted.length > 512 ? `${redacted.slice(0, 512)}…[TRUNCATED]` : redacted
  }
  if (Array.isArray(value)) return value.map(item => redact(item))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([entryKey, entryValue]) => [entryKey, redact(entryValue, entryKey)]))
  }
  return value
}

function safeTarget(args: unknown): string {
  try {
    const serialized = JSON.stringify(redact(args))
    return serialized.length > 2000 ? `${serialized.slice(0, 2000)}…[TRUNCATED]` : serialized
  } catch {
    return '[UNSERIALIZABLE_ARGUMENTS]'
  }
}

function safeLogValue(value: unknown): string {
  return String(value).replace(/[\u0000-\u001F\u007F\u2028\u2029]/g, ' ').slice(0, 512)
}

export function formatAuditLog(toolName: string, args: unknown, state: TurnRiskState, sinks: SinkRisk[], assessment: RiskAssessment): string {
  const target = typeof args === 'string' ? redact(args) : safeTarget(args)
  const decision = assessment.decision === 'BLOCK' ? 'BLOCKED' : assessment.decision === 'ASK' ? 'ASKED' : 'ALLOWED'
  return ['⚠ DSH Injection Guard', '', 'Possible indirect prompt injection detected.', '', 'Untrusted context:', ...state.sources.filter(s => s.trust === 'UNTRUSTED').map(s => `  source: ${safeLogValue(s.label)}`), '', 'Injection signals:', ...state.injectionSignals.map(s => `  - ${safeLogValue(s.evidence)}`), '', 'Sensitive action:', `  tool: ${safeLogValue(toolName)}`, `  target: ${safeLogValue(target)}`, `  sink: ${sinks.map(s => s.type).join(', ') || 'none'}`, '', 'Risk:', `  ${assessment.level} (${assessment.score}/100)`, '', 'Decision:', `  ${decision}`].join('\n')
}
