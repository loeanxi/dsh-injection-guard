import type { GuardLocale, RiskAssessment, SinkRisk, TurnRiskState } from '../types.js'

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

export function formatAuditLog(toolName: string, args: unknown, state: TurnRiskState, sinks: SinkRisk[], assessment: RiskAssessment, locale: GuardLocale = 'en'): string {
  const target = typeof args === 'string' ? redact(args) : safeTarget(args)
  const zh = locale === 'zh-CN'
  const decision = assessment.decision === 'BLOCK' ? (zh ? '已阻断（BLOCKED）' : 'BLOCKED') : assessment.decision === 'ASK' ? (zh ? '需要确认（ASKED）' : 'ASKED') : (zh ? '已允许（ALLOWED）' : 'ALLOWED')
  return [zh ? '⚠ DSH 注入防护 / DSH Injection Guard' : '⚠ DSH Injection Guard', '', zh ? '检测到可能的间接提示词注入。' : 'Possible indirect prompt injection detected.', '', zh ? '上下文来源：' : 'Context sources:', ...state.sources.filter(s => s.trust !== 'TRUSTED').map(s => `  ${zh ? '不可信' : s.trust.toLowerCase()}: ${safeLogValue(s.label)}`), '', zh ? '注入信号：' : 'Injection signals:', ...state.injectionSignals.map(s => `  - ${safeLogValue(s.source ? `${s.source}: ${s.evidence}` : s.evidence)}`), '', zh ? '敏感操作：' : 'Sensitive action:', `  ${zh ? '工具' : 'tool'}: ${safeLogValue(toolName)}`, `  ${zh ? '目标' : 'target'}: ${safeLogValue(target)}`, `  ${zh ? '风险类型' : 'sink'}: ${sinks.map(s => s.type).join(', ') || 'none'}`, '', zh ? '原因：' : 'Reasons:', ...assessment.reasons.map(reason => `  - ${safeLogValue(reason)}`), '', zh ? '风险：' : 'Risk:', `  ${assessment.level} (${assessment.score}/100)`, '', zh ? '决定：' : 'Decision:', `  ${decision}`].join('\n')
}
