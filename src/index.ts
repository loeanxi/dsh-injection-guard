import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { PostToolDecision, PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import { classifySource } from './context/source-classifier.js'
import { detectInjection } from './context/injection-detector.js'
import { formatAuditLog } from './logging/audit-log.js'
import { evaluateRisk } from './risk/risk-engine.js'
import { classifySink } from './sinks/sink-classifier.js'
import type { TurnRiskState } from './types.js'

export const name = 'injection-guard'
export interface Config { log?: boolean; askThreshold?: number; failClosed?: boolean }
export const Config: z<Config> = z.object({ log: z.boolean().default(true), askThreshold: z.number().default(60), failClosed: z.boolean().default(true) })

type Message = { source?: unknown; role?: string; content?: unknown }
function objectOf(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' ? value as Record<string, unknown> : undefined }
function textOf(content: unknown, seen = new WeakSet<object>()): string {
  if (typeof content === 'string') return content.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '')
  if (Array.isArray(content)) {
    if (seen.has(content)) return ''
    seen.add(content)
    return content.map(item => textOf(item, seen)).filter(Boolean).join('\n')
  }
  if (!content || typeof content !== 'object') return ''
  if (seen.has(content)) return ''
  seen.add(content)
  const value = objectOf(content)
  return textOf(value?.text ?? value?.value ?? value?.content ?? value?.data ?? value?.parts, seen)
}
function agentKey(agent: unknown): string {
  try {
    const value = objectOf(agent)
    const session = objectOf(value?.session)
    return String(value?.id ?? session?.id ?? 'unknown')
  } catch { return 'unknown' }
}
function uniqueSources(sources: TurnRiskState['sources']): TurnRiskState['sources'] {
  return [...new Map(sources.map(source => [`${source.trust}:${source.label}`, source])).values()]
}
function uniqueSignals(signals: TurnRiskState['injectionSignals']): TurnRiskState['injectionSignals'] {
  return [...new Map(signals.map(signal => [`${signal.source ?? ''}:${signal.type}:${signal.evidence}`, signal])).values()]
}
function stateFromMessages(agent: unknown, messages: readonly Message[], turn?: number): TurnRiskState {
  const sources = messages.map(message => classifySource(message.source ?? (message.role === 'tool' ? { kind: 'tool', label: 'tool output' } : undefined)))
  const signalGroups = messages.map((message, index) => detectInjection(textOf(message.content)).map(signal => ({ ...signal, source: sources[index].label })))
  const injectionSignals = signalGroups.flat()
  const hasExplicitUntrustedSource = sources.some(source => source.trust === 'UNTRUSTED')
  const hasUnknownSignal = signalGroups.some((signals, index) => signals.length > 0 && sources[index].trust === 'UNKNOWN')
  const inferredUntrustedSource = !hasExplicitUntrustedSource && hasUnknownSignal
    ? [{ label: 'inferred from injection signal', trust: 'UNTRUSTED' as const }]
    : []
  const allSources = uniqueSources([...sources, ...inferredUntrustedSource])
  const hasUntrustedContext = hasExplicitUntrustedSource || inferredUntrustedSource.length > 0
  return { agentId: agentKey(agent), turn, hasUntrustedContext, sources: allSources, injectionSignals, contextRiskScore: hasUntrustedContext ? 20 : 0 }
}

function mergeRiskState(current: TurnRiskState, incoming: TurnRiskState): TurnRiskState {
  const signals = uniqueSignals([...current.injectionSignals, ...incoming.injectionSignals])
  const sources = uniqueSources([...current.sources, ...incoming.sources])
  return {
    ...incoming,
    injectionSignals: signals,
    sources,
    hasUntrustedContext: current.hasUntrustedContext || incoming.hasUntrustedContext,
    contextRiskScore: current.hasUntrustedContext || incoming.hasUntrustedContext ? 20 : 0,
  }
}

export function apply(ctx: Context, config: Config): void {
  const states = new WeakMap<object, TurnRiskState>()
  const log = config.log !== false
  const askThreshold = config.askThreshold ?? 60
  const failClosed = config.failClosed !== false
  ctx.on('agent/pre-step', (event: { agent: object; messages: readonly Message[]; turn?: number }, next): Promise<PreStepDecision> => {
    try {
      const incoming = stateFromMessages(event.agent, event.messages, event.turn)
      const previous = states.get(event.agent)
      const sameTurn = previous !== undefined && event.turn !== undefined && previous.turn === event.turn
      states.set(event.agent, sameTurn ? mergeRiskState(previous, incoming) : incoming)
    } catch {
      states.delete(event.agent)
    }
    return next()
  })
  ctx.on('tools/post-execute', async (exec: ToolExecution, result: unknown, next): Promise<PostToolDecision> => {
    const agent = objectOf(exec.agent)
    const state = agent ? states.get(agent) : undefined
    if (state) {
      try {
        const signals = detectInjection(textOf(result))
        if (signals.length) {
          state.injectionSignals = uniqueSignals([...state.injectionSignals, ...signals.map(signal => ({ ...signal, source: `${exec.name} output` }))])
          state.sources = uniqueSources([...state.sources, { label: `${exec.name} output`, trust: 'UNTRUSTED' }])
          state.hasUntrustedContext = true
          state.contextRiskScore = 20
        }
      } catch {
        if (agent) states.delete(agent)
      }
    }
    return next()
  })
  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    const agent = objectOf(exec.agent)
    const state = agent ? states.get(agent) : undefined
    let sinks
    try {
      sinks = classifySink(exec.name, exec.arguments)
    } catch {
      if (!failClosed) return next()
      const unknownState: TurnRiskState = { agentId: agentKey(agent), hasUntrustedContext: false, sources: [{ label: 'sink classification failed', trust: 'UNKNOWN' }], injectionSignals: [], contextRiskScore: 0 }
      const audit = formatAuditLog(String(exec.name), exec.arguments, unknownState, [{ type: 'none', evidence: 'classification failed' }], { score: 0, level: 'LOW', decision: 'ASK', reasons: ['guard: sink classification failed; fail-closed review required'] })
      if (log) console.warn(audit)
      return { kind: 'ask', reason: audit }
    }
    if (!sinks.length) return next()
    if (!state) {
      if (!failClosed) return next()
      const unknownState: TurnRiskState = { agentId: agentKey(agent), hasUntrustedContext: false, sources: [{ label: 'turn state unavailable', trust: 'UNKNOWN' }], injectionSignals: [], contextRiskScore: 0 }
      const assessment = evaluateRisk(unknownState, sinks)
      assessment.reasons.unshift('guard: turn state unavailable; fail-closed review required')
      const audit = formatAuditLog(exec.name, exec.arguments, unknownState, sinks, assessment)
      if (log) console.warn(audit)
      return { kind: 'ask', reason: audit }
    }
    if (!state.hasUntrustedContext) return next()
    const assessment = evaluateRisk(state, sinks)
    if (assessment.decision === 'BLOCK') {
      const audit = formatAuditLog(exec.name, exec.arguments, state, sinks, assessment)
      if (log) console.warn(audit)
      return { kind: 'deny', reason: audit }
    }
    if (assessment.score >= askThreshold) {
      const audit = formatAuditLog(exec.name, exec.arguments, state, sinks, assessment)
      if (log) console.warn(audit)
      return { kind: 'ask', reason: audit }
    }
    return next()
  })
}

export * from './types.js'
export * from './context/source-classifier.js'
export * from './context/injection-detector.js'
export * from './sinks/sink-classifier.js'
export * from './risk/risk-engine.js'
