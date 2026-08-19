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
export interface Config { log?: boolean; askThreshold?: number }
export const Config: z<Config> = z.object({ log: z.boolean().default(true), askThreshold: z.number().default(60) })

type Message = { source?: unknown; role?: string; content?: unknown }
function textOf(content: unknown): string {
  if (typeof content === 'string') return content.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '')
  if (Array.isArray(content)) return content.map(textOf).filter(Boolean).join('\n')
  if (!content || typeof content !== 'object') return ''
  const value = content as { text?: unknown; value?: unknown; content?: unknown; data?: unknown; parts?: unknown }
  return textOf(value.text ?? value.value ?? value.content ?? value.data ?? value.parts)
}
function agentKey(agent: unknown): string { const value = agent as { id?: unknown; session?: { id?: unknown } }; return String(value.id ?? value.session?.id ?? 'unknown') }
function uniqueSources(sources: TurnRiskState['sources']): TurnRiskState['sources'] {
  return [...new Map(sources.map(source => [`${source.trust}:${source.label}`, source])).values()]
}
function uniqueSignals(signals: TurnRiskState['injectionSignals']): TurnRiskState['injectionSignals'] {
  return [...new Map(signals.map(signal => [`${signal.type}:${signal.evidence}`, signal])).values()]
}
function stateFromMessages(agent: unknown, messages: readonly Message[], turn?: number): TurnRiskState {
  const injectionSignals = messages.flatMap(message => detectInjection(textOf(message.content)))
  const sources = messages.map(message => classifySource(message.source ?? (message.role === 'tool' ? { kind: 'tool', label: 'tool output' } : undefined)))
  const hasExplicitUntrustedSource = sources.some(source => source.trust === 'UNTRUSTED')
  const inferredUntrustedSource = !hasExplicitUntrustedSource && injectionSignals.length > 0
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
  ctx.on('agent/pre-step', (event: { agent: object; messages: readonly Message[]; turn?: number }, next): Promise<PreStepDecision> => {
    const incoming = stateFromMessages(event.agent, event.messages, event.turn)
    const previous = states.get(event.agent)
    const sameTurn = previous !== undefined && event.turn !== undefined && previous.turn === event.turn
    states.set(event.agent, sameTurn ? mergeRiskState(previous, incoming) : incoming)
    return next()
  })
  ctx.on('tools/post-execute', async (exec: ToolExecution, result: unknown, next): Promise<PostToolDecision> => {
    const agent = exec.agent as object | undefined
    const state = agent ? states.get(agent) : undefined
    if (state) {
      const signals = detectInjection(textOf(result))
      if (signals.length) {
        state.injectionSignals = uniqueSignals([...state.injectionSignals, ...signals])
        state.sources = uniqueSources([...state.sources, { label: `${exec.name} output`, trust: 'UNTRUSTED' }])
        state.hasUntrustedContext = true
        state.contextRiskScore = 20
      }
    }
    return next()
  })
  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    const agent = exec.agent as object | undefined
    const state = agent ? states.get(agent) : undefined
    if (!state) return next()
    const sinks = classifySink(exec.name, exec.arguments)
    if (!sinks.length || (!state.hasUntrustedContext && !state.injectionSignals.length)) return next()
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
