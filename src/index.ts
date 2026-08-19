import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import { classifySource } from './context/source-classifier.js'
import { detectInjection } from './context/injection-detector.js'
import { formatAuditLog } from './logging/audit-log.js'
import { evaluateRisk } from './risk/risk-engine.js'
import { classifySink } from './sinks/sink-classifier.js'
import type { TurnRiskState } from './types.js'

export const name = 'injection-guard'
export interface Config { log?: boolean; askThreshold?: number }
export const Config: z<Config> = z.object({ log: z.boolean().default(true), askThreshold: z.number().default(60) })

type Message = { source?: unknown; content?: unknown }
function textOf(content: unknown): string {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content.map(block => typeof block === 'string' ? block : (block as { type?: string; text?: string }).text ?? '').join('\n')
}
function agentKey(agent: unknown): string { const value = agent as { id?: unknown; session?: { id?: unknown } }; return String(value.id ?? value.session?.id ?? 'unknown') }
function stateFromMessages(agent: unknown, messages: readonly Message[]): TurnRiskState {
  const sources = messages.map(message => classifySource(message.source))
  const injectionSignals = messages.flatMap(message => detectInjection(textOf(message.content)))
  return { agentId: agentKey(agent), hasUntrustedContext: sources.some(source => source.trust === 'UNTRUSTED'), sources, injectionSignals, contextRiskScore: sources.some(source => source.trust === 'UNTRUSTED') ? 20 : 0 }
}

export function apply(ctx: Context, config: Config): void {
  const states = new WeakMap<object, TurnRiskState>()
  const log = config.log !== false
  const askThreshold = config.askThreshold ?? 60
  ctx.on('agent/pre-step', (event: { agent: object; messages: readonly Message[] }, next): Promise<PreStepDecision> => {
    states.set(event.agent, stateFromMessages(event.agent, event.messages))
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
