import type { SinkRisk, SemanticRisk } from '../types.js'

export interface SemanticRiskInput { text: string; sinks: SinkRisk[] }

const imperative = /\b(read|cat|print|dump|extract|retrieve|send|upload|post|execute|run|download|ignore|override|disregard)\b/i
const secretTarget = /(?:~[\\/]\.ssh|\.aws|\.env|id_(?:rsa|ed25519)|private\s+key|credentials?|password|token|secret)/i
const externalTarget = /https?:\/\/|webhook|external\s+(?:url|server)|remote\s+(?:host|endpoint)/i
const authorityHijack = /ignore\s+(?:all\s+)?previous|override\s+(?:the\s+)?system|new\s+instructions?|you\s+are\s+now|security\s+verification/i

/** Conservative intent scoring. It can only add risk, never lower a decision. */
export function scoreSemanticRisk(input: SemanticRiskInput): SemanticRisk {
  const text = input.text.normalize('NFKC')
  const reasons: string[] = []
  let score = 0
  const hasSensitiveSink = input.sinks.some(sink => sink.type !== 'none')
  if (hasSensitiveSink && imperative.test(text) && secretTarget.test(text)) {
    score += 10
    reasons.push('semantic: imperative action targets credential-like data')
  }
  if (hasSensitiveSink && imperative.test(text) && secretTarget.test(text) && externalTarget.test(text)) {
    score += 10
    reasons.push('semantic: sensitive data and external destination co-occur')
  }
  if (authorityHijack.test(text) && imperative.test(text)) {
    score += 5
    reasons.push('semantic: authority-hijack language is paired with an action')
  }
  return { score: Math.min(score, 20), reasons }
}
