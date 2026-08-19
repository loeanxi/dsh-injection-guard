import type { SourceRisk } from '../types.js'
function recordOf(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' ? value as Record<string, unknown> : undefined }
export function classifySource(source: unknown): SourceRisk {
  if (typeof source === 'string') {
    const kind = source.toLowerCase()
    if (kind === 'user' || kind === 'system' || kind === 'agent') return { label: kind, trust: 'TRUSTED' }
    if (kind === 'plugin') return { label: 'plugin output', trust: 'SEMI_TRUSTED' }
    if (kind === 'tool' || kind === 'tool-result' || kind === 'web' || kind === 'file' || kind === 'document') return { label: kind, trust: 'UNTRUSTED' }
    return { label: source, trust: 'UNKNOWN' }
  }
  if (!source || typeof source !== 'object') return { label: 'unknown', trust: 'UNKNOWN' }
  const value = recordOf(source)
  const kindValue = value?.kind ?? value?.type
  const kind = typeof kindValue === 'string' ? kindValue.toLowerCase() : undefined
  const label = typeof value?.label === 'string' ? value.label : undefined
  if (kind === 'user' || kind === 'system' || kind === 'agent') return { label: label ?? kind, trust: 'TRUSTED' }
  if (kind === 'plugin') return { label: label ?? 'plugin output', trust: 'SEMI_TRUSTED' }
  if (kind === 'tool' || kind === 'tool-result' || kind === 'web' || kind === 'file' || kind === 'document') {
    const sourceLabel = [value?.path, label, value?.callId].find(item => typeof item === 'string')
    return { label: typeof sourceLabel === 'string' ? sourceLabel : kind, trust: 'UNTRUSTED' }
  }
  return { label: label ?? kind ?? 'unknown', trust: 'UNKNOWN' }
}
