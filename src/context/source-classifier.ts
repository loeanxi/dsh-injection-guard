import type { SourceRisk } from '../types.js'
export function classifySource(source: unknown): SourceRisk {
  const value = source as { kind?: string; type?: string; path?: string; label?: string; callId?: string } | undefined
  const kind = (value?.kind ?? value?.type)?.toLowerCase()
  if (kind === 'user' || kind === 'system' || kind === 'agent') return { label: value?.label ?? kind, trust: 'TRUSTED' }
  if (kind === 'plugin') return { label: value?.label ?? 'plugin output', trust: 'SEMI_TRUSTED' }
  if (kind === 'tool' || kind === 'tool-result' || kind === 'web' || kind === 'file' || kind === 'document') {
    return { label: value?.path ?? value?.label ?? value?.callId ?? kind, trust: 'UNTRUSTED' }
  }
  return { label: value?.label ?? kind ?? 'unknown', trust: 'UNKNOWN' }
}
