import type { SourceRisk } from '../types.js'
export function classifySource(source: unknown): SourceRisk {
  const value = source as { kind?: string; path?: string; label?: string } | undefined
  const kind = value?.kind?.toLowerCase()
  if (kind === 'user' || kind === 'system' || kind === 'agent') return { label: value?.label ?? kind, trust: 'TRUSTED' }
  if (kind === 'plugin') return { label: value?.label ?? 'plugin output', trust: 'SEMI_TRUSTED' }
  if (kind === 'tool' || kind === 'web' || kind === 'file' || kind === 'document') return { label: value?.path ?? value?.label ?? kind, trust: 'UNTRUSTED' }
  return { label: value?.label ?? kind ?? 'unknown', trust: 'UNKNOWN' }
}
