import type { SinkRisk } from '../types.js'
function normalize(value: string): string { return value.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '') }
export function classifySink(toolName: string, args: unknown): SinkRisk[] {
  const text = normalize(`${toolName} ${typeof args === 'string' ? args : JSON.stringify(args)}`)
  const checks: Array<[SinkRisk['type'], RegExp]> = [
    ['download-execute', /(?:curl|wget)[^\n|]*\|\s*(?:bash|sh)|(?:curl|wget)[^\n]*(?:bash|sh)/i],
    ['credential-access', /(?:~\/|\.ssh|\.aws|\.env|id_rsa|id_ed25519|credentials?|private[ _-]?key|password|secret)/i],
    ['network', /\b(?:curl|wget|upload|webhook|POST)\b|https?:\/\//i],
    ['shell', /\b(?:bash|sh|powershell|sudo|chmod|eval|base64)\b/i],
    ['destructive-filesystem', /\b(?:rm|delete|truncate|overwrite)\b/i],
  ]
  return checks.flatMap(([type, pattern]) => pattern.test(text) ? [{ type, evidence: text.match(pattern)?.[0] ?? type }] : [])
}
