import type { SinkRisk } from '../types.js'
function normalize(value: string): string { return value.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '') }
function serialize(args: unknown): string {
  if (typeof args === 'string') return args
  try { return JSON.stringify(args) ?? String(args) } catch { return String(args) }
}
export function classifySink(toolName: string, args: unknown): SinkRisk[] {
  const text = normalize(`${toolName} ${serialize(args)}`)
  const checks: Array<[SinkRisk['type'], RegExp]> = [
    ['download-execute', /(?:curl|wget)[^\n|]*\|\s*(?:bash|sh)|(?:curl|wget)[^\n]*(?:bash|sh)/i],
    ['credential-access', /(?:~\/|\.ssh|\.aws|\.env|id_rsa|id_ed25519|credentials?|private[ _-]?key|password|secret)/i],
    ['network', /\b(?:curl|wget|scp|nc|netcat|upload|webhook|POST|fetch|Invoke-WebRequest|Invoke-RestMethod)\b|https?:\/\//i],
    ['shell', /\b(?:bash|sh|powershell|sudo|chmod|eval|base64)\b/i],
    ['destructive-filesystem', /\b(?:rm|delete|truncate|overwrite)\b/i],
  ]
  return checks.flatMap(([type, pattern]) => pattern.test(text) ? [{ type, evidence: text.match(pattern)?.[0] ?? type }] : [])
}
