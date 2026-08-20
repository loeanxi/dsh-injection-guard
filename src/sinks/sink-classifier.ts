import type { SinkRisk } from '../types.js'
function normalize(value: string): string { return value.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g, '') }
function safeString(value: unknown): string { try { return String(value) } catch { return '[UNSERIALIZABLE_ARGUMENTS]' } }
function serialize(args: unknown): string {
  if (typeof args === 'string') return args
  try { return JSON.stringify(args) ?? safeString(args) } catch { return safeString(args) }
}
export function classifySink(toolName: string, args: unknown): SinkRisk[] {
  const text = normalize(`${safeString(toolName)} ${serialize(args)}`)
  const credentialPattern = /(?:~[\\/]|\.ssh(?:[\\/]|$)|\.aws(?:[\\/]|$)|\.env(?:[\\/\."']|$)|id_(?:rsa|ed25519)|credentials?|private[ _-]?key|(?:["']?(?:api[-_ ]?key|access[-_ ]?key|token|password|secret|authorization|cookie)["']?\s*[:=]))/i
  const checks: Array<[SinkRisk['type'], RegExp]> = [
    ['download-execute', /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)[^\n|]*(?:\|\s*(?:bash|sh|python(?:3)?|node|iex|Invoke-Expression)|(?:-o|--output|-OutFile)\s+[^\n]+(?:bash|sh|python(?:3)?|node|iex))/i],
    ['credential-access', credentialPattern],
    ['network', /\b(?:curl|wget|scp|nc|netcat|upload|webhook|POST|fetch|Invoke-WebRequest|Invoke-RestMethod)\b|https?:\/\//i],
    ['shell', /\b(?:bash|sh|powershell|sudo|chmod|eval|base64)\b/i],
    ['destructive-filesystem', /\b(?:rm|delete|truncate|overwrite)\b/i],
  ]
  return checks.flatMap(([type, pattern]) => pattern.test(text) ? [{ type, evidence: text.match(pattern)?.[0] ?? type }] : [])
}
