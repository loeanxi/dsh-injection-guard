import type { SinkRisk } from '../types.js'
function normalize(value: string): string { return value.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g, '') }
function safeString(value: unknown): string { try { return String(value) } catch { return '[UNSERIALIZABLE_ARGUMENTS]' } }
function serialize(args: unknown): string {
  if (typeof args === 'string') return args
  try { return JSON.stringify(args) ?? safeString(args) } catch { return safeString(args) }
}
export function classifySink(toolName: string, args: unknown): SinkRisk[] {
  const text = normalize(String(safeString(toolName) + ' ' + serialize(args)))
  const tool = normalize(safeString(toolName))
  const credentialText = /(?:ask|question|message|chat|glob|grep|search)/i.test(tool)
    ? tool
    : /(?:^|[.:])(?:read|cat|open)$/i.test(tool) && args && typeof args === 'object'
      ? tool + ' ' + Object.entries(args).filter(([key]) => /^(?:path|file_path|filePath|filename)$/i.test(key)).map(([, value]) => safeString(value)).join(' ')
      : /(?:http|post|put|patch|pwsh|powershell|bash|sh|shell|curl|scp|upload)/i.test(tool) ? text : tool
  const credentialPattern = /(?:~[\\/]|\.ssh(?:[\\/]|$)|\.aws(?:[\\/]|$)|\.env(?:[\\/\.\"']|$)|id_(?:rsa|ed25519)|credentials?(?:(?:[._-](?:json|ya?ml|txt))|[\\/]|$)|private[ _-]?key(?:(?:[._-][a-z0-9]+)|[\\/]|$)|(?:[\"']?(?:api[-_ ]?key|access[-_ ]?key|token|password|secret|authorization|cookie)[\"']?\s*[:=]))/i
  const checks: Array<[SinkRisk['type'], RegExp]> = [
    ['download-execute', /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)[^\n|]*(?:\|\s*(?:bash|sh|python(?:3)?|node|iex|Invoke-Expression)|(?:-o|--output|-OutFile)\s+[^\n]+(?:bash|sh|python(?:3)?|node|iex))/i],
    ['credential-access', credentialPattern],
    ['network', /\b(?:curl|wget|scp|nc|netcat|upload|webhook|POST|fetch|Invoke-WebRequest|Invoke-RestMethod)\b|https?:\/\//i],
    ['shell', /\b(?:bash|sh|powershell|sudo|chmod|eval|base64)\b/i],
    ['destructive-filesystem', /\b(?:rm|delete|truncate|overwrite)\b/i],
  ]
  return checks.flatMap(([type, pattern]) => {
    const candidate = type === 'credential-access' ? credentialText : text
    return pattern.test(candidate) ? [{ type, evidence: candidate.match(pattern)?.[0] ?? type }] : []
  })
}
