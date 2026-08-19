import type { InjectionSignal } from '../types.js'
const rules: Array<[InjectionSignal['type'], InjectionSignal['severity'], RegExp]> = [
  ['instruction-hijack', 'high', /ignore\s+(all\s+)?previous\s+instructions?|disregard\s+previous|override\s+(the\s+)?system|new\s+instructions?|system\s+message|developer\s+message/i],
  ['identity-spoofing', 'medium', /you\s+are\s+now|act\s+as\s+(an?\s+)?administrator|system\s+override|security\s+verification|authorized\s+by/i],
  ['secret-access', 'high', /(?:~\/)?\.ssh(?:\/|$)|(?:~\/)?\.aws(?:\/|$)|ssh\s+key|private\s+key|(?:^|[\s./])\.env(?:$|[\s/])|credentials?|(?:api|access)\s+key|password|token|AWS_SECRET_ACCESS_KEY/i],
  ['exfiltration', 'critical', /send\s+to|upload\s+to|POST\s+to|\bcurl\b|\bwget\b|webhook/i],
  ['obfuscated-execution', 'high', /base64|\beval\b|decode|execute\s+this|run\s+this\s+command/i],
]
export function detectInjection(text: string): InjectionSignal[] {
  return rules.flatMap(([type, severity, pattern]) => { const match = text.match(pattern); return match ? [{ type, severity, evidence: match[0] }] : [] })
}
