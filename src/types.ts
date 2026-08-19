export type SourceTrust = 'TRUSTED' | 'SEMI_TRUSTED' | 'UNTRUSTED' | 'UNKNOWN'
export type SignalSeverity = 'low' | 'medium' | 'high' | 'critical'
export type SignalType = 'instruction-hijack' | 'identity-spoofing' | 'secret-access' | 'exfiltration' | 'obfuscated-execution'
export type SinkType = 'credential-access' | 'network' | 'shell' | 'download-execute' | 'destructive-filesystem' | 'none'
export interface SourceRisk { label: string; trust: SourceTrust }
export interface InjectionSignal { type: SignalType; severity: SignalSeverity; evidence: string }
export interface SinkRisk { type: SinkType; evidence: string }
export interface TurnRiskState { agentId: string; turn?: number; hasUntrustedContext: boolean; sources: SourceRisk[]; injectionSignals: InjectionSignal[]; contextRiskScore: number }
export interface RiskAssessment { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; decision: 'ALLOW' | 'ASK' | 'BLOCK'; reasons: string[] }
