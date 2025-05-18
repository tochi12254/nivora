export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical'

export interface Threat {
  id: string
  timestamp: string
  threat_type: string
  source_ip: string
  destination_ip: string
  protocol: string
  severity: ThreatSeverity
  description: string
  raw_data: string
  acknowledged: boolean
}