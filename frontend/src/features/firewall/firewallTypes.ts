

// features/firewall/firewallTypes.ts
export type FirewallRuleAction = 'allow' | 'deny'
export type FirewallRuleDirection = 'in' | 'out' | 'any'
export type FirewallRuleProtocol = 'tcp' | 'udp' | 'icmp' | 'any'

export interface FirewallRule {
  id: string
  action: FirewallRuleAction
  direction: FirewallRuleDirection
  source_ip?: string
  destination_ip?: string
  source_port?: number
  destination_port?: number
  protocol?: FirewallRuleProtocol
  interface?: string
  is_active: boolean
  created_at: string
  created_by: string
  description?: string
}

export interface FirewallLog {
  id: string
  timestamp: string
  action: FirewallRuleAction
  rule_id?: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol: string
  packet_size: number
  matched_rule?: string
  direction: FirewallRuleDirection
}

export interface FirewallStats {
  total_rules: number
  active_rules: number
  blocked_ips: number
  packets_processed: number
  packets_allowed: number
  packets_blocked: number
  last_updated: string
}