export interface Threat {
  id: string
  timestamp: string
  threat_type: string
  source_ip: string
  destination_ip: string
  protocol: string
  length: number
  raw_data: string
}

// src/types.ts

// Threat type matching your backend's threat model
export interface Threat {
  id: string;
  timestamp: string; // ISO format datetime
  threat_type: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  length: number;
  raw_data: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

// NetworkPacket type matching your scapy packet data
export interface NetworkPacket {
  id: string;
  timestamp: string; // ISO format datetime
  source_ip: string;
  destination_ip: string;
  source_mac?: string;
  destination_mac?: string;
  protocol: string;
  length: number;
  flags?: string;
  src_port?: number;
  dst_port?: number;
  payload?: string;
}

// Firewall rule type
export interface FirewallRule {
  id: string;
  action: 'allow' | 'deny';
  direction: 'in' | 'out' | 'any';
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: 'tcp' | 'udp' | 'icmp' | 'any';
  interface?: string;
  is_active: boolean;
  created_at: string;
  expires_at?: string;
}

// WebSocket state type
export interface WebSocketState {
  threats: Threat[];
  packets: NetworkPacket[];
  connected: boolean;
  error?: string | null;
}



export interface FirewallLog {
  id: string
  timestamp: string
  action: string
  rule_id?: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol: string
  packet_size: number
}

export interface NetworkStats {
  active_connections: number
  known_hosts: number
  threats_detected: number
  packets_processed: number
  avg_packet_size: number
}