export interface NetworkPacket {
  id: string
  timestamp: string
  source_ip: string
  destination_ip: string
  protocol: string
  length: number
  flags?: string
  src_port?: number
  dst_port?: number
  payload?: string
}

export interface NetworkStats {
  timestamp: string
  packets_per_second: number
  bytes_per_second: number
  active_connections: number
  top_protocols: Array<{
    protocol: string
    count: number
    percentage: number
  }>
  threat_count: number
}