// types/network.ts
export enum BehaviorType {
  PORT_SCANNING = "Port Scanning",
  UNUSUAL_TRAFFIC_SPIKE = "Unusual Traffic Spike",
  DATA_EXFILTRATION = "Data Exfiltration",
  PROTOCOL_ANOMALY = "Protocol Anomaly",
  GEOGRAPHIC_ANOMALY = "Geographic Anomaly",
  DDoS = "DDoS",
  BRUTE_FORCE = "Brute Force Attempt",
  MALWARE_COMMS = "Malware Communication"
}

export enum SeverityLevel {
  LOW = "Low",
  MEDIUM = "Medium",
  HIGH = "High",
  CRITICAL = "Critical"
}

export enum Protocol {
  TCP = "TCP",
  UDP = "UDP",
  ICMP = "ICMP",
  HTTP = "HTTP",
  HTTPS = "HTTPS",
  DNS = "DNS",
  SSH = "SSH"
}

export interface NetworkAnomalyPayload {
  anomaly_id: string;
  timestamp: string; // ISO 8601 format
  behavior_type: BehaviorType;
  severity: SeverityLevel;
  
  // Network context
  source_ip: string;
  destination_ip?: string;
  protocol?: Protocol;
  port?: number;
  bytes_transferred?: number;
  
  // Additional metadata
  description: string;
  confidence_score?: number;
  mitigation_status: "pending" | "in_progress" | "resolved";
  related_threats?: string[];
}


