import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { SocketEvent } from '@/hooks/useSocket';

// Define all the interfaces (they're already in your useSocket.ts, but we'll include relevant ones here)
interface ThreatDat { id: string; message: string; severity: 'low' | 'medium' | 'high'; }
interface PhishingData { url: string; confidence: number; }
interface TrainingProgress { epoch: number; accuracy: number; loss: number; }
interface NetworkAnomaly { type: string; packetCount: number; }
interface AccessData { user: string; sourceIp: string; }
interface FirewallData { rule: string; action: 'block' | 'allow'; }
interface UrlClassification { url: string; category: string; confidence: number; }
interface ServiceStatus { name: string; status: 'running' | 'stopped'; uptime?: number; }
interface Alert { message: string; timestamp: string; }
interface HttpActivity { endpoint: string; method: string; statusCode: number; }
interface DnsQuery { domain: string; recordType: string; }
interface ErrorData { error: string; code?: number; }
interface SshConnection { ip: string; user?: string; }
interface FirewallEvent { ip: string; type: 'block' | 'allow'; reason: string; }
interface Rule { id: string; name: string; description: string; }
interface SystemStats { cpu: number; memory: number; network: number; }
interface SystemStatus { online: boolean; services: string[]; }
interface IPv6Activity { source: string; destination: string; payloadSize: number; }
interface CriticalAlert { type: string; source: string; mitigation: string; }
interface SystemTelemetry { cpu: number; memory: number; processes: ProcessInfo[]; }
interface ThreatResponse { action: string; target: string; success: boolean; }
interface ProcessInspection { pid: number; name: string; suspicious: boolean; }
interface ConnectionAnalysis { protocol: string; count: number; riskScore: number; }
interface FileQuarantined { path: string; hash: string; reason: string; }
interface SystemSnapshot { timestamp: string; metrics: SystemStats; }
interface ProcessInfo { pid: number; name: string; cpu: number; memory: number; }
interface PacketMetadata {
  timestamp: number;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: number | null;
  length: number;
  src_port: number | null;
  dst_port: number | null;
  payload: string | null;
}

interface SocketState {
  isConnected: boolean;
  connectionError: string | null;
  // Security events
  threats: ThreatData[];
  firewallEvents: FirewallEvent[];
  phishingLinks: PhishingData[];
  unauthorizedAccess: AccessData[];
  criticalAlerts: CriticalAlert[];
  securityAlerts: Alert[];
  fileQuarantines: FileQuarantined[];
  threatResponses: ThreatResponse[];
  
  // Network events
  networkAnomalies: NetworkAnomaly[];
  httpActivities: HttpActivity[];
  dnsQueries: DnsQuery[];
  ipv6Activities: IPv6Activity[];
  packetData: PacketMetadata[];
  connectionAnalyses: ConnectionAnalysis[];
  
  // System events
  systemStats: SystemStats[];
  systemStatus: SystemStatus | null;
  systemTelemetry: SystemTelemetry[];
  systemErrors: ErrorData[];
  serviceStatuses: ServiceStatus[];
  processInspections: ProcessInspection[];
  
  // Training events
  trainingProgress: TrainingProgress | null;
  trainingCompleted: boolean;
  
  // Other events
  urlClassifications: UrlClassification[];
  firewallBlocks: FirewallData[];
  sshConnections: SshConnection[];
  rules: Rule[];
  systemSnapshots: SystemSnapshot[];
  
  // Latest event timestamps
  lastUpdated: {
    [key in SocketEvent['type']]?: string;
  };
}

const initialState: SocketState = {
  isConnected: false,
  connectionError: null,
  threats: [],
  firewallEvents: [],
  phishingLinks: [],
  unauthorizedAccess: [],
  criticalAlerts: [],
  securityAlerts: [],
  fileQuarantines: [],
  threatResponses: [],
  networkAnomalies: [],
  httpActivities: [],
  dnsQueries: [],
  ipv6Activities: [],
  packetData: [],
  connectionAnalyses: [],
  systemStats: [],
  systemStatus: null,
  systemTelemetry: [],
  systemErrors: [],
  serviceStatuses: [],
  processInspections: [],
  trainingProgress: null,
  trainingCompleted: false,
  urlClassifications: [],
  firewallBlocks: [],
  sshConnections: [],
  rules: [],
  systemSnapshots: [],
  lastUpdated: {},
};

const socketSlice = createSlice({
  name: 'socket',
  initialState,
  reducers: {
    // Connection management
    setConnectionStatus(state, action: PayloadAction<boolean>) {
      state.isConnected = action.payload;
    },
    setConnectionError(state, action: PayloadAction<string | null>) {
      state.connectionError = action.payload;
    },
    
    // Security event reducers
    addThreat(state, action: PayloadAction<ThreatData>) {
      state.threats.push(action.payload);
      state.lastUpdated['threat_detected'] = new Date().toISOString();
    },
    addFirewallEvent(state, action: PayloadAction<FirewallEvent>) {
      state.firewallEvents.push(action.payload);
      state.lastUpdated['firewall_event'] = new Date().toISOString();
    },
    addPhishingLink(state, action: PayloadAction<PhishingData>) {
      state.phishingLinks.push(action.payload);
      state.lastUpdated['phishing_link_detected'] = new Date().toISOString();
    },
    addUnauthorizedAccess(state, action: PayloadAction<AccessData>) {
      state.unauthorizedAccess.push(action.payload);
      state.lastUpdated['unauthorized_access'] = new Date().toISOString();
    },
    addCriticalAlert(state, action: PayloadAction<CriticalAlert>) {
      state.criticalAlerts.push(action.payload);
      state.lastUpdated['critical_alert'] = new Date().toISOString();
    },
    addSecurityAlert(state, action: PayloadAction<Alert>) {
      state.securityAlerts.push(action.payload);
      state.lastUpdated['security_alert'] = new Date().toISOString();
    },
    addFileQuarantine(state, action: PayloadAction<FileQuarantined>) {
      state.fileQuarantines.push(action.payload);
      state.lastUpdated['file_quarantined'] = new Date().toISOString();
    },
    addThreatResponse(state, action: PayloadAction<ThreatResponse>) {
      state.threatResponses.push(action.payload);
      state.lastUpdated['threat_response'] = new Date().toISOString();
    },
    
    // Network event reducers
    addNetworkAnomaly(state, action: PayloadAction<NetworkAnomaly>) {
      state.networkAnomalies.push(action.payload);
      state.lastUpdated['network_anomaly'] = new Date().toISOString();
    },
    addHttpActivity(state, action: PayloadAction<HttpActivity>) {
      state.httpActivities.push(action.payload);
      state.lastUpdated['http_activity'] = new Date().toISOString();
    },
    addDnsQuery(state, action: PayloadAction<DnsQuery>) {
      state.dnsQueries.push(action.payload);
      state.lastUpdated['dns_activity'] = new Date().toISOString();
    },
    addIpv6Activity(state, action: PayloadAction<IPv6Activity>) {
      state.ipv6Activities.push(action.payload);
      state.lastUpdated['ipv6_activity'] = new Date().toISOString();
    },
    addPacketData(state, action: PayloadAction<PacketMetadata>) {
      state.packetData.push(action.payload);
      state.lastUpdated['packet_data'] = new Date().toISOString();
    },
    addConnectionAnalysis(state, action: PayloadAction<ConnectionAnalysis>) {
      state.connectionAnalyses.push(action.payload);
      state.lastUpdated['connection_analysis'] = new Date().toISOString();
    },
    
    // System event reducers
    addSystemStat(state, action: PayloadAction<SystemStats>) {
      state.systemStats.push(action.payload);
      if (state.systemStats.length > 100) state.systemStats.shift(); // Keep last 100 entries
      state.lastUpdated['system_stats'] = new Date().toISOString();
    },
    setSystemStatus(state, action: PayloadAction<SystemStatus>) {
      state.systemStatus = action.payload;
      state.lastUpdated['system_status'] = new Date().toISOString();
    },
    addSystemTelemetry(state, action: PayloadAction<SystemTelemetry>) {
      state.systemTelemetry.push(action.payload);
      if (state.systemTelemetry.length > 50) state.systemTelemetry.shift(); // Keep last 50 entries
      state.lastUpdated['system_telemetry'] = new Date().toISOString();
    },
    addSystemError(state, action: PayloadAction<ErrorData>) {
      state.systemErrors.push(action.payload);
      state.lastUpdated['system_error'] = new Date().toISOString();
    },
    addServiceStatus(state, action: PayloadAction<ServiceStatus>) {
      state.serviceStatuses.push(action.payload);
      state.lastUpdated['service_status'] = new Date().toISOString();
    },
    addProcessInspection(state, action: PayloadAction<ProcessInspection>) {
      state.processInspections.push(action.payload);
      state.lastUpdated['process_inspection'] = new Date().toISOString();
    },
    
    // Training event reducers
    setTrainingProgress(state, action: PayloadAction<TrainingProgress>) {
      state.trainingProgress = action.payload;
      state.lastUpdated['training_progress'] = new Date().toISOString();
    },
    setTrainingCompleted(state) {
      state.trainingCompleted = true;
      state.lastUpdated['training_completed'] = new Date().toISOString();
    },
    
    // Other event reducers
    addUrlClassification(state, action: PayloadAction<UrlClassification>) {
      state.urlClassifications.push(action.payload);
      state.lastUpdated['url_classification_result'] = new Date().toISOString();
    },
    addFirewallBlock(state, action: PayloadAction<FirewallData>) {
      state.firewallBlocks.push(action.payload);
      state.lastUpdated['firewall_blocked'] = new Date().toISOString();
    },
    addSshConnection(state, action: PayloadAction<SshConnection>) {
      state.sshConnections.push(action.payload);
      state.lastUpdated['ssh_connection'] = new Date().toISOString();
    },
    setRules(state, action: PayloadAction<Rule[]>) {
      state.rules = action.payload;
      state.lastUpdated['get_rules'] = new Date().toISOString();
    },
    addSystemSnapshot(state, action: PayloadAction<SystemSnapshot>) {
      state.systemSnapshots.push(action.payload);
      state.lastUpdated['system_snapshot'] = new Date().toISOString();
    },
    
    // Clear actions for when you need to reset certain state
    clearThreats(state) {
      state.threats = [];
    },
    clearFirewallEvents(state) {
      state.firewallEvents = [];
    },
    clearNetworkAnomalies(state) {
      state.networkAnomalies = [];
    },
    clearAll(state) {
      return { ...initialState, isConnected: state.isConnected };
    },
    
    // Generic event handler that can handle any SocketEvent
    handleSocketEvent(state, action: PayloadAction<SocketEvent>) {
      const { type, data } = action.payload;
      state.lastUpdated[type] = new Date().toISOString();
    },
  },
});

// Export all actions
export const {
  setConnectionStatus,
  setConnectionError,
  addThreat,
  addFirewallEvent,
  addPhishingLink,
  addUnauthorizedAccess,
  addCriticalAlert,
  addSecurityAlert,
  addFileQuarantine,
  addThreatResponse,
  addNetworkAnomaly,
  addHttpActivity,
  addDnsQuery,
  addIpv6Activity,
  addPacketData,
  addConnectionAnalysis,
  addSystemStat,
  setSystemStatus,
  addSystemTelemetry,
  addSystemError,
  addServiceStatus,
  addProcessInspection,
  setTrainingProgress,
  setTrainingCompleted,
  addUrlClassification,
  addFirewallBlock,
  addSshConnection,
  setRules,
  addSystemSnapshot,
  clearThreats,
  clearFirewallEvents,
  clearNetworkAnomalies,
  clearAll,
  handleSocketEvent,
} = socketSlice.actions;

export default socketSlice.reducer;