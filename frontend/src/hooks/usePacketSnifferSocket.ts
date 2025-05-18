import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { useDispatch } from 'react-redux';
import { 
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
  handleSocketEvent
} from '@/app/slices/socketSlice';




import { 
  PacketMetadata,
  ThreatData,
  PhishingData,
  NetworkAnomaly,
  AccessData,
  FirewallEvent,
  CriticalAlert,
  Alert,
  FileQuarantined,
  ThreatResponse,
  HttpActivity,
  DnsQuery,
  IPv6Activity,
  ConnectionAnalysis,
  SystemStats,
  SystemStatus,
  SystemTelemetry,
  ErrorData,
  ServiceStatus,
  ProcessInspection,
  TrainingProgress,
  UrlClassification,
  FirewallData,
  SshConnection,
  Rule,
  SystemSnapshot
} from './useSocket';



export type PacketSnifferEvent =
  | { type: 'packet_data'; data: PacketMetadata }
  | { type: 'network_anomaly'; data: NetworkAnomaly }
  | { type: 'http_activity'; data: HttpActivity }
  | { type: 'dns_activity'; data: DnsQuery }
  | { type: 'ipv6_activity'; data: IPv6Activity }
  | { type: 'connection_analysis'; data: ConnectionAnalysis }
  | { type: 'threat_detected'; data: ThreatData }
  | { type: 'phishing_link_detected'; data: PhishingData }
  | { type: 'unauthorized_access'; data: AccessData }
  | { type: 'critical_alert'; data: CriticalAlert }
  | { type: 'security_alert'; data: Alert }
  | { type: 'file_quarantined'; data: FileQuarantined }
  | { type: 'threat_response'; data: ThreatResponse }
  | { type: 'firewall_blocked'; data: FirewallData }
  | { type: 'firewall_event'; data: FirewallEvent }
  | { type: 'ssh_connection'; data: SshConnection }
  | { type: 'system_stats'; data: SystemStats }
  | { type: 'system_status'; data: SystemStatus }
  | { type: 'system_telemetry'; data: SystemTelemetry }
  | { type: 'system_error'; data: ErrorData }
  | { type: 'service_status'; data: ServiceStatus }
  | { type: 'process_inspection'; data: ProcessInspection }
  | { type: 'system_snapshot'; data: SystemSnapshot }
  | { type: 'training_progress'; data: TrainingProgress }
  | { type: 'training_completed'; data: null }
  | { type: 'url_classification_result'; data: UrlClassification }
  | { type: 'get_rules'; data: Rule[] }
  | { type: 'rules_updated'; data: { count: number } };

interface UsePacketSnifferSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  connectionError: string | null;
  connect: () => void;
  disconnect: () => void;
  emitEvent: <T extends PacketSnifferEvent['type']>(
    type: T, 
    data: Extract<PacketSnifferEvent, { type: T }>['data']
  ) => void;
}

const ALL_SOCKET_EVENTS: PacketSnifferEvent['type'][] = [
  'packet_data', 'network_anomaly', 'http_activity', 'dns_activity',
  'ipv6_activity', 'connection_analysis', 'threat_detected', 'phishing_link_detected',
  'unauthorized_access', 'critical_alert', 'security_alert', 'file_quarantined',
  'threat_response', 'firewall_blocked', 'firewall_event', 'ssh_connection',
  'system_stats', 'system_status', 'system_telemetry', 'system_error',
  'service_status', 'process_inspection', 'system_snapshot', 'training_progress',
  'training_completed', 'url_classification_result', 'get_rules', 'rules_updated'
];

export function usePacketSnifferSocket(): UsePacketSnifferSocketReturn {
  const dispatch = useDispatch();
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const initialized = useRef(false);

  const handleEvent = useCallback((event: PacketSnifferEvent) => {
    // Dispatch to Redux first
    dispatch(handleSocketEvent(event));
    
    // Then handle specific events with their dedicated actions
    switch (event.type) {
      case 'packet_data':
        dispatch(addPacketData(event.data));
        break;
      case 'threat_detected':
        dispatch(addThreat(event.data));
        break;
      case 'firewall_event':
        dispatch(addFirewallEvent(event.data));
        break;
      case 'phishing_link_detected':
        dispatch(addPhishingLink(event.data));
        break;
      case 'unauthorized_access':
        dispatch(addUnauthorizedAccess(event.data));
        break;
      case 'critical_alert':
        dispatch(addCriticalAlert(event.data));
        break;
      case 'security_alert':
        dispatch(addSecurityAlert(event.data));
        break;
      case 'file_quarantined':
        dispatch(addFileQuarantine(event.data));
        break;
      case 'threat_response':
        dispatch(addThreatResponse(event.data));
        break;
      case 'network_anomaly':
        dispatch(addNetworkAnomaly(event.data));
        break;
      case 'http_activity':
        dispatch(addHttpActivity(event.data));
        break;
      case 'dns_activity':
        dispatch(addDnsQuery(event.data));
        break;
      case 'ipv6_activity':
        dispatch(addIpv6Activity(event.data));
        break;
      case 'connection_analysis':
        dispatch(addConnectionAnalysis(event.data));
        break;
      case 'system_stats':
        dispatch(addSystemStat(event.data));
        break;
      case 'system_status':
        dispatch(setSystemStatus(event.data));
        break;
      case 'system_telemetry':
        dispatch(addSystemTelemetry(event.data));
        break;
      case 'system_error':
        dispatch(addSystemError(event.data));
        break;
      case 'service_status':
        dispatch(addServiceStatus(event.data));
        break;
      case 'process_inspection':
        dispatch(addProcessInspection(event.data));
        break;
      case 'training_progress':
        dispatch(setTrainingProgress(event.data));
        break;
      case 'training_completed':
        dispatch(setTrainingCompleted());
        break;
      case 'url_classification_result':
        dispatch(addUrlClassification(event.data));
        break;
      case 'firewall_blocked':
        dispatch(addFirewallBlock(event.data));
        break;
      case 'ssh_connection':
        dispatch(addSshConnection(event.data));
        break;
      case 'get_rules':
        dispatch(setRules(event.data));
        break;
      case 'system_snapshot':
        dispatch(addSystemSnapshot(event.data));
        break;
      default:
        // Handle any untyped events
        console.warn('Unhandled event type:', event.type);
    }
  }, [dispatch]);

  const connect = useCallback(() => {
    if (socketRef.current?.connected || initialized.current) return;

    const newSocket = io('http://127.0.0.1:8000/packet_sniffer', {
      path: '/socket.io',
      transports: ['websocket'],
      reconnectionAttempts: 5,
      reconnectionDelay: 3000,
      autoConnect: false,
      upgrade: false,
    });

    newSocket
      .on('connect', () => {
        setIsConnected(true);
        setConnectionError(null);
        dispatch(setConnectionStatus(true));
        console.log("✅ Packet Sniffer Socket connected");
      })
      .on('connect_error', (err) => {
        setConnectionError(err.message);
        dispatch(setConnectionError(err.message));
        console.error('❌ Connection Error:', err);
      })
      .on('disconnect', () => {
        setIsConnected(false);
        dispatch(setConnectionStatus(false));
        console.warn('⚠️ Socket Disconnected');
      });

    ALL_SOCKET_EVENTS.forEach(event => {
      newSocket.on(event, (data: any) => handleEvent({ type: event, data } as PacketSnifferEvent));
    });

    newSocket.connect();
    socketRef.current = newSocket;
    initialized.current = true;
  }, [dispatch, handleEvent]);

  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
      initialized.current = false;
      setIsConnected(false);
      dispatch(setConnectionStatus(false));
      console.log('🔌 Socket Disconnected');
    }
  }, [dispatch]);

  const emitEvent = useCallback<UsePacketSnifferSocketReturn['emitEvent']>((type, data) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(type, data);
    } else {
      console.warn('⚠️ Cannot emit event - socket not connected');
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    socket: socketRef.current,
    isConnected,
    connectionError,
    connect,
    disconnect,
    emitEvent,
  };
}