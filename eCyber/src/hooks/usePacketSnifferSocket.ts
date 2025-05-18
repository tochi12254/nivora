import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

// ==================== Event Interfaces ====================
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
interface ThreatData { id: string; message: string; severity: 'low' | 'medium' | 'high'; }
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
  | { type: 'user_alert'; data: Alert }
  | { type: 'database_error'; data: ErrorData }
  | { type: 'detection_error'; data: ErrorData }
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
  subscribe: <T extends PacketSnifferEvent['type']>(
    eventType: T,
    handler: (data: Extract<PacketSnifferEvent, { type: T }>['data']) => void
  ) => void;
  unsubscribe: <T extends PacketSnifferEvent['type']>(
    eventType: T,
    handler: (data: Extract<PacketSnifferEvent, { type: T }>['data']) => void
  ) => void;
}

export function usePacketSnifferSocket(): UsePacketSnifferSocketReturn {
  const socketRef = useRef<Socket | null>(null);
  const handlers = useRef(new Map<string, Set<Function>>());
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const initialized = useRef(false);

  const handleEvent = useCallback((event: PacketSnifferEvent) => {
    handlers.current.get(event.type)?.forEach((handler) => handler(event.data));
  }, []);

  const connect = useCallback(() => {
    if (socketRef.current?.connected || initialized.current) return;

    const socket = io('http://127.0.0.1:8000/packet_sniffer', {
      transports: ['websocket'],
      autoConnect: false,
    });

    socket.on('connect', () => {
      setIsConnected(true);
      setConnectionError(null);
      console.log('[Socket] PacketSniffer connected');
    });

    socket.on('connect_error', (err) => {
      setConnectionError(err.message);
      console.error('[Socket] PacketSniffer connection error:', err);
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      console.warn('[Socket] PacketSniffer disconnected');
    });

    // Generic event proxy handler
    const allEventTypes: PacketSnifferEvent['type'][] = [
      'packet_data', 'network_anomaly', 'http_activity', 'dns_activity', 'ipv6_activity',
      'connection_analysis', 'threat_detected', 'phishing_link_detected', 'unauthorized_access',
      'critical_alert', 'security_alert', 'file_quarantined', 'threat_response',
      'firewall_blocked', 'firewall_event', 'ssh_connection', 'system_stats', 'system_status',
      'system_telemetry', 'system_error', 'service_status', 'process_inspection',
      'system_snapshot', 'training_progress', 'training_completed', 'url_classification_result',
      'get_rules', 'user_alert', 'database_error', 'detection_error', 'rules_updated'
    ];

    allEventTypes.forEach((event) => {
      socket.on(event, (data) => handleEvent({ type: event, data } as PacketSnifferEvent));
    });

    socket.connect();
    socketRef.current = socket;
    initialized.current = true;
  }, [handleEvent]);

  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
      initialized.current = false;
      setIsConnected(false);
    }
  }, []);

  const emitEvent = useCallback(
    <T extends PacketSnifferEvent['type']>(
      type: T,
      data: Extract<PacketSnifferEvent, { type: T }>['data']
    ) => {
      if (socketRef.current?.connected) {
        socketRef.current.emit(type, data);
      }
    },
    []
  );

  const subscribe = useCallback(
    <T extends PacketSnifferEvent['type']>(
      eventType: T,
      handler: (data: Extract<PacketSnifferEvent, { type: T }>['data']) => void
    ) => {
      if (!handlers.current.has(eventType)) {
        handlers.current.set(eventType, new Set());
      }
      handlers.current.get(eventType)!.add(handler);
    },
    []
  );

  const unsubscribe = useCallback(
    <T extends PacketSnifferEvent['type']>(
      eventType: T,
      handler: (data: Extract<PacketSnifferEvent, { type: T }>['data']) => void
    ) => {
      handlers.current.get(eventType)?.delete(handler);
    },
    []
  );

  useEffect(() => {
    connect();
    return () => {
      disconnect();
      handlers.current.clear();
    };
  }, [connect, disconnect]);

  return {
    socket: socketRef.current,
    isConnected,
    connectionError,
    connect,
    disconnect,
    emitEvent,
    subscribe,
    unsubscribe,
  };
}
