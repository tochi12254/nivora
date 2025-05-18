import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

interface SystemTelemetry {
  cpu: number;
  memory: number;
  processes: any[];
}

type TelemetryEvent =
  | { type: 'system_telemetry'; data: SystemTelemetry };

interface UseTelemetrySocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  connectionError: string | null;
  connect: () => void;
  disconnect: () => void;
  emitEvent: <T extends TelemetryEvent['type']>(type: T, data: Extract<TelemetryEvent, { type: T }>['data']) => void;
  subscribe: <T extends TelemetryEvent['type']>(eventType: T, handler: (data: Extract<TelemetryEvent, { type: T }>['data']) => void) => void;
  unsubscribe: <T extends TelemetryEvent['type']>(eventType: T, handler: (data: Extract<TelemetryEvent, { type: T }>['data']) => void) => void;
}

export function useTelemetrySocket(): UseTelemetrySocketReturn {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const handlers = useRef(new Map<string, Set<Function>>());
  const initialized = useRef(false);

  const handleEvent = useCallback((event: TelemetryEvent) => {
    handlers.current.get(event.type)?.forEach(handler => handler(event.data));
  }, []);

  const connect = useCallback(() => {
    if (socketRef.current?.connected || initialized.current) return;

    const socket = io('http://127.0.0.1:8000/telemetry', {
      transports: ['websocket'],
      autoConnect: false,
    });

    socket.on('connect', () => {
      setIsConnected(true);
      setConnectionError(null);
      console.log('TelemetrySocket connected');
    });

    socket.on('connect_error', (err) => {
      setConnectionError(err.message);
      console.error('TelemetrySocket connection error:', err);
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      console.warn('TelemetrySocket disconnected');
    });

    socket.on('system_telemetry', (data) => handleEvent({ type: 'system_telemetry', data }));

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

  const emitEvent = useCallback(<T extends TelemetryEvent['type']>(type: T, data: Extract<TelemetryEvent, { type: T }>['data']) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(type, data);
    }
  }, []);

  const subscribe = useCallback(<T extends TelemetryEvent['type']>(eventType: T, handler: (data: Extract<TelemetryEvent, { type: T }>['data']) => void) => {
    if (!handlers.current.has(eventType)) {
      handlers.current.set(eventType, new Set());
    }
    handlers.current.get(eventType)!.add(handler);
  }, []);

  const unsubscribe = useCallback(<T extends TelemetryEvent['type']>(eventType: T, handler: (data: Extract<TelemetryEvent, { type: T }>['data']) => void) => {
    handlers.current.get(eventType)?.delete(handler);
  }, []);

  useEffect(() => {
    connect();
    return () => {
      disconnect();
      handlers.current.clear();
    };
  }, [connect, disconnect]);

  return { socket: socketRef.current, isConnected, connectionError, connect, disconnect, emitEvent, subscribe, unsubscribe };
}
