// src/services/socket.ts
import { io, Socket } from "socket.io-client";

const socket: Socket = io("http://127.0.0.1:8000", {
  transports: ["websocket"],
  autoConnect: false,
});

export const connectSocket = () => {
  if (!socket.connected) {
    socket.connect();
  }
};

export const disconnectSocket = () => {
  if (socket.connected) {
    socket.disconnect();
  }
};

// Packet monitoring events
export const setupPacketListeners = (callback: (packet: any) => void) => {
  socket.on("packet_received", callback);
  socket.on("traffic_stats", (stats) => {
    console.log("Traffic stats update:", stats);
  });
  socket.on("threat_detected", (threat) => {
    console.log("Threat detected:", threat);
  });
};

export const startSniffing = (intrfc: string, filter?: string) => {
  socket.emit("start_sniffing", { intrfc, filter });
};

export const stopSniffing = () => {
  socket.emit("stop_sniffing");
};