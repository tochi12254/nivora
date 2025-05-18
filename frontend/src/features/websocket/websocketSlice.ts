// features/websocket/websocketSlice.ts
import { createSlice, PayloadAction } from '@reduxjs/toolkit';

import { Threat, NetworkPacket, WebSocketState } from '@/types/types';
const initialState: WebSocketState = {
  threats: [],
  packets: [],
  connected: false,
  error: null
};

const websocketSlice = createSlice({
  name: 'websocket',
  initialState,
  reducers: {
    connectionEstablished: (state) => {
      state.connected = true;
      state.error = null;
    },
    connectionLost: (state, action: PayloadAction<string>) => {
      state.connected = false;
      state.error = action.payload;
    },
    threatDetected: (state, action: PayloadAction<Threat>) => {
      // Keep only the last 100 threats to prevent memory issues
      state.threats = [action.payload, ...state.threats.slice(0, 99)];
    },
    packetReceived: (state, action: PayloadAction<NetworkPacket>) => {
      // Keep only the last 200 packets to prevent memory issues
      state.packets = [action.payload, ...state.packets.slice(0, 199)];
    },
    clearThreats: (state) => {
      state.threats = [];
    },
    clearPackets: (state) => {
      state.packets = [];
    }
  }
});

export const { 
  connectionEstablished, 
  connectionLost, 
  threatDetected, 
  packetReceived,
  clearThreats,
  clearPackets
} = websocketSlice.actions;

export default websocketSlice.reducer;



// // In your WebSocket message handler
// if (data.type === 'threat' && isThreat(data.payload)) {
//   store.dispatch(threatDetected(data.payload));
// } else if (data.type === 'packet' && isNetworkPacket(data.payload)) {
//   store.dispatch(packetReceived(data.payload));
// }