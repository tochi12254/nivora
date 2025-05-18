import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { NetworkPacket, NetworkStats } from './networkTypes'

interface NetworkState {
  packets: NetworkPacket[]
  stats: NetworkStats | null
  status: 'idle' | 'loading' | 'succeeded' | 'failed'
  error: string | null
}

const initialState: NetworkState = {
  packets: [],
  stats: null,
  status: 'idle',
  error: null
}

const networkSlice = createSlice({
  name: 'network',
  initialState,
  reducers: {
    packetReceived(state, action: PayloadAction<NetworkPacket>) {
      // Keep only the last 500 packets
      state.packets = [action.payload, ...state.packets.slice(0, 499)]
    },
    statsUpdated(state, action: PayloadAction<NetworkStats>) {
      state.stats = action.payload
    },
    clearPackets(state) {
      state.packets = []
    },
    setNetworkStatus(state, action: PayloadAction<{
      status: 'idle' | 'loading' | 'succeeded' | 'failed'
      error?: string | null
    }>) {
      state.status = action.payload.status
      state.error = action.payload.error || null
    }
  }
})

export const { packetReceived, statsUpdated, clearPackets, setNetworkStatus } = networkSlice.actions

export default networkSlice.reducer