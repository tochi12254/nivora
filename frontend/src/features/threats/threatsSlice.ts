import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit'
import { Threat, ThreatSeverity } from './threatTypes'
import { getThreatsApi, acknowledgeThreatApi } from './threatsApi'

interface ThreatsState {
  threats: Threat[]
  acknowledged: string[] // IDs of acknowledged threats
  filters: {
    severity: ThreatSeverity | 'all'
    timeRange: '24h' | '7d' | '30d' | 'all'
  }
  status: 'idle' | 'loading' | 'succeeded' | 'failed'
  error: string | null
}

const initialState: ThreatsState = {
  threats: [],
  acknowledged: [],
  filters: {
    severity: 'all',
    timeRange: '24h'
  },
  status: 'idle',
  error: null
}

export const fetchThreats = createAsyncThunk(
  'threats/fetchThreats',
  async (_, { rejectWithValue }) => {
    try {
      return await getThreatsApi()
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

export const acknowledgeThreat = createAsyncThunk(
  'threats/acknowledge',
  async (threatId: string, { rejectWithValue }) => {
    try {
      await acknowledgeThreatApi(threatId)
      return threatId
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

const threatsSlice = createSlice({
  name: 'threats',
  initialState,
  reducers: {
    threatDetected(state, action: PayloadAction<Threat>) {
      state.threats = [action.payload, ...state.threats]
    },
    setSeverityFilter(state, action: PayloadAction<ThreatSeverity | 'all'>) {
      state.filters.severity = action.payload
    },
    setTimeRangeFilter(state, action: PayloadAction<'24h' | '7d' | '30d' | 'all'>) {
      state.filters.timeRange = action.payload
    }
  },
  extraReducers: builder => {
    builder
      .addCase(fetchThreats.pending, (state) => {
        state.status = 'loading'
      })
      .addCase(fetchThreats.fulfilled, (state, action) => {
        state.status = 'succeeded'
        state.threats = action.payload
      })
      .addCase(fetchThreats.rejected, (state, action) => {
        state.status = 'failed'
        state.error = action.payload as string
      })
      .addCase(acknowledgeThreat.fulfilled, (state, action) => {
        state.acknowledged.push(action.payload)
      })
  }
})

export const { threatDetected, setSeverityFilter, setTimeRangeFilter } = threatsSlice.actions

export default threatsSlice.reducer