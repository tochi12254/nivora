import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit'
import { FirewallRule, FirewallLog } from './firewallTypes'
import { 
  getFirewallRulesApi, 
  addFirewallRuleApi, 
  deleteFirewallRuleApi,
  getFirewallLogsApi
} from './firewallApi'

interface FirewallState {
  rules: FirewallRule[]
  logs: FirewallLog[]
  status: 'idle' | 'loading' | 'succeeded' | 'failed'
  error: string | null
  activeTab: 'rules' | 'logs'
}

const initialState: FirewallState = {
  rules: [],
  logs: [],
  status: 'idle',
  error: null,
  activeTab: 'rules'
}

export const fetchFirewallRules = createAsyncThunk(
  'firewall/fetchRules',
  async (_, { rejectWithValue }) => {
    try {
      return await getFirewallRulesApi()
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

export const addFirewallRule = createAsyncThunk(
  'firewall/addRule',
  async (rule: Omit<FirewallRule, 'id' | 'created_at'>, { rejectWithValue }) => {
    try {
      return await addFirewallRuleApi(rule)
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

export const deleteFirewallRule = createAsyncThunk(
  'firewall/deleteRule',
  async (ruleId: string, { rejectWithValue }) => {
    try {
      await deleteFirewallRuleApi(ruleId)
      return ruleId
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

export const fetchFirewallLogs = createAsyncThunk(
  'firewall/fetchLogs',
  async (_, { rejectWithValue }) => {
    try {
      return await getFirewallLogsApi()
    } catch (err) {
      return rejectWithValue(err.message)
    }
  }
)

const firewallSlice = createSlice({
  name: 'firewall',
  initialState,
  reducers: {
    setActiveTab(state, action: PayloadAction<'rules' | 'logs'>) {
      state.activeTab = action.payload
    },
    ruleAdded(state, action: PayloadAction<FirewallRule>) {
      state.rules.push(action.payload)
    },
    logReceived(state, action: PayloadAction<FirewallLog>) {
      state.logs = [action.payload, ...state.logs.slice(0, 499)]
    }
  },
  extraReducers: builder => {
    builder
      .addCase(fetchFirewallRules.pending, (state) => {
        state.status = 'loading'
      })
      .addCase(fetchFirewallRules.fulfilled, (state, action) => {
        state.status = 'succeeded'
        state.rules = action.payload
      })
      .addCase(fetchFirewallRules.rejected, (state, action) => {
        state.status = 'failed'
        state.error = action.payload as string
      })
      .addCase(addFirewallRule.fulfilled, (state, action) => {
        state.rules.push(action.payload)
      })
      .addCase(deleteFirewallRule.fulfilled, (state, action) => {
        state.rules = state.rules.filter(rule => rule.id !== action.payload)
      })
      .addCase(fetchFirewallLogs.fulfilled, (state, action) => {
        state.logs = action.payload
      })
  }
})

export const { setActiveTab, ruleAdded, logReceived } = firewallSlice.actions

export default firewallSlice.reducer