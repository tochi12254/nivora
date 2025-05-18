// features/firewall/firewallApi.ts
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import { 
  FirewallRule, 
  FirewallLog,
  FirewallRuleAction,
  FirewallRuleDirection
} from './firewallTypes'

export const firewallApi = createApi({
  reducerPath: 'firewallApi',
  baseQuery: fetchBaseQuery({ 
    baseUrl: '/api/firewall',
    prepareHeaders: (headers) => {
      const token = localStorage.getItem('token')
      if (token) {
        headers.set('Authorization', `Bearer ${token}`)
      }
      return headers
    }
  }),
  tagTypes: ['FirewallRules', 'FirewallLogs'],
  endpoints: (builder) => ({
    // Get all firewall rules
    getFirewallRules: builder.query<FirewallRule[], void>({
      query: () => '/rules',
      providesTags: ['FirewallRules'],
      transformResponse: (response: { data: FirewallRule[] }) => response.data
    }),

    // Add a new firewall rule
    addFirewallRule: builder.mutation<FirewallRule, Partial<FirewallRule>>({
      query: (rule) => ({
        url: '/rules',
        method: 'POST',
        body: rule
      }),
      invalidatesTags: ['FirewallRules']
    }),

    // Delete a firewall rule
    deleteFirewallRule: builder.mutation<void, string>({
      query: (ruleId) => ({
        url: `/rules/${ruleId}`,
        method: 'DELETE'
      }),
      invalidatesTags: ['FirewallRules']
    }),

    // Get firewall logs
    getFirewallLogs: builder.query<FirewallLog[], { 
      limit?: number 
      action?: FirewallRuleAction
      direction?: FirewallRuleDirection
    }>({
      query: (params) => ({
        url: '/logs',
        params: {
          limit: params.limit || 100,
          action: params.action,
          direction: params.direction
        }
      }),
      providesTags: ['FirewallLogs'],
      transformResponse: (response: { data: FirewallLog[] }) => response.data
    }),

    // Block an IP address
    blockIpAddress: builder.mutation<void, { 
      ip: string 
      timeout?: number 
      direction?: FirewallRuleDirection
    }>({
      query: ({ ip, timeout = 3600, direction = 'in' }) => ({
        url: '/block',
        method: 'POST',
        body: { ip, timeout, direction }
      }),
      invalidatesTags: ['FirewallRules', 'FirewallLogs']
    }),

    // Unblock an IP address
    unblockIpAddress: builder.mutation<void, string>({
      query: (ip) => ({
        url: `/block/${ip}`,
        method: 'DELETE'
      }),
      invalidatesTags: ['FirewallRules', 'FirewallLogs']
    }),

    // Get blocked IPs
    getBlockedIps: builder.query<string[], void>({
      query: () => '/blocked',
      providesTags: ['FirewallRules']
    }),

    // Export firewall rules
    exportFirewallRules: builder.query<string, void>({
      query: () => ({
        url: '/export',
        responseHandler: (response) => response.text()
      })
    }),

    // Import firewall rules
    importFirewallRules: builder.mutation<void, string>({
      query: (rulesConfig) => ({
        url: '/import',
        method: 'POST',
        body: { config: rulesConfig },
        headers: {
          'Content-Type': 'application/json'
        }
      }),
      invalidatesTags: ['FirewallRules']
    })
  })
})

// Export hooks for usage in components
export const {
  useGetFirewallRulesQuery,
  useAddFirewallRuleMutation,
  useDeleteFirewallRuleMutation,
  useGetFirewallLogsQuery,
  useBlockIpAddressMutation,
  useUnblockIpAddressMutation,
  useGetBlockedIpsQuery,
  useExportFirewallRulesQuery,
  useImportFirewallRulesMutation
} = firewallApi