import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'


import { Threat, NetworkPacket, FirewallLog, FirewallRule, NetworkStats } from '@/types/types'

export const cyberwatchApi = createApi({
  reducerPath: 'cyberwatchApi',
  baseQuery: fetchBaseQuery({ 
    baseUrl: '/api',
    prepareHeaders: (headers) => {
      const token = localStorage.getItem('token')
      if (token) {
        headers.set('Authorization', `Bearer ${token}`)
      }
      return headers
    }
  }),
  tagTypes: ['Threats', 'Packets', 'FirewallRules', 'Logs'],
  endpoints: (builder) => ({
    // Threat endpoints
    getThreats: builder.query<Threat[], void>({
      query: () => '/threats',
      providesTags: ['Threats'],
      transformResponse: (response: { data: Threat[] }) => response.data
    }),

    getThreatById: builder.query<Threat, string>({
      query: (id) => `/threats/${id}`,
      providesTags: (result, error, id) => [{ type: 'Threats', id }]
    }),

    // Network endpoints
    getNetworkPackets: builder.query<NetworkPacket[], void>({
      query: () => '/network/packets',
      providesTags: ['Packets']
    }),

    getNetworkStats: builder.query<NetworkStats, void>({
      query: () => '/network/stats',
      pollingInterval: 5000 // Refresh every 5 seconds
    }),

    // Firewall endpoints
    getFirewallRules: builder.query<FirewallRule[], void>({
      query: () => '/firewall/rules',
      providesTags: ['FirewallRules']
    }),

    addFirewallRule: builder.mutation<FirewallRule, Partial<FirewallRule>>({
      query: (body) => ({
        url: '/firewall/rules',
        method: 'POST',
        body
      }),
      invalidatesTags: ['FirewallRules']
    }),

    // Log endpoints
    getLogs: builder.query<FirewallLog[], { limit?: number }>({
      query: ({ limit = 100 }) => `/logs?limit=${limit}`,
      providesTags: ['Logs']
    }),
  }),
})

export const {
  useGetThreatsQuery,
  useGetThreatByIdQuery,
  useGetNetworkPacketsQuery,
  useGetNetworkStatsQuery,
  useGetFirewallRulesQuery,
  useAddFirewallRuleMutation,
  useGetLogsQuery,
} = cyberwatchApi