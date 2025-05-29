import { configureStore } from '@reduxjs/toolkit'

import socketSlice  from './slices/socketSlice'
import { dnsActivityReducer,firewallEventsReducer,
  threatDetectionsReducer,
  ipv6ActivityReducer,
  packetDataReducer,
  systemMetricsReducer,
  securityAlertsReducer,
  phishingDetectionsReducer,
  threatResponsesReducer,
  quarantinedFilesReducer } from './slices/realtimeDataSlice'

export const store = configureStore({
  reducer: {
    socket:socketSlice,
    dnsActivity: dnsActivityReducer,
    firewallEvents: firewallEventsReducer,
    threatDetections: threatDetectionsReducer,
    ipv6Activity: ipv6ActivityReducer,
    packetData: packetDataReducer,
    systemMetrics: systemMetricsReducer,
    securityAlerts: securityAlertsReducer,
    phishingDetections: phishingDetectionsReducer,
    threatResponses: threatResponsesReducer,
    quarantinedFiles: quarantinedFilesReducer,
  },
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
// This file sets up the Redux store for the application, integrating various slices for real-time data management. 