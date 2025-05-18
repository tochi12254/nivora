import { configureStore } from '@reduxjs/toolkit'
import { cyberwatchApi } from '@/features/api/cyberwatchApi'
import websocketReducer from '../features/websocket/websocketSlice'
import displaySlice from '@/features/display/displaySlice'
import socketSlice  from './slices/socketSlice'

export const store = configureStore({
  reducer: {
    [cyberwatchApi.reducerPath]: cyberwatchApi.reducer,
    // websocket: websocketReducer,
    display: displaySlice,
    socket:socketSlice,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(cyberwatchApi.middleware),
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch




