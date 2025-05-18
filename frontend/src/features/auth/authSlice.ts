import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { AppThunk } from '../../app/store'
import { loginApi, refreshTokenApi } from './authApi'
import { AuthState, LoginCredentials, User } from './authTypes'

const initialState: AuthState = {
  user: null,
  token: null,
  refreshToken: null,
  status: 'idle',
  error: null
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    loginStart(state) {
      state.status = 'loading'
      state.error = null
    },
    loginSuccess(state, action: PayloadAction<{
      user: User
      token: string
      refreshToken: string
    }>) {
      state.user = action.payload.user
      state.token = action.payload.token
      state.refreshToken = action.payload.refreshToken
      state.status = 'succeeded'
    },
    loginFailed(state, action: PayloadAction<string>) {
      state.status = 'failed'
      state.error = action.payload
    },
    logout(state) {
      state.user = null
      state.token = null
      state.refreshToken = null
      state.status = 'idle'
    },
    tokenRefreshed(state, action: PayloadAction<string>) {
      state.token = action.payload
    }
  }
})

export const { loginStart, loginSuccess, loginFailed, logout, tokenRefreshed } = authSlice.actions

export default authSlice.reducer

// Thunk for login
export const login = (credentials: LoginCredentials): AppThunk => async dispatch => {
  try {
    dispatch(loginStart())
    const response = await loginApi(credentials)
    dispatch(loginSuccess(response))
    localStorage.setItem('token', response.token)
    localStorage.setItem('refreshToken', response.refreshToken)
  } catch (err) {
    dispatch(loginFailed(err.message))
  }
}

// Thunk for token refresh
export const refreshToken = (): AppThunk => async (dispatch, getState) => {
  const { refreshToken } = getState().auth
  if (!refreshToken) return

  try {
    const newToken = await refreshTokenApi(refreshToken)
    dispatch(tokenRefreshed(newToken))
    localStorage.setItem('token', newToken)
  } catch (err) {
    dispatch(logout())
  }
}