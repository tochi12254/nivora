export interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  lastLogin?: string
}

export interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  status: 'idle' | 'loading' | 'succeeded' | 'failed'
  error: string | null
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface TokenResponse {
  token: string
  refreshToken: string
  user: User
}