// eCyber/src/context/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom'; // Replaces useRouter from Next.js
import { storeAuthToken, removeAuthToken, apiClient, getAuthToken } from '@/services/api';
import { setAuthModalState } from '@/app/slices/displaySlice';
import { useDispatch } from 'react-redux';

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_two_factor_enabled?: boolean;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (token: string, userData?: User) => Promise<void>;
  logout: () => void;
  fetchUserProfile: () => Promise<void>;
  updateUser2FAStatus: (is_enabled: boolean) => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

const getCurrentUserProfile = async (): Promise<{ success: boolean; user?: User; message?: string }> => {
  const token = getAuthToken();
  if (!token) return { success: false, message: "No token found." };

  try {
    const response = await apiClient.get<User>('/auth/me');
    return { success: true, user: response.data };
  } catch (error: any) {
    const message = error.response?.data?.detail || error.message || "Failed to fetch profile.";
    return { success: false, message };
  }
};

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate(); // React Router navigation
  const dispatch = useDispatch();

  useEffect(() => {
    const initializeAuth = async () => {
      if (!token) {
        setIsLoading(false);
        return;
      }

      const result = await getCurrentUserProfile();
      if (result.success && result.user) {
        setUser(result.user);
      } else {
        logout();
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, [token]);

  const login = async (authToken: string, userData?: User) => {
    storeAuthToken(authToken);
    setToken(authToken);

    if (userData) {
      setUser(userData);
    } else {
      const result = await getCurrentUserProfile();
      if (result.success && result.user) {
        setUser(result.user);
      }
    }

    navigate('/dashboard'); // Redirect after login (optional)
  };

  const logout = () => {
    removeAuthToken();
    setToken(null);
    setUser(null);
    navigate('/'); // Redirect after logout
  };

  const fetchUserProfile = async () => {
    const result = await getCurrentUserProfile();
    if (result.success && result.user) {
      setUser(result.user);
    }
  };

  const updateUser2FAStatus = (is_enabled: boolean) => {
    if (user) {
      setUser({ ...user, is_two_factor_enabled: is_enabled });
    }
  };

  const value: AuthState = {
    user,
    token,
    isLoading,
    isAuthenticated: !!user && !!token,
    login,
    logout,
    fetchUserProfile,
    updateUser2FAStatus,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthState => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
