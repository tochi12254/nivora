// src/pages/Login.tsx
import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import axiosInstance from '@/api/axiosInstance';
import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { RootState } from '@/app/store';
import { useSelector, useDispatch } from 'react-redux';
import { Button } from '@/components/ui/button';
import { setIsLoginShown } from '@/features/display/displaySlice';

// Validation schemas
const loginSchema = yup.object().shape({
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup.string().required('Password is required').min(8, 'Password must be at least 8 characters'),
   username: yup.string(),
});

const registerSchema = yup.object().shape({
  username: yup.string().required('Username is required').min(3, 'Username must be at least 3 characters'),
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup.string().required('Password is required').min(8, 'Password must be at least 8 characters'),
  full_name: yup.string(),
});

type LoginFormData = yup.InferType<typeof loginSchema>;
type RegisterFormData = yup.InferType<typeof registerSchema>;

const Login = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const isLoginShown = useSelector((state: RootState) => state.display.isLoginShown);
  const dispatch = useDispatch();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<LoginFormData | RegisterFormData>({
    resolver: yupResolver(isLogin ? loginSchema : registerSchema),
  });

  const handleFormSubmit = async (data: LoginFormData | RegisterFormData) => {
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        // Handle login
        const response = await axiosInstance.post('/api/auth/login', {
          email: data.email,
          password: data.password,
        });
        localStorage.setItem('token', response.data.access_token);
      } else {
        // Handle register
        const registerData = data as RegisterFormData;
        const response = await axiosInstance.post('/api/users/', {
          username: registerData.username,
          email: registerData.email,
          password: registerData.password,
          full_name: registerData.full_name || '',
        });
        localStorage.setItem('token', response.data.access_token);
      }
      
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.response?.data?.detail || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const toggleAuthMode = () => {
    setIsLogin(!isLogin);
    reset();
    setError('');
  };

  return (
    <div className="absolute w-screen bg-black flex items-center justify-center">
      <Dialog.Root open={isLoginShown}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/80 backdrop-blur-sm" />
          <Dialog.Content className="fixed top-1/2 left-1/2 w-[90vw] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl bg-[#111] p-8 shadow-2xl border border-[#00ffae]/30 text-white animate-fade-in">
            <Dialog.Close className="absolute top-4 right-4 text-white hover:text-red-500">
              <button onClick={() => dispatch(setIsLoginShown(false))}>
                <X size={20} />
              </button>
            </Dialog.Close>
            <Dialog.Title className="text-3xl font-bold text-[#00ffae] text-center mb-6 tracking-widest">
              {isLogin ? 'LOGIN' : 'REGISTER'}
            </Dialog.Title>

            <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-5">
              {!isLogin && (
                <>
                  <div>
                    <label className="block text-sm mb-1 text-[#00ffae]">Username</label>
                    <input
                      {...register('username')}
                      type="text"
                      className="w-full px-4 py-2 bg-[#222] border border-[#00ffae]/30 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-[#00ffae]"
                      placeholder="neo123"
                    />
                    {errors.username && (
                      <p className="text-red-500 text-xs mt-1">{errors.username.message}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm mb-1 text-[#00ffae]">Full Name (Optional)</label>
                    <input
                      {...register('full_name')}
                      type="text"
                      className="w-full px-4 py-2 bg-[#222] border border-[#00ffae]/30 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-[#00ffae]"
                      placeholder="Neo Anderson"
                    />
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm mb-1 text-[#00ffae]">Email</label>
                <input
                  {...register('email')}
                  type="email"
                  className="w-full px-4 py-2 bg-[#222] border border-[#00ffae]/30 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-[#00ffae]"
                  placeholder="neo@matrix.com"
                />
                {errors.email && (
                  <p className="text-red-500 text-xs mt-1">{errors.email.message}</p>
                )}
              </div>

              <div>
                <label className="block text-sm mb-1 text-[#00ffae]">Password</label>
                <input
                  {...register('password')}
                  type="password"
                  className="w-full px-4 py-2 bg-[#222] border border-[#00ffae]/30 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-[#00ffae]"
                  placeholder="••••••••"
                />
                {errors.password && (
                  <p className="text-red-500 text-xs mt-1">{errors.password.message}</p>
                )}
              </div>

              <Button
                type="submit"
                disabled={loading}
                className="w-full py-2 bg-[#00ffae] hover:bg-[#00ffaa] text-black font-bold rounded-md transition-colors duration-300"
              >
                {loading ? 'Loading...' : isLogin ? 'Login' : 'Register'}
              </Button>
            </form>

            {error && (
              <p className="text-red-500 text-center text-sm mt-4">{error}</p>
            )}

            <div className="text-center mt-6">
              <button
                type="button"
                onClick={toggleAuthMode}
                className="text-sm text-[#00ffae] hover:underline"
              >
                {isLogin ? "Don't have an account? Register" : "Already have an account? Login"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
};

export default Login;