// src/services/api.ts
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

export const createUser = async (userData: {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}) => {
  const response = await axios.post(`${API_BASE_URL}/users/`, userData);
  return response.data;
};

export const getUsers = async () => {
  const response = await axios.get(`${API_BASE_URL}/users/`);
  return response.data;
};

export const getUser = async (userId: number) => {
  const response = await axios.get(`${API_BASE_URL}/users/${userId}`);
  return response.data;
};

export const updateUser = async (
  userId: number,
  updateData: {
    email?: string;
    full_name?: string;
    password?: string;
  }
) => {
  const response = await axios.put(
    `${API_BASE_URL}/users/${userId}`,
    updateData
  );
  return response.data;
};

export const deleteUser = async (userId: number) => {
  const response = await axios.delete(`${API_BASE_URL}/users/${userId}`);
  return response.data;
};