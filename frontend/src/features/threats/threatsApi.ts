import { Threat } from './threatTypes'
import { cyberwatchApi as api } from '../api/cyberwatchApi'

export const getThreatsApi = async (): Promise<Threat[]> => {
  const response = await api.get('/threats')
  return response.data
}

export const acknowledgeThreatApi = async (threatId: string): Promise<void> => {
  await api.patch(`/threats/${threatId}/acknowledge`)
}

export const fetchThreatDetails = async (threatId: string): Promise<Threat> => {
  const response = await api.get(`/threats/${threatId}`)
  return response.data
}