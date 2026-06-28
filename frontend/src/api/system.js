import { api } from './client';

const PREFIX = '/api/v1/system';

export const systemApi = {
  health: () => api.get(`${PREFIX}/health`),
  status: () => api.get(`${PREFIX}/status`),
  network: () => api.get(`${PREFIX}/network`),
  config: () => api.get(`${PREFIX}/config`),
  startDetection: () => api.post(`${PREFIX}/detection/start`),
  stopDetection: () => api.post(`${PREFIX}/detection/stop`),
  reloadSignatures: () => api.post(`${PREFIX}/signatures/reload`),
};
