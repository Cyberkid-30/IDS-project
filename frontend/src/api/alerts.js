import { api } from './client';

const PREFIX = '/api/v1/alerts';

export const alertsApi = {
  list: ({ page = 1, page_size = 50, severity, status, source_ip, dest_ip, start_date, end_date } = {}) =>
    api.get(`${PREFIX}/`, { page, page_size, severity, status, source_ip, dest_ip, start_date, end_date }),
  stats: () => api.get(`${PREFIX}/stats`),
  get: (id) => api.get(`${PREFIX}/${id}`),
  updateStatus: (id, status) => api.patch(`${PREFIX}/${id}/status`, { status }),
  remove: (id) => api.delete(`${PREFIX}/${id}`),
  cleanup: (days = 30) => api.post(`${PREFIX}/cleanup`, undefined, { days }),
};
