import { api } from './client';

const PREFIX = '/api/v1/signatures';

export const signaturesApi = {
  list: ({ page = 1, page_size = 50, enabled, severity, category, search } = {}) =>
    api.get(`${PREFIX}/`, { page, page_size, enabled, severity, category, search }),
  categories: () => api.get(`${PREFIX}/categories`),
  get: (id) => api.get(`${PREFIX}/${id}`),
  create: (data) => api.post(`${PREFIX}/`, data),
  update: (id, data) => api.put(`${PREFIX}/${id}`, data),
  remove: (id) => api.delete(`${PREFIX}/${id}`),
  toggle: (id) => api.post(`${PREFIX}/${id}/toggle`),
};
