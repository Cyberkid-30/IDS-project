import { api } from './client';

const PREFIX = '/api/v1/firewall';

export const firewallApi = {
  list: () => api.get(`${PREFIX}/blocked`),
  block: (data) => api.post(`${PREFIX}/block`, data), // { ip_address, reason }
  unblock: (ip) => api.delete(`${PREFIX}/unblock/${encodeURIComponent(ip)}`),
};
