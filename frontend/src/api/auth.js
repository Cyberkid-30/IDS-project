import { api } from './client';

const PREFIX = '/api/v1/auth';

export const authApi = {
  login: (username, password) => api.post(`${PREFIX}/login`, { username, password }),
  me: () => api.get(`${PREFIX}/me`),
  changePassword: (currentPassword, newPassword) =>
    api.patch(`${PREFIX}/me/password`, {
      current_password: currentPassword,
      new_password: newPassword,
    }),
  // Requires an existing session - SentryWatch provisions accounts,
  // it doesn't offer public sign-up.
  register: (username, password) => api.post(`${PREFIX}/register`, { username, password }),
};
