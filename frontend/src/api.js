// Keep API requests on the current origin. Vite proxies /api in development,
// and FastAPI serves the same prefix in the unified production deployment.
const API_BASE = '/api';

export const getAuthToken = () => localStorage.getItem('legavault_token');
export const setAuthToken = (token) => localStorage.setItem('legavault_token', token);
export const removeAuthToken = () => localStorage.removeItem('legavault_token');

export const getStoredUser = () => {
  try {
    const u = localStorage.getItem('legavault_user');
    return u ? JSON.parse(u) : null;
  } catch {
    return null;
  }
};

export const setStoredUser = (user) => {
  localStorage.setItem('legavault_user', JSON.stringify(user));
};

export const removeStoredUser = () => {
  localStorage.removeItem('legavault_user');
};

async function parseResponseJson(res) {
  const text = await res.text();
  if (!text) {
    if (!res.ok) {
      throw new Error(`Server returned status ${res.status} (${res.statusText || 'No details'})`);
    }
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    if (!res.ok) {
      throw new Error(text || `Request failed with status ${res.status}`);
    }
    throw new Error('Invalid response format received from server.');
  }
}

async function apiFetch(endpoint, options = {}) {
  const token = getAuthToken();
  const headers = { ...(options.headers || {}) };

  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // If body is not FormData, default to application/json
  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/verify-otp')) {
    removeAuthToken();
    removeStoredUser();
    window.dispatchEvent(new Event('auth:unauthorized'));
  }

  return response;
}

export const api = {
  // Authentication
  async register(email, fullName, password, role, lawyerRegistrationCode = '') {
    const res = await apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email,
        full_name: fullName,
        password,
        role,
        lawyer_registration_code: lawyerRegistrationCode || null,
      }),
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Registration failed');
    return data;
  },

  async login(email, password) {
    const res = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    return data;
  },

  async resendOtp(email) {
    const res = await apiFetch('/auth/resend-otp', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to resend OTP');
    return data;
  },

  async verifyOtp(email, otp) {
    const res = await apiFetch('/auth/verify-otp', {
      method: 'POST',
      body: JSON.stringify({ email, otp }),
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'OTP verification failed');
    return data;
  },

  async logout() {
    try {
      await apiFetch('/auth/logout', { method: 'POST' });
    } catch {
      // ignore
    } finally {
      removeAuthToken();
      removeStoredUser();
    }
  },

  async getMe() {
    const res = await apiFetch('/auth/me');
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to get profile');
    return data;
  },

  // Users
  async getUsers() {
    const res = await apiFetch('/users');
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to list users');
    return data;
  },

  // Documents
  async getDocuments() {
    const res = await apiFetch('/documents');
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to fetch documents');
    return data;
  },

  async getDocument(id) {
    const res = await apiFetch(`/documents/${id}`);
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to fetch document details');
    return data;
  },

  async uploadDocument(title, description, file) {
    const formData = new FormData();
    formData.append('title', title);
    if (description) formData.append('description', description);
    formData.append('file', file);

    const res = await apiFetch('/documents/upload', {
      method: 'POST',
      body: formData,
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Upload failed');
    return data;
  },

  async shareDocument(docId, recipientId, permission = 'view') {
    const res = await apiFetch(`/documents/${docId}/share`, {
      method: 'POST',
      body: JSON.stringify({ recipient_id: recipientId, permission }),
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Sharing failed');
    return data;
  },

  async revokeShare(docId, recipientId) {
    const res = await apiFetch(`/documents/${docId}/share/${recipientId}`, {
      method: 'DELETE',
    });
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Revocation failed');
    return data;
  },

  async downloadDocument(docId, originalFilename) {
    const res = await apiFetch(`/documents/${docId}/download`);
    if (!res.ok) {
      let msg = 'Download failed';
      try {
        const err = await parseResponseJson(res);
        msg = err.detail || msg;
      } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = originalFilename || `document_${docId}.bin`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    return true;
  },

  // Audit Logs
  async getAuditLogs(action = '') {
    const query = action ? `?action=${encodeURIComponent(action)}` : '';
    const res = await apiFetch(`/audit-logs${query}`);
    const data = await parseResponseJson(res);
    if (!res.ok) throw new Error(data.detail || 'Failed to load audit logs');
    return data;
  },

  // Health check
  async getHealth() {
    const res = await apiFetch('/health');
    return await parseResponseJson(res);
  }
};
