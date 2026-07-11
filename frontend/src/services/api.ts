const API_BASE = 'http://localhost:8000/api/v1';

// ── Token Management ────────────────────────────────────────────────────────
let accessToken: string | null = localStorage.getItem('cspm_token');

export const setToken = (token: string | null) => {
  accessToken = token;
  if (token) localStorage.setItem('cspm_token', token);
  else localStorage.removeItem('cspm_token');
};

export const getToken = () => accessToken;

const headers = (): HeadersInit => {
  const h: HeadersInit = { 'Content-Type': 'application/json' };
  if (accessToken) h['Authorization'] = `Bearer ${accessToken}`;
  return h;
};

// ── Generic Fetch Wrapper ───────────────────────────────────────────────────
async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...headers(), ...(options?.headers || {}) },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.message || err.detail || `API Error ${res.status}`);
  }
  if (res.status === 204) return {} as T;
  return res.json();
}

// ── Auth ─────────────────────────────────────────────────────────────────────
export const auth = {
  register: (data: { email: string; full_name: string; password: string }) =>
    apiFetch('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  login: async (email: string, password: string) => {
    const res = await apiFetch<{ access_token: string; refresh_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setToken(res.access_token);
    localStorage.setItem('cspm_refresh', res.refresh_token);
    return res;
  },
  me: () => apiFetch<{ id: string; email: string; full_name: string; role: string }>('/auth/me'),
  changePassword: (current_password: string, new_password: string) =>
    apiFetch('/auth/me/password', { method: 'PUT', body: JSON.stringify({ current_password, new_password }) }),
  createApiKey: () => apiFetch<{ api_key: string; prefix: string }>('/auth/api-key', { method: 'POST' }),
  revokeApiKey: () => apiFetch('/auth/api-key', { method: 'DELETE' }),
  logout: () => { setToken(null); localStorage.removeItem('cspm_refresh'); },
};

// ── Dashboard ────────────────────────────────────────────────────────────────
export const dashboard = {
  summary: () => apiFetch<any>('/dashboard/summary'),
  riskTrend: (days = 30) => apiFetch<any[]>(`/dashboard/risk-trend?days=${days}`),
  topRisks: (limit = 10) => apiFetch<any[]>(`/dashboard/top-risks?limit=${limit}`),
  compliance: () => apiFetch<any>('/dashboard/compliance'),
};

// ── Accounts ─────────────────────────────────────────────────────────────────
export const accounts = {
  list: () => apiFetch<any[]>('/accounts'),
  get: (id: string) => apiFetch<any>(`/accounts/${id}`),
  create: (data: any) => apiFetch('/accounts', { method: 'POST', body: JSON.stringify(data) }),
  update: (id: string, data: any) => apiFetch(`/accounts/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id: string) => apiFetch(`/accounts/${id}`, { method: 'DELETE' }),
  validate: (id: string) => apiFetch(`/accounts/${id}/validate`, { method: 'POST' }),
};

// ── Scans ────────────────────────────────────────────────────────────────────
export const scans = {
  list: (params?: { account_id?: string; status?: string; page?: number }) => {
    const q = new URLSearchParams();
    if (params?.account_id) q.set('account_id', params.account_id);
    if (params?.status) q.set('status', params.status);
    if (params?.page) q.set('page', String(params.page));
    return apiFetch<any>(`/scans?${q}`);
  },
  start: (cloud_account_id: string, scan_type = 'full') =>
    apiFetch('/scans', { method: 'POST', body: JSON.stringify({ cloud_account_id, scan_type }) }),
  get: (id: string) => apiFetch<any>(`/scans/${id}`),
  status: (id: string) => apiFetch<any>(`/scans/${id}/status`),
  cancel: (id: string) => apiFetch(`/scans/${id}/cancel`, { method: 'POST' }),
};

// ── Findings ─────────────────────────────────────────────────────────────────
export const findings = {
  search: (filters: any) =>
    apiFetch<any>('/findings/search', { method: 'POST', body: JSON.stringify(filters) }),
  get: (id: string) => apiFetch<any>(`/findings/${id}`),
  suppress: (id: string, reason: string) =>
    apiFetch(`/findings/${id}/suppress`, { method: 'PUT', body: JSON.stringify({ reason }) }),
  updateStatus: (id: string, status: string, reason?: string) =>
    apiFetch(`/findings/${id}/status`, { method: 'PUT', body: JSON.stringify({ status, reason }) }),
};

// ── Compliance ───────────────────────────────────────────────────────────────
export const compliance = {
  frameworks: () => apiFetch<string[]>('/compliance/frameworks'),
  posture: (scan_id?: string) => apiFetch<any>(`/compliance/posture${scan_id ? `?scan_id=${scan_id}` : ''}`),
  framework: (name: string) => apiFetch<any>(`/compliance/posture/${name}`),
  findingFrameworks: (findingId: string) => apiFetch<any>(`/compliance/finding/${findingId}/frameworks`),
};

// ── Remediation ──────────────────────────────────────────────────────────────
export const remediation = {
  supportedRules: () => apiFetch<Record<string, string>>('/remediation/supported-rules'),
  execute: (finding_ids: string[], dry_run = true) =>
    apiFetch<any[]>('/remediation/execute', { method: 'POST', body: JSON.stringify({ finding_ids, dry_run }) }),
  steps: (findingId: string) => apiFetch<any>(`/remediation/finding/${findingId}/steps`),
  aiRemediation: (findingId: string) =>
    apiFetch<any>(`/remediation/finding/${findingId}/ai-remediation`, { method: 'POST' }),
};

// ── Reports ──────────────────────────────────────────────────────────────────
export const reports = {
  generate: (params: any) => apiFetch('/reports/generate', { method: 'POST', body: JSON.stringify(params) }),
  list: () => apiFetch<any[]>('/reports'),
};

// ── Health ────────────────────────────────────────────────────────────────────
export const health = {
  check: () =>
    fetch('http://localhost:8000/health')
      .then((res) => res.json())
      .catch(() => ({ status: 'unreachable' })),
};
