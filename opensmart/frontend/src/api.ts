import type { AuditEvent, DataInfo, HostInterface, LogonInfo, ModuleConfig, NetworkIdsAlert, NetworkIdsAttackMap, NetworkIdsConfig, NetworkIdsSummary, NetworkTrafficConfig, NetworkTrafficSummary, OpenSmartModule, ProvisioningOverview, ProvisionResult, ResourcePoint, ResourceStatus, SchemaCheckResult, SessionInfo, Settings, StatusItem, ToolConfig, User } from './types';

let csrfToken = '';

export function setCsrfToken(token?: string) {
  csrfToken = token || '';
}

function query(params: Record<string, string | number | boolean | undefined>) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') search.set(key, String(value));
  });
  const value = search.toString();
  return value ? `?${value}` : '';
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (csrfToken && options.method && options.method !== 'GET') headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { ...options, headers, credentials: 'include' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || 'Request failed');
  return data as T;
}

export const api = {
  login: (username: string, password: string) => request<{ user: User }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => request<{ user: User }>('/api/auth/me'),
  publicSettings: () => request<{ settings: Settings }>('/api/settings/public'),
  settings: () => request<{ settings: Settings }>('/api/settings'),
  saveSettings: (settings: Settings) => request<{ settings: Settings }>('/api/settings', { method: 'PUT', body: JSON.stringify({ settings }) }),
  testWebhook: (url: string, label: string) => request<{ ok: boolean; detail: string }>('/api/settings/webhook-test', { method: 'POST', body: JSON.stringify({ url, label }) }),
  modules: () => request<{ modules: ModuleConfig[] }>('/api/modules'),
  saveModules: (modules: ModuleConfig[]) => request<{ modules: ModuleConfig[] }>('/api/modules', { method: 'PUT', body: JSON.stringify(modules.map(({ id, enabled, config }) => ({ id, enabled, config }))) }),
  tools: () => request<{ tools: ToolConfig[] }>('/api/tools'),
  saveTools: (tools: ToolConfig[]) => request<{ tools: ToolConfig[] }>('/api/tools', { method: 'PUT', body: JSON.stringify(tools.map(({ id, enabled, config }) => ({ id, enabled, config }))) }),
  openSmartModules: () => request<{ modules: OpenSmartModule[] }>('/api/opensmart-modules'),
  saveOpenSmartModules: (modules: OpenSmartModule[]) => request<{ modules: OpenSmartModule[] }>('/api/opensmart-modules', { method: 'PUT', body: JSON.stringify(modules.map(({ id, enabled, config }) => ({ id, enabled, config }))) }),
  status: () => request<{ modules: StatusItem[] }>('/api/status'),
  changePassword: (currentPassword: string, newPassword: string) => request<{ ok: boolean }>('/api/account/password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) }),
  updateProfile: (fullName: string, email: string) => request<{ user: User }>('/api/account/profile', { method: 'PUT', body: JSON.stringify({ fullName, email }) }),
  accountSessions: () => request<{ sessions: SessionInfo[]; logons: LogonInfo[] }>('/api/account/sessions'),
  terminateOtherSessions: () => request<{ sessions: SessionInfo[]; logons: LogonInfo[] }>('/api/account/sessions/others', { method: 'DELETE' }),
  audit: () => request<{ events: AuditEvent[] }>('/api/audit'),
  auditLog: (lines = 500) => request<{ lines: string[]; path: string; error: string | null }>(`/api/audit/log?lines=${lines}`),
  users: () => request<{ users: User[] }>('/api/users'),
  createUser: (user: Partial<User> & { password: string }) => request<{ users: User[] }>('/api/users', { method: 'POST', body: JSON.stringify(user) }),
  updateUser: (user: Partial<User> & { id: number; password?: string }) => request<{ users: User[] }>(`/api/users/${user.id}`, { method: 'PUT', body: JSON.stringify(user) }),
  deleteUser: (id: number) => request<{ users: User[] }>(`/api/users/${id}`, { method: 'DELETE' }),
  networkIdsConfig: () => request<{ config: NetworkIdsConfig }>('/api/network-ids/config'),
  networkIdsStatus: () => request<NetworkIdsConfig>('/api/network-ids/status'),
  networkIdsSummary: (params: Record<string, string | number | boolean | undefined>, options: RequestInit = {}) => request<NetworkIdsSummary>(`/api/network-ids/summary${query(params)}`, options),
  cancelNetworkIdsSummary: (queryId: string) => request<{ ok: boolean }>(`/api/network-ids/summary/cancel${query({ query_id: queryId })}`, { method: 'POST' }),
  networkIdsAlerts: (params: Record<string, string | number | boolean | undefined>, options: RequestInit = {}) => request<{ alerts: NetworkIdsAlert[]; total: number; malformed_lines: number }>(`/api/network-ids/alerts${query(params)}`, options),
  cancelNetworkIdsAlerts: (queryId: string) => request<{ ok: boolean }>(`/api/network-ids/alerts/cancel${query({ query_id: queryId })}`, { method: 'POST' }),
  networkIdsDetails: (params: Record<string, string | number | undefined>, options: RequestInit = {}) => request<{ table: string; rows: Record<string, unknown>[]; total: number; cancelled?: boolean }>(`/api/network-ids/details${query(params)}`, options),
  networkIdsAttackMap: (params: Record<string, string | number | boolean | undefined>, options: RequestInit = {}) => request<NetworkIdsAttackMap>(`/api/network-ids/attack-map${query(params)}`, options),
  cancelNetworkIdsDetails: (queryId: string) => request<{ ok: boolean }>(`/api/network-ids/details/cancel${query({ query_id: queryId })}`, { method: 'POST' }),
  acknowledgeNetworkIdsAlert: (alertId: number) => request<{ ok: boolean }>('/api/network-ids/tracking/ack', { method: 'POST', body: JSON.stringify({ alert_id: alertId }) }),
  acknowledgeNetworkIdsCritical: (params: Record<string, string | number | undefined>) => request<{ ok: boolean; count: number }>(`/api/network-ids/tracking/ack-critical${query(params)}`, { method: 'POST' }),
  networkTrafficConfig: () => request<{ config: NetworkTrafficConfig }>('/api/network-traffic/config'),
  networkTrafficSummary: (params: Record<string, string | number | boolean | undefined>, options: RequestInit = {}) => request<NetworkTrafficSummary>(`/api/network-traffic/summary${query(params)}`, options),
  cancelNetworkTrafficSummary: (queryId: string) => request<{ ok: boolean }>(`/api/network-traffic/summary/cancel${query({ query_id: queryId })}`, { method: 'POST' }),
  networkTrafficDetails: (params: Record<string, string | number | undefined>, options: RequestInit = {}) => request<{ table: string; rows: Record<string, unknown>[]; total: number; cancelled?: boolean }>(`/api/network-traffic/details${query(params)}`, options),
  cancelNetworkTrafficDetails: (queryId: string) => request<{ ok: boolean }>(`/api/network-traffic/details/cancel${query({ query_id: queryId })}`, { method: 'POST' }),
  resources: () => request<ResourceStatus>('/api/status/resources'),
  resourcesHistory: (timeframe: string) => request<{ points: ResourcePoint[]; timeframe: string }>(`/api/status/resources/history?timeframe=${timeframe}`),
  dataInfo: () => request<DataInfo>('/api/status/data-info'),
  schemaCheck: () => request<SchemaCheckResult>('/api/status/schema-check'),
  provisionStart: (name: string, kind: 'container' | 'module' | 'tool') => request<ProvisionResult>('/api/provisioning/start', { method: 'POST', body: JSON.stringify({ name, kind }) }),
  provisionStop: (name: string) => request<ProvisionResult>('/api/provisioning/stop', { method: 'POST', body: JSON.stringify({ name, kind: 'container' }) }),
  provisionStatus: (container: string) => request<{ container: string; running: boolean; detail: string }>(`/api/provisioning/status/${container}`),
  provisionOverview: () => request<ProvisioningOverview>('/api/provisioning/overview'),
  provisionRestart: (name: string) => request<{ name: string; ok: boolean; detail: string }>('/api/provisioning/restart', { method: 'POST', body: JSON.stringify({ name, kind: 'container' }) }),
  hostInterfaces: () => request<{ interfaces: HostInterface[] }>('/api/provisioning/host-interfaces'),
};
