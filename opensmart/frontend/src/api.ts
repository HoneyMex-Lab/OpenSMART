import type { AuditEvent, DataInfo, FirewallAlias, FirewallApply, FirewallApplyResult, FirewallEngine, FirewallLiveState, FirewallProfile, FirewallRule, FirewallSummary, FirewallValidateResult, HostInterface, HostResources, IdsSource, IdsSummary, LogonInfo, ModuleConfig, MtuApply, MtuApplyResult, NetworkIdsAlert, NetworkIdsAttackMap, NetworkIdsConfig, NetworkIdsSummary, NetworkInterface, NetworkTrafficConfig, NetworkTrafficSummary, OpenSmartModule, ProvisioningOverview, ProvisionResult, ResourcePoint, ResourceStatus, SchemaCheckResult, SessionInfo, Settings, StatusItem, ToolConfig, User, VpnCa, VpnInstance, VpnSettings, VpnStatus, VpnUser } from './types';

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
  setTheme: (theme: string) => request<{ ok: boolean; theme: string }>('/api/account/theme', { method: 'PUT', body: JSON.stringify({ theme }) }),
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
  idsManageSummary: () => request<IdsSummary>('/api/network-ids/manage/summary'),
  idsReadFile: (kind: string) => request<{ kind: string; content: string }>(`/api/network-ids/manage/files/${kind}`),
  idsWriteFile: (kind: string, content: string) => request<{ ok: boolean }>(`/api/network-ids/manage/files/${kind}`, { method: 'PUT', body: JSON.stringify({ content }) }),
  idsSources: () => request<{ sources: IdsSource[] }>('/api/network-ids/manage/sources'),
  idsSourceAction: (action: 'enable' | 'disable', name: string, params: Record<string, string> = {}) => request<{ ok: boolean }>(`/api/network-ids/manage/sources/${action}`, { method: 'POST', body: JSON.stringify({ name, params }) }),
  idsUpdateRules: () => request<{ ok: boolean; detail: string }>('/api/network-ids/manage/update', { method: 'POST' }),
  idsTestConfig: () => request<{ ok: boolean; detail: string }>('/api/network-ids/manage/test', { method: 'POST' }),
  idsRestart: () => request<{ ok: boolean; detail: string }>('/api/network-ids/manage/restart', { method: 'POST' }),
  idsDetection: () => request<{ settings: Record<string, string> }>('/api/network-ids/manage/detection'),
  idsUpdateDetection: (values: Record<string, string>) => request<{ ok: boolean }>('/api/network-ids/manage/detection', { method: 'PUT', body: JSON.stringify(values) }),
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
  hostResources: () => request<HostResources>('/api/provisioning/host-resources'),
  netInterfaces: () => request<{ interfaces: NetworkInterface[] }>('/api/network/interfaces'),
  netRescan: () => request<{ interfaces: NetworkInterface[] }>('/api/network/interfaces/rescan', { method: 'POST' }),
  netUpdateInterface: (name: string, fields: Partial<Pick<NetworkInterface, 'alias' | 'description' | 'role' | 'monitor'>>) =>
    request<NetworkInterface>(`/api/network/interfaces/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(fields) }),
  netRemapInterface: (name: string, newName: string) =>
    request<{ ok: boolean }>(`/api/network/interfaces/${encodeURIComponent(name)}/remap`, { method: 'POST', body: JSON.stringify({ new_name: newName }) }),
  netMtuStatus: (name: string) => request<{ apply: MtuApply | null }>(`/api/network/interfaces/${encodeURIComponent(name)}/mtu/status`),
  netSetMtu: (name: string, mtu: number, confirmSeconds: number) =>
    request<MtuApplyResult>(`/api/network/interfaces/${encodeURIComponent(name)}/mtu`, { method: 'POST', body: JSON.stringify({ mtu, confirm_seconds: confirmSeconds }) }),
  netConfirmMtu: (name: string, token: string) =>
    request<{ ok: boolean }>(`/api/network/interfaces/${encodeURIComponent(name)}/mtu/confirm`, { method: 'POST', body: JSON.stringify({ token }) }),
  netCancelMtu: (name: string, token: string) =>
    request<{ ok: boolean }>(`/api/network/interfaces/${encodeURIComponent(name)}/mtu/cancel`, { method: 'POST', body: JSON.stringify({ token }) }),
  vpnCas: () => request<{ cas: VpnCa[] }>('/api/vpn/cas'),
  vpnCreateCa: (payload: { name: string; cn?: string; description?: string }) => request<{ ca: VpnCa }>('/api/vpn/cas', { method: 'POST', body: JSON.stringify(payload) }),
  vpnDeleteCa: (name: string) => request<{ ok: boolean }>(`/api/vpn/cas/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  vpnInstances: () => request<{ instances: VpnInstance[] }>('/api/vpn/instances'),
  vpnCreateInstance: (payload: { name: string; vpn_type: string; port: number; auth_mode: string; ldap_config: Record<string, string>; subnet?: string; settings?: Partial<VpnSettings>; ca?: string }) => request<{ instance: VpnInstance }>('/api/vpn/instances', { method: 'POST', body: JSON.stringify(payload) }),
  vpnDeleteInstance: (name: string) => request<{ ok: boolean }>(`/api/vpn/instances/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  vpnInstanceAction: (name: string, action: 'start' | 'stop' | 'restart') => request<{ ok: boolean; detail: string }>(`/api/vpn/instances/${encodeURIComponent(name)}/${action}`, { method: 'POST' }),
  vpnUsers: (name: string) => request<{ users: VpnUser[] }>(`/api/vpn/instances/${encodeURIComponent(name)}/users`),
  vpnCreateUser: (name: string, username: string, serverHost: string, password = '') => request<{ name: string; instance: string }>(`/api/vpn/instances/${encodeURIComponent(name)}/users`, { method: 'POST', body: JSON.stringify({ username, server_host: serverHost, password }) }),
  vpnSetUserPassword: (name: string, username: string, password: string) => request<{ ok: boolean }>(`/api/vpn/instances/${encodeURIComponent(name)}/users/${encodeURIComponent(username)}/password`, { method: 'POST', body: JSON.stringify({ password }) }),
  vpnRevokeUser: (name: string, username: string) => request<{ ok: boolean }>(`/api/vpn/instances/${encodeURIComponent(name)}/users/${encodeURIComponent(username)}/revoke`, { method: 'POST' }),
  vpnSetUserEnabled: (name: string, username: string, enabled: boolean) => request<{ ok: boolean }>(`/api/vpn/instances/${encodeURIComponent(name)}/users/${encodeURIComponent(username)}/enabled`, { method: 'POST', body: JSON.stringify({ enabled }) }),
  vpnInstanceStatus: (name: string) => request<VpnStatus>(`/api/vpn/instances/${encodeURIComponent(name)}/status`),
  vpnInstanceLogs: (name: string, tail = 200) => request<{ logs: string }>(`/api/vpn/instances/${encodeURIComponent(name)}/logs?tail=${tail}`),
  vpnUpdateInstance: (name: string, payload: { settings?: Partial<VpnSettings>; ldap_config?: Record<string, string> }) => request<{ instance: VpnInstance }>(`/api/vpn/instances/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(payload) }),
  vpnUserConfig: async (name: string, username: string): Promise<{ filename: string; content: string }> => {
    // The download route is admin+CSRF-guarded even though it is a GET.
    const response = await fetch(`/api/vpn/instances/${encodeURIComponent(name)}/users/${encodeURIComponent(username)}/config`, { credentials: 'include', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {} });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Download failed');
    }
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    return { filename: match ? match[1] : `${name}-${username}.conf`, content: await response.text() };
  },
  fwSummary: () => request<FirewallSummary>('/api/firewall/summary'),
  fwProfiles: () => request<{ profiles: FirewallProfile[] }>('/api/firewall/profiles'),
  fwRules: (profileId: number) => request<{ rules: FirewallRule[] }>(`/api/firewall/profiles/${profileId}/rules`),
  fwPreview: (profileId: number) => request<{ nft: string }>(`/api/firewall/profiles/${profileId}/preview`),
  fwValidate: (profileId: number) => request<FirewallValidateResult>(`/api/firewall/profiles/${profileId}/validate`, { method: 'POST' }),
  fwLive: () => request<FirewallLiveState>('/api/firewall/live'),
  fwLogs: (lines = 200) => request<{ lines: string[] }>('/api/firewall/logs', { method: 'POST', body: JSON.stringify({ lines }) }),
  fwUpdateRule: (ruleId: number, fields: Partial<FirewallRule>) =>
    request<FirewallRule>(`/api/firewall/rules/${ruleId}`, { method: 'PUT', body: JSON.stringify(fields) }),
  fwCreateRule: (profileId: number, fields: Partial<FirewallRule>) =>
    request<FirewallRule>(`/api/firewall/profiles/${profileId}/rules`, { method: 'POST', body: JSON.stringify(fields) }),
  fwDeleteRule: (ruleId: number) => request<{ ok: boolean }>(`/api/firewall/rules/${ruleId}`, { method: 'DELETE' }),
  fwMoveRule: (ruleId: number, direction: 'up' | 'down') =>
    request<FirewallRule>(`/api/firewall/rules/${ruleId}/move`, { method: 'POST', body: JSON.stringify({ direction }) }),
  fwCreateProfile: (name: string, description = '', engine: FirewallEngine = 'nftables') =>
    request<FirewallProfile>('/api/firewall/profiles', { method: 'POST', body: JSON.stringify({ name, description, engine }) }),
  fwUpdateProfile: (profileId: number, fields: Partial<Pick<FirewallProfile, 'name' | 'description' | 'policies' | 'custom_nft'>>) =>
    request<FirewallProfile>(`/api/firewall/profiles/${profileId}`, { method: 'PUT', body: JSON.stringify(fields) }),
  fwDeleteProfile: (profileId: number) => request<{ ok: boolean }>(`/api/firewall/profiles/${profileId}`, { method: 'DELETE' }),
  fwCloneProfile: (profileId: number, newName: string) =>
    request<FirewallProfile>(`/api/firewall/profiles/${profileId}/clone`, { method: 'POST', body: JSON.stringify({ new_name: newName }) }),
  fwApplies: () => request<{ applies: FirewallApply[] }>('/api/firewall/applies'),
  fwApply: (profileId: number, confirmSeconds: number) =>
    request<FirewallApplyResult>(`/api/firewall/profiles/${profileId}/apply`, { method: 'POST', body: JSON.stringify({ confirm_seconds: confirmSeconds }) }),
  fwConfirmApply: (token: string) => request<{ ok: boolean }>('/api/firewall/apply/confirm', { method: 'POST', body: JSON.stringify({ token }) }),
  fwCancelApply: (token: string) => request<{ ok: boolean }>('/api/firewall/apply/cancel', { method: 'POST', body: JSON.stringify({ token }) }),
  fwAliases: () => request<{ aliases: FirewallAlias[] }>('/api/firewall/aliases'),
  fwCreateAlias: (name: string, kind: 'address' | 'port', valuesCsv: string, description = '') =>
    request<FirewallAlias>('/api/firewall/aliases', { method: 'POST', body: JSON.stringify({ name, kind, values_csv: valuesCsv, description }) }),
  fwUpdateAlias: (aliasId: number, fields: Partial<Pick<FirewallAlias, 'name' | 'values_csv' | 'description'>>) =>
    request<FirewallAlias>(`/api/firewall/aliases/${aliasId}`, { method: 'PUT', body: JSON.stringify(fields) }),
  fwDeleteAlias: (aliasId: number) => request<{ ok: boolean }>(`/api/firewall/aliases/${aliasId}`, { method: 'DELETE' }),
};
