export type Role = 'admin' | 'user';

export type User = {
  id: number;
  username: string;
  role: Role;
  fullName: string;
  email: string;
  enabled?: boolean;
  csrfToken?: string;
  mustChangePassword?: boolean;
};

export type Settings = Record<string, string>;

export type ModuleConfig = {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  config: string;
};

export type ToolConfig = ModuleConfig;

export type OpenSmartModule = ModuleConfig;

export type StatusItem = {
  name: string;
  enabled: boolean;
  status: string;
  detail: string;
};

export type AuditEvent = {
  created_at: string;
  actor_username: string;
  event_type: string;
  target: string;
  ip_address: string;
  detail: string;
};

export type SessionInfo = {
  created_at: string;
  expires_at: string;
  ip_address: string;
  user_agent: string;
  current: boolean;
};

export type LogonInfo = {
  created_at: string;
  ip_address: string;
  detail: string;
};

export type NetworkIdsConfig = {
  eve_source?: string;
  eve_json_path: string;
  initial_ingestion_gb?: string | number;
  summary_refresh_minutes: number;
  default_top_n: number;
  analysis_page_size: number;
  details_max_rows: number;
  details_page_size: number;
  configured: boolean;
  readable: boolean;
  detail: string;
  refresh_status: string;
  progress_percent: number;
  current_action: string;
  last_check_started_at: string;
  last_check_finished_at: string;
  last_check_bytes_total: number;
  last_check_bytes_read: number;
  last_check_lines_read: number;
  last_check_alerts_read: number;
  last_check_network_read: number;
  last_check_non_alerts: number;
  last_updated: string;
  error: string;
  track_critical_alerts?: string;
  first_ingestion_required?: boolean;
};

export type NetworkIdsAlert = Record<string, string | number> & {
  timestamp: string;
  src_ip: string;
  src_port: string | number;
  dest_ip: string;
  dest_port: string | number;
  proto: string;
  severity: string;
  category: string;
  signature: string;
  payload_printable: string;
  payload: string;
  alert_id?: number;
  tracking_status?: string;
};

export type NetworkIdsSummaryRow = Record<string, string | number> & {
  alerts: number;
};

export type NetworkIdsSummary = {
  generated_at: string;
  cached: boolean;
  initial_ingestion_gb?: string | number;
  refresh_status: string;
  progress_percent: number;
  current_action: string;
  last_check_started_at: string;
  last_check_finished_at: string;
  last_check_bytes_total: number;
  last_check_bytes_read: number;
  last_check_lines_read: number;
  last_check_alerts_read: number;
  last_check_network_read: number;
  last_check_non_alerts: number;
  last_updated: string;
  error: string;
  is_first_run: boolean;
  first_ingestion_required?: boolean;
  critical_new_alerts?: number;
  counters: {
    total_alerts: number;
    severity: Record<string, number>;
    total_categories: number;
    total_signature_sources: number;
  };
  tables: Record<string, NetworkIdsSummaryRow[]>;
};

export type NetworkIdsAttackMapPoint = {
  country: string;
  city?: string;
  lat: number;
  lon: number;
  src_ip_count: number;
  alert_count: number;
  signatures: Record<string, number>;
  severities: Record<string, number>;
};

export type NetworkIdsAttackMap = {
  configured: boolean;
  detail: string;
  mode: string;
  total_alerts: number;
  mapped_alerts: number;
  unmapped_alerts: number;
  geo_points: NetworkIdsAttackMapPoint[];
  tables: {
    top_src_ips: Array<{ src_ip: string; alerts: number; country?: string }>;
    top_signatures: Array<{ signature: string; sources: number; alerts: number }>;
    severity_by_source: Array<{ severity: string; sources: number; alerts: number }>;
  };
  unmapped_reasons: Record<string, number>;
  cancelled?: boolean;
};

export type NetworkTrafficConfig = NetworkIdsConfig & {
  enabled: boolean;
  log_source?: string;
  zeek_json_path?: string;
  enabled_protocols: string[];
};

export type NetworkTrafficRow = Record<string, string | number> & {
  events?: number;
};

export type NetworkTrafficSummary = NetworkTrafficConfig & {
  generated_at: string;
  counters: Record<string, number>;
  tables: Record<string, NetworkTrafficRow[]>;
};

export type ResourceStatus = {
  cpu_percent: number;
  cpu_count: number;
  memory_total_gb: number;
  memory_used_gb: number;
  memory_percent: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  uptime_seconds: number;
};

export type ResourcePoint = {
  t: string;
  cpu: number;
  memory: number;
  disk: number;
};

export type DataInfoModule = {
  retention_enabled: boolean;
  retention_days: number;
  retention_time: string;
  earliest_event: string | null;
  total: number;
};

export type DataInfo = {
  ids: DataInfoModule;
  network: DataInfoModule;
};

export type SchemaCheckResult = {
  ok: boolean;
  missing_tables: string[];
  extra_tables: string[];
};

export type ProvisionResult = {
  name: string;
  ok: boolean;
  detail: string;
  containers: { container: string; ok: boolean; detail: string }[];
};

export type ContainerDetail = {
  name: string;
  exists: boolean;
  status: string;
  image?: string;
  uptime_seconds?: number | null;
  restart_count?: number;
  health?: string | null;
  warnings?: string[];
};

export type ProjectOverview = {
  project: string;
  containers: ContainerDetail[];
  running: number;
  total: number;
  profile?: string | null;
};

export type VpnSummary = {
  wireguard: { configured: boolean; peers: number };
  openvpn: { configured: boolean; valid_certs: number; revoked_certs: number };
};

export type ProvisioningOverview = {
  projects: ProjectOverview[];
  vpn: VpnSummary;
};

export type HostInterface = {
  name: string;
  up: boolean;
  mtu: number;
  virtual: boolean;
};

export type VpnInstance = {
  id: number;
  name: string;
  vpn_type: 'openvpn' | 'wireguard';
  port: number;
  subnet: string;
  auth_mode: 'certs' | 'ldap';
  created_at: string;
  running: boolean;
  status: string;
  uptime_seconds: number | null;
  users: number;
};

export type VpnUser = {
  name: string;
  status: string;
  expires_at: string;
  has_config: boolean;
};
