export type ToolDefinition = {
  key: string;
  title: string;
  logo: string;
  // Whether the tool can be shown inside OpenSMART's iframe. Self-hosted
  // admin UIs like Arkime (X-Frame-Options: DENY), Wazuh and Proxmox
  // (X-Frame-Options: SAMEORIGIN + self-signed HTTPS the browser won't let
  // you bypass inside a frame) deliberately block framing for clickjacking
  // protection, so embedding only ever yields a blank/error area — those
  // open in a new tab instead. Defaults to true when omitted.
  embeddable?: boolean;
  // Same-origin path served by OpenSMART's front-door proxy (see
  // containers/run/nginx/). Setting the tool URL to this makes it embed in
  // the iframe (the proxy strips framing headers). Omitted for tools the
  // proxy doesn't route.
  alias?: string;
};

export const toolDefinitions: Record<string, ToolDefinition> = {
  OPNsense: { key: 'tool_url_opnsense', title: 'Firewall - OPNsense', logo: '/assets/tools/opnsense.svg', alias: '/opnsense/' },
  NTOP: { key: 'tool_url_ntop', title: 'Traffic - NTOP', logo: '/assets/tools/ntop.svg' },
  Arkime: { key: 'tool_url_arkime', title: 'Traffic - Arkime', logo: '/assets/tools/arkime.svg', embeddable: false, alias: '/arkime/' },
  Proxmox: { key: 'tool_url_proxmox', title: 'Assets - Proxmox', logo: '/assets/tools/proxmox.svg', embeddable: false, alias: '/proxmox/' },
  Wazuh: { key: 'tool_url_wazuh', title: 'SIEM - Wazuh', logo: '/assets/tools/wazuh.svg', embeddable: false, alias: '/wazuh/' },
  Graylog: { key: 'tool_url_graylog', title: 'SIEM - Graylog', logo: '/assets/tools/graylog.svg' },
};

// Absolute URL for a tool's alias, anchored at the front-door proxy's own
// origin (not the page currently viewing this — see isAliasUrl below for
// why a bare relative path is NOT enough). window.location.origin already
// resolves to the proxy's origin when reached through it; when reached
// directly on the app's own port this still points requests at the
// correct proxy host (https default port 443), matching how
// _install_check_host_resources' sibling, the front-door proxy compose
// file, publishes it.
export function aliasUrl(definition: ToolDefinition): string {
  return `${window.location.protocol}//${window.location.hostname}${definition.alias}`;
}

// Is `url` served through OUR front-door proxy at this tool's alias path?
// Checked by PATH, not by "is the URL relative" — a relative "/arkime/"
// only resolves correctly when the CURRENT page was itself loaded through
// the proxy; an absolute "https://host/arkime/" resolves correctly no
// matter which port loaded the current page (the app's own :8000 remains
// a fully supported direct-access mode). Either form, once it reaches
// nginx, gets the same X-Frame-Options/CSP stripped — framing permission
// depends on the response headers of the framed resource, not on the
// parent page's origin, so an absolute proxy URL embeds exactly as well
// as a relative one while also working from any access port.
export function isAliasUrl(url: string, definition: ToolDefinition | undefined): boolean {
  if (!definition?.alias || !url) return false;
  try {
    return new URL(url, window.location.origin).pathname.startsWith(definition.alias);
  } catch {
    return false;
  }
}
