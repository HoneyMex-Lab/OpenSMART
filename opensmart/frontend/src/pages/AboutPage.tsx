import type { Settings } from '../types';

export default function AboutPage({ settings }: { settings: Settings }) {
  return (
    <section className="about-page">
      <article className="card about-hero">
        <p className="eyebrow">About the platform</p>
        <h2>{settings.platform_title}</h2>
        <p className="version-line"><span>Version {settings.platform_version}</span><span>Build {settings.platform_build || 'unknown'}</span></p>
        <p>OpenSMART is an open source framework prototype for integrating security monitoring, network tooling, assets, and administration in one responsive console.</p>
      </article>

      <article className="card">
        <h2>Project Partners</h2>
        <p className="muted">OpenSMART is presented with support and branding from these project partners.</p>
        <div className="partner-grid">
          <a href="https://miztonlabs.org" target="_blank" rel="noreferrer">
            <img src="/assets/branding/logo_miztonlabs.jpg" alt="Mizton Labs" />
            <span>Mizton Labs</span>
          </a>
          <a href="https://honeynet.org.mx" target="_blank" rel="noreferrer">
            <img src="/assets/branding/logo_honeynet_simple.png" alt="Honeynet Project México" />
            <span>Honeynet Project México</span>
          </a>
        </div>
      </article>

      <article className="card">
        <div className="dev-team-title-row"><h2>Development Team</h2><a className="dev-members-badge" href="https://honeynet.org.mx/members/" target="_blank" rel="noreferrer">Members</a></div>
        <p className="muted">HoneyMex Lab &amp; Mizton Labs · 2026</p>
        <ul className="dev-team-list">
          <li><strong>Javier Santillan</strong><span>Core Project Member, Core Dev</span></li>
          <li><strong>Anduin Tovar</strong><span>Core Project Member</span></li>
          <li><strong>Paulo Contreras</strong><span>Core Project Member</span></li>
        </ul>
      </article>
    </section>
  );
}
