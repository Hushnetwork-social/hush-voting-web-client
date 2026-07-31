import Image from 'next/image';
import Link from 'next/link';

const deliveryTargets = [
  {
    name: 'Web application',
    detail: 'Next.js server deployment for app.hushvoting.com',
    state: 'Foundation ready',
  },
  {
    name: 'Ubuntu desktop',
    detail: 'Tauri packages for Debian/Ubuntu and AppImage',
    state: 'Shell ready',
  },
  {
    name: 'Android application',
    detail: 'Tauri AAB delivery to the Google Play internal track',
    state: 'Pipeline next',
  },
] as const;

export default function HomePage() {
  return (
    <main className="app-shell antialiased">
      <header className="topbar">
        <Link className="brand" href="/" aria-label="HushVoting home">
          <span className="brand-mark" aria-hidden="true">
            <Image
              src="/assets/hushvoting-logo.png"
              alt=""
              width={48}
              height={48}
              priority
            />
          </span>
          <span>HushVoting!</span>
        </Link>
        <span className="foundation-badge">Client foundation</span>
      </header>

      <section className="hero" aria-labelledby="hero-title">
        <div className="hero-copy">
          <p className="eyebrow">One governed voting experience</p>
          <h1 id="hero-title">HushVoting! is becoming its own application.</h1>
          <p className="hero-summary">
            The dedicated client will use the existing HushNetwork identity and HushServerNode
            election backend across web, Ubuntu desktop, and Android.
          </p>
        </div>
        <aside className="readiness" aria-label="Foundation status">
          <span className="readiness-label">Current milestone</span>
          <strong>Cross-platform application shell</strong>
          <p>Election workflows will move here by tested vertical slice.</p>
        </aside>
      </section>

      <section className="targets" aria-labelledby="targets-title">
        <div className="section-heading">
          <p className="eyebrow">Delivery targets</p>
          <h2 id="targets-title">One UI, platform-specific release evidence</h2>
        </div>
        <div className="target-grid">
          {deliveryTargets.map((target) => (
            <article className="target" key={target.name}>
              <div>
                <h3>{target.name}</h3>
                <p>{target.detail}</p>
              </div>
              <span>{target.state}</span>
            </article>
          ))}
        </div>
      </section>

      <footer className="foundation-note">
        This is the initial application foundation. It does not yet expose live election actions.
      </footer>
    </main>
  );
}
