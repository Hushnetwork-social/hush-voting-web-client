# Build Targets and Caching

## Build products

| Product | Frontend mode | Native/toolchain mode | Initial distribution |
|---|---|---|---|
| Web | Next.js standalone server | Docker image | GHCR and `app.hushvoting.com` |
| Ubuntu desktop | Next.js static export | Tauri/Rust `.deb` and AppImage | GitHub Actions artifact/release |
| Android | Next.js static export | Tauri/Rust/Gradle signed AAB | Google Play internal track |
| iOS (deferred) | Next.js static export | Tauri/Rust/Xcode archive | TestFlight after macOS cost review |

The static export must remain free of Next.js server-route assumptions. Platform-specific capabilities belong behind small Tauri adapters.

## Build-cache policy

Caches accelerate reproducible work; they are never release evidence and never contain signing material.

### Safe CI caches

- npm download cache, keyed by `package-lock.json`;
- Next.js production-web compilation cache (`.next-web/cache`), keyed by OS, Node version, lockfile, and source fallback; browser development remains isolated in `.next`, Tauri development in `.next-tauri`, and the final `.next-static` export is rebuilt rather than restored as a cache;
- Cargo registry/git/build cache through `Swatinem/rust-cache`;
- Gradle dependency and build cache through `gradle/actions/setup-gradle`;
- Docker BuildKit layers through GitHub Actions cache.

### Do not cache

- Android or Apple signing keys and passwords;
- Google Play or App Store service-account credentials;
- `.env` files containing protected values;
- signed AAB/APK/AppImage/deb artifacts as cache entries;
- decrypted voter, trustee, ballot, receipt, or restricted-audit data;
- generated runtime secrets.

Signed artifacts are uploaded as immutable workflow/release artifacts with SHA-256 evidence.

## Cache invalidation

- dependency caches invalidate when lockfiles change;
- Rust caches include `src-tauri/Cargo.lock`;
- Android caches include Gradle wrapper/catalog inputs once the generated Android project is committed;
- Tauri configuration changes are part of release evidence even when they do not invalidate every dependency cache;
- manual cache busting uses a versioned prefix such as `next-v2-` rather than deleting unrelated repository caches.

## GitHub Actions cost control

- ordinary pull requests run web/static builds and unit tests on Ubuntu only;
- Linux desktop, Android, and eventual iOS release jobs run only on explicit release tags or manual dispatch;
- Android release jobs cache npm, Cargo, and Gradle dependencies;
- iOS jobs remain disabled until a macOS runner/minutes budget and signing approach are approved;
- do not build every native architecture for every commit;
- internal Android releases initially build the Play-required arm64 application bundle and add other test artifacts only when needed.

## Runtime cache policy

Build caching is separate from application data caching. Election query caching will be designed with the transport/state layer and must:

- key data by server, identity/actor, election, visibility scope, and contract version;
- prevent one identity from reading another identity's cached actor-bound response;
- avoid persistent caching of private keys, mnemonics, decrypted ballots, trustee shares, or restricted anomaly payloads;
- invalidate or revalidate around lifecycle-changing transactions;
- expose stale/offline state explicitly rather than presenting cached protocol state as current;
- support explicit logout/wipe behavior on Android and desktop.

No service worker or broad offline cache is enabled in the foundation milestone.
