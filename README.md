# HushVoting Web Client

Focused web application for HushVoting election workflows.

This repository is intended to power `app.hushvoting.com`. It provides the HushVoting-specific product shell for creating elections, managing election lifecycle actions, voting, trustee approval, auditor review, result visibility, and receipt or package verification.

## Role in the HushNetwork ecosystem

HushVoting uses the existing HushNetwork account and identity model. A user that exists in HushNetwork is the same user for HushVoting; this client should authenticate and retrieve identity data through the shared HushServerNode backend rather than introducing a separate user system.

HushVoting also shares the existing HushServerNode backend. This repository is a focused frontend service, not a new backend.

Related repositories:

- `hush-server-node`: shared backend, identity, and election services.
- `hush-voting-website`: public HushVoting website for `www.hushvoting.com`.
- `hush-web-client`: broader HushNetwork app client.
- `hush-website`: broader HushNetwork public website.

## Architecture decisions

### Product boundaries

- `hush-voting-website` is the separate public marketing and information site at
  `www.hushvoting.com`; it uses TanStack Start.
- This repository is the authenticated voting application at
  `app.hushvoting.com`. It does not contain a copy of the public website.

### Voting application framework: Next.js

**Decision:** Use Next.js and TypeScript for the HushVoting voting application.

The voting client needs one carefully tested implementation of election
creation, ballot casting, trustee actions, auditor review, verification, and
identity integration. Next.js is the established HushNetwork application
framework and is already compatible with the static-client build required by a
native WebView shell. Replacing it with TanStack Start would not reduce the
native mobile build cost, but would add a high-risk framework migration to the
voting workflow.

TanStack Start remains the deliberate choice for the separate public website;
it is not the framework for this authenticated voting client.

### Native application shell: Tauri 2

**Decision:** Use Tauri 2 as the single native shell family for this client.

One Next.js application now targets:

- web application at `app.hushvoting.com`;
- signed Android application for the Google Play internal track and later production tracks;
- Ubuntu desktop application as Debian and AppImage packages.

The same Tauri structure should permit an iPhone application later. iOS initialization, signing,
and App Store/TestFlight workflows are deferred until the macOS runner strategy and GitHub Actions
minutes budget are approved. Windows and macOS desktop packages are not current delivery targets.

The Android and iPhone applications are store-delivered native packages, not
PWAs. Tauri is retained because it permits one TypeScript/React voting UI and
one native-shell contract across the required mobile platforms, without a
second React Native or platform-specific UI implementation.

The Tauri shell must host a deterministic static frontend bundle. All backend
and election authority remains in HushServerNode. Native-only capabilities
(such as push-notification registration, notification-tap routing, deep links,
secure device storage, biometrics, and permissions) must be exposed through a
small, capability-scoped, tested bridge rather than scattered platform checks
in the voting UI.

### Release and build policy

Native builds are intentionally more expensive than web builds. They must run
only for explicit release candidates, approved version tags, or manual release
dispatches—not for ordinary web deployments or every pull request. Release
workflows must cache safe build dependencies, preserve signing isolation, and
publish hashes and release evidence for each signed native artifact.

## Planned scope

- Authentication entry using the shared HushNetwork identity model.
- HushVoting election hub.
- Election creation and owner/admin workflows.
- Voter eligibility, ballot casting, and receipt/status surfaces.
- Trustee governed-action and tally-share workflows.
- Auditor and result/artifact review surfaces.
- Public or semi-public receipt verification where appropriate.

## Backend model

The client should call HushServerNode through configured environment URLs. A dedicated `api.hushvoting.com` backend is not required for the initial architecture.

Example production configuration:

```env
NEXT_PUBLIC_APP_BASE_URL=https://app.hushvoting.com
NEXT_PUBLIC_MARKETING_BASE_URL=https://www.hushvoting.com
HUSHSERVER_NODE_ENDPOINT=host.docker.internal:4665
```

The web build uses a same-origin BFF and keeps the binary gRPC endpoint
server-side. The production container joins the existing `HushNetwork` Docker
network and maps `host.docker.internal` to the Lightsail host gateway, where
HushServerNode already publishes native gRPC on port `4665`.

Example local configuration:

```env
NEXT_PUBLIC_APP_BASE_URL=http://localhost:3201
NEXT_PUBLIC_MARKETING_BASE_URL=http://localhost:3200
NEXT_PUBLIC_GRPC_URL=http://localhost:4666
HUSHSERVER_NODE_ENDPOINT=localhost:4665
```

## Development status

The cross-platform foundation is implemented:

- Next.js/React/TypeScript web application;
- deterministic Next.js static export for Tauri;
- minimal Tauri 2 Rust shell;
- Ubuntu `.deb` and AppImage release workflow;
- signed Android AAB workflow with optional Google Play internal-track publication;
- npm, Next.js, Cargo, Gradle, and Docker build caching boundaries.

Election features have not yet been migrated. The foundation screen deliberately does not expose
live election actions.

## Local development

Ubuntu instructions: [`docs/development/UBUNTU.md`](docs/development/UBUNTU.md)

```bash
npm ci
npm run dev
```

Quality and build commands:

```bash
npm run lint
npm run typecheck
npm run test:unit
npm run build:web
npm run build:static
npm run tauri:dev # starts its own Next.js server on port 3202
npm run tauri:build:linux
```

Build-target and cache policy: [`docs/architecture/BUILD_TARGETS_AND_CACHING.md`](docs/architecture/BUILD_TARGETS_AND_CACHING.md)

## Brand and visual language

The canonical HushVoting logo and Sovereign Shield visual language currently live in the sibling
`hush-voting-website` repository:

- `public/assets/hushvoting-logo.png`;
- `STYLEGUIDE.md`;
- `styles/app.css`.

The application uses the same surface, primary, typography, spacing, and radius language while
retaining the operational HushVoting rules from EPIC-013. To synchronize a newly approved website
logo and regenerate the Next.js, Linux, Android, iOS, Windows, and macOS icon assets from the
workspace root layout, run:

```bash
npm run brand:sync
```

## CI contract

GitHub Actions validates repository metadata on every push and pull request.

The frontend CI validates:

- lint;
- TypeScript;
- unit tests;
- Next.js standalone web build;
- Next.js static/Tauri frontend build;
- locked Cargo metadata.

The HushServerNode-backed `test:e2e:happy-path` script becomes mandatory before the first election
vertical slice is accepted. It is intentionally not represented by a fake scaffold test. Focused
Playwright E2E remains in `hush-server-node/Node/HushNode.IntegrationTests` with matching server
TwinTests.

The CI workflow exposes these filter hints for the E2E script:

```env
HUSH_CI_E2E_DOTNET_FILTER=Category=E2E&Category=HappyPath&Category!=LONG_RUNNING
HUSH_CI_GHERKIN_TAG_EXPRESSION=@HappyPath and not @LONG_RUNNING
```

## AWS CD secrets

AWS deployment should use the same secret model as the existing HushNetwork web client deployment.

Required GitHub Actions secrets:

- `AWS_HOST`
- `AWS_SSH_PRIVATE_KEY`
- `AWS_SSH_USER`
- `GHCR_TOKEN`
- `GHCR_USERNAME`

GitHub does not expose existing secret values for copying between repositories. To configure this
repository, export the values in a local shell and run:

```bash
bash scripts/github/set-aws-cd-secrets.sh Hushnetwork-social/hush-voting-web-client
```

## CD contract

Deployment is handled by GitHub Actions in `.github/workflows/cd.yml`.

Trigger tag:

```text
HushVotingWebClient-vMAJOR.MINOR.PATCH
```

Published image:

```text
ghcr.io/hushnetwork-social/hush-voting-web-client:<version>
```

AWS runtime:

- Container name: `HushVotingWebClient`
- Local port: `127.0.0.1:3009`
- Public domain: `https://app.hushvoting.com`
- Nginx route: `app.hushvoting.com` proxies to `http://127.0.0.1:3009`
- Backend: existing HushServerNode via server-only binary gRPC on host port `4665`

Port `3006` belongs to the independently deployed Z3C Results application and
must not be reused or stopped by HushVoting deployment automation. The web
client container exposes HTTP on container port `3000`.

Every deployment verifies both the container root and
`POST /api/blockchain/index` before succeeding. The latter proves the web
client's same-origin BFF can reach the existing HushServerNode over binary
gRPC; a rendering-only deployment is not considered healthy.

Create and push an annotated release tag from an approved `main` commit:

```bash
git tag -a HushVotingWebClient-v1.2.3 -m "Release HushVoting Web Client v1.2.3"
git push origin HushVotingWebClient-v1.2.3
```

For rollback, manually dispatch the CD workflow with a previously approved
semantic version. The workflow republishes that commit's image only when run
from the matching source ref; never move or overwrite an existing release tag.

## Native releases

Ubuntu desktop packages are built only by an explicit
`HushVotingDesktop-vMAJOR.MINOR.PATCH` tag or manual workflow dispatch.

Android internal deployment is documented in
[`docs/release/ANDROID_INTERNAL.md`](docs/release/ANDROID_INTERNAL.md). The scaffold proposes the
permanent Android application ID `com.hushvoting.client`; product ownership must confirm it before the
first Google Play upload.

Native release jobs do not run for ordinary pull requests. iOS remains deferred because it requires
a macOS runner, Apple signing assets, and an approved Actions-minutes budget.

## License

MIT
