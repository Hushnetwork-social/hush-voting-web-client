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

One Next.js application will produce these delivery targets:

- web application at `app.hushvoting.com`;
- signed Android application for Google Play;
- signed iPhone application for the Apple App Store; and
- Windows, macOS, and Linux desktop applications only when a confirmed product
  requirement justifies them.

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
NEXT_PUBLIC_GRPC_URL=https://api.hushnetwork.social
GRPC_SERVER_URL=https://api.hushnetwork.social
```

Example local configuration:

```env
NEXT_PUBLIC_APP_BASE_URL=http://localhost:3201
NEXT_PUBLIC_MARKETING_BASE_URL=http://localhost:3200
NEXT_PUBLIC_GRPC_URL=http://localhost:4666
GRPC_SERVER_URL=http://localhost:4666
```

## Development status

This repository has been initialized with project metadata only. The frontend scaffold and runtime commands will be added when implementation starts.

## CI contract

GitHub Actions validates repository metadata on every push and pull request.

After the frontend scaffold is added, `package.json` must define:

- `build`: production build.
- `test:unit` or `test`: unit test suite.
- `test:e2e:happy-path`: HappyPath Gherkin E2E integration tests, excluding `LONG_RUNNING` scenarios.

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
- Local port: `127.0.0.1:3006`
- Public domain: `https://app.hushvoting.com`
- Backend: existing HushServerNode at `https://api.hushnetwork.social`

The web client container is expected to expose HTTP on container port `3000`.

## License

MIT
