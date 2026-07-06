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
