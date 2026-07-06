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

## License

MIT
