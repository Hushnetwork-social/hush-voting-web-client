# Google Play Internal Deployment

The Android release workflow builds a signed Android App Bundle and can publish it to the Google Play internal track.

## Permanent identity gate

The scaffold currently uses:

```text
Application ID: com.hushvoting.client
Product name: HushVoting
```

The application ID becomes effectively permanent after the Play application is created and an artifact is uploaded. Product ownership must confirm this identifier before the first Play upload. Changing it later creates a different Android application rather than an update.

## One-time Google Play setup

1. Create the HushVoting application in Google Play Console using `com.hushvoting.client`.
2. Accept required Play Console agreements and complete the initial application declarations.
3. Enable Play App Signing and record who owns recovery and administrative access.
4. Create a Google Cloud/Play service account with only the release permissions required for this application.
5. Grant that service account access to the HushVoting application in Play Console.
6. Create the internal testing track and tester group.
7. Complete privacy policy, Data Safety, content rating, target audience, and store-listing requirements before widening distribution.

The first application/setup step may require a manual Play Console action before API uploads succeed.

## Signing key

Generate a dedicated HushVoting Android upload key. Do not reuse the HushFeeds key.

Keep an offline encrypted backup and record recovery ownership. Export the keystore as a single-line base64 value for GitHub Actions:

```bash
base64 -w 0 hush-voting-upload.keystore
```

Configure these secrets in the protected `HushVoting Google Play Internal` GitHub environment:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`
- `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON`

Use environment reviewers to protect publishing and secret access.

## Build without publishing

Dispatch `.github/workflows/cd-android.yml` with:

- a valid `MAJOR.MINOR.PATCH` version;
- `publish_to_play=false`.

The workflow uploads the signed AAB and JSON release evidence as protected GitHub Actions artifacts.

## Publish internally

Either:

- dispatch the workflow with `publish_to_play=true`; or
- push an approved `HushVotingAndroid-vMAJOR.MINOR.PATCH` tag.

An approved tag requests internal-track publication automatically.

Every Play upload must use a monotonically increasing Android version code. Before the first real upload, verify the Tauri-generated version-code mapping for two successive SemVer versions and add an explicit version-code input if it does not guarantee monotonicity for the release strategy.

## Cache and evidence boundary

The workflow caches npm, Next.js, Cargo, and Gradle build inputs. It does not cache signing keys or signed bundles. Each AAB is uploaded with:

- SHA-256 artifact digest;
- package ID;
- source commit;
- signing-certificate fingerprint;
- workflow run ID.

## Current release blockers

Before inviting internal testers to election workflows:

- confirm `com.hushvoting.client`;
- configure the dedicated upload key and Play service account;
- implement the Android Keystore-backed HushNetwork credential vault;
- select and test the Android-to-HushServerNode transport model;
- define app links/deep links;
- replace the generated foundation icon if final branding differs;
- test the first election vertical slice on a physical Android device.
