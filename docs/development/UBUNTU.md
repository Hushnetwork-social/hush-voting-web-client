# Ubuntu Development

Ubuntu is the primary development and Linux desktop build environment for HushVoting.

## Toolchain

- Node.js 22 and the npm version pinned by `packageManager` in `package.json`.
- Rust stable through `rustup`.
- Tauri 2 Linux system prerequisites.
- Java 17, Android command-line tools, Android SDK, and Android NDK 27 for Android work.

## Tauri Linux prerequisites

Install the current Tauri 2 Debian/Ubuntu prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  curl \
  file \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libssl-dev \
  libwebkit2gtk-4.1-dev \
  wget
```

Package names can change between Ubuntu releases. If Ubuntu 26.04 replaces one of these packages, use the current Tauri 2 Linux prerequisite package providing the same library rather than adding an unreviewed compatibility repository.

## Web application

```bash
npm ci
npm run dev
```

Open `http://localhost:3201`.

The browser server uses `.next` for its development output. Production web builds use `.next-web`, so running a build cannot overwrite a live development server's HMR state.

Production builds:

```bash
npm run build:web
npm run build:static
```

The standalone web server build is written under `.next-web`. The deterministic exported frontend bundle consumed by Tauri is written under `.next-static`.

## Ubuntu desktop application

```bash
npm ci
npm run tauri:dev
```

Tauri automatically starts a separate Next.js development server on `http://localhost:3202` using `.next-tauri`. This allows the browser WebApp on port `3201` and the Ubuntu desktop app to run at the same time without sharing a Next.js development directory.

The first `tauri:dev` launch compiles the Linux Cargo debug profile and can take tens of seconds. Later launches reuse `src-tauri/target` and normally compile only the small application crate. `npm run clean` intentionally preserves this native cache. Use `npm run clean:native` only when a full Rust/Tauri rebuild is actually required.

Before Tauri starts, the development command installs a per-user Linux desktop entry and approved icon under `~/.local/share`. This lets GNOME associate the development executable with the display name `HushVoting!` and the Sovereign Shield icon instead of showing a generic gear and `hush-voting-app`. Close and reopen an already-running desktop window after changing this identity.

To run both, use two terminals:

```bash
# Terminal 1 — browser WebApp
npm run dev

# Terminal 2 — Ubuntu desktop app
npm run tauri:dev
```

Build installable Linux artifacts:

```bash
npm run tauri:build:linux
```

Expected release formats are Debian (`.deb`) for Ubuntu and AppImage for portable Linux testing.

## Android application

After Java 17 and the Android SDK/NDK are configured:

```bash
npm ci
npm run tauri:android:init
npm run tauri:android:dev
npm run tauri:android:build:debug
```

The debug build command produces local APK/AAB artifacts without production signing. Release AABs are signed only in the protected workflow.

The Android emulator must be able to reach the selected HushServerNode endpoint. Localhost inside the emulator is the emulator itself; use `10.0.2.2` for an API running on the Ubuntu host when the transport adapter is introduced.

Production signing and Google Play upload are performed only by the protected Android release workflow. Never commit a keystore, service-account JSON, password, or generated signing properties.

## iOS

The shared Tauri/Next.js structure is intended to permit iOS later, but Ubuntu cannot build or sign an iOS application. iOS initialization and release require a reviewed macOS runner strategy, Apple signing assets, and an explicit GitHub Actions minutes budget.
