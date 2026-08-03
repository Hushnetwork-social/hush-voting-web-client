#[cfg(desktop)]
use tauri::{image::Image, Manager};

/// FEAT-005 Ubuntu vault adapter (contracts/storage model Phase 2; Secret
/// Service/crypto/atomic lifecycle Phase 3; native session/command/transport/
/// single-instance Phase 4; composition hardening Phase 6).
pub mod ubuntu_vault;

use ubuntu_vault::commands::{hush_vault_handshake, hush_vault_submit_secret, VaultState};
use ubuntu_vault::lifecycle::ownership::VaultOwnership;

#[cfg(desktop)]
fn application_icon() -> tauri::Result<Image<'static>> {
    Image::from_bytes(include_bytes!("../icons/icon.png")).map(|icon| icon.to_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Exactly one HushVoting process per Ubuntu user session: a second
        // launch focuses the existing main window and performs no vault or
        // keyring action. Arbitrary command-line/deep-link input is never
        // forwarded into authenticated state.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .manage(VaultState::default())
        .invoke_handler(tauri::generate_handler![
            hush_vault_handshake,
            hush_vault_submit_secret
        ])
        .setup(|app| {
            #[cfg(desktop)]
            if let Some(window) = app.get_webview_window("main") {
                window.set_icon(application_icon()?)?;
            }

            // Defense in depth: exclusive vault ownership lock. A second
            // process that cannot acquire it must exit safely (the plugin
            // already focused the existing window). Crash-stale locks are
            // released by the kernel.
            #[cfg(desktop)]
            {
                use tauri::Manager;
                let app_data = app.path().app_data_dir().expect("app data dir");
                let vault_root = app_data.join("vault/v1");
                match VaultOwnership::try_acquire(&vault_root) {
                    Ok(_ownership) => {
                        // Ownership held for the process lifetime.
                        app.manage(OwnershipGuard(Some(_ownership)));
                    }
                    Err(ubuntu_vault::lifecycle::ownership::OwnershipError::AlreadyOwned) => {
                        // Another instance owns the vault: never touch
                        // keyring/vault state; the plugin focused the main
                        // window; exit quietly.
                        std::process::exit(0);
                    }
                    Err(ubuntu_vault::lifecycle::ownership::OwnershipError::LockUnavailable) => {
                        // Fail closed: no vault access without ownership.
                        std::process::exit(1);
                    }
                }
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running HushVoting");
}

/// Process-lifetime vault ownership guard (kept alive via managed state; the
/// lock is released when this is dropped at process end).
#[allow(dead_code)]
struct OwnershipGuard(Option<VaultOwnership>);
