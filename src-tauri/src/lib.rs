#[cfg(desktop)]
use tauri::{image::Image, Manager};

/// FEAT-005 Ubuntu vault adapter (contracts + storage model in Phase 2;
/// Secret Service/crypto/session/composition in Phases 3, 4, 6).
pub mod ubuntu_vault;

#[cfg(desktop)]
fn application_icon() -> tauri::Result<Image<'static>> {
    Image::from_bytes(include_bytes!("../icons/icon.png")).map(|icon| icon.to_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(desktop)]
            if let Some(window) = app.get_webview_window("main") {
                window.set_icon(application_icon()?)?;
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running HushVoting");
}
