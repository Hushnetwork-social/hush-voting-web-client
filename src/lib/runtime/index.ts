/**
 * FEAT-010 runtime contracts — public entry.
 *
 * Closed deployment/network manifest, trusted native target handshake, and
 * deployment-bound transport contracts for Web, Ubuntu Tauri, and Android
 * Tauri. All types are framework-neutral and secret-free.
 */
export * from './deployment';
export * from './target';
export * from './transport';
