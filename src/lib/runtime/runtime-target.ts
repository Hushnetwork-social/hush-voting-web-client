export type RuntimeTarget = 'web' | 'tauri';

export function getRuntimeTarget(): RuntimeTarget {
  if (typeof window === 'undefined') {
    return 'web';
  }

  return '__TAURI_INTERNALS__' in window || '__TAURI__' in window ? 'tauri' : 'web';
}
