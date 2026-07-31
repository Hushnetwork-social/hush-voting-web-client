import { getRuntimeTarget } from './runtime-target';

describe('getRuntimeTarget', () => {
  afterEach(() => {
    Reflect.deleteProperty(window, '__TAURI_INTERNALS__');
  });

  it('returns web in a browser without the Tauri bridge', () => {
    expect(getRuntimeTarget()).toBe('web');
  });

  it('returns tauri when the scoped native bridge exists', () => {
    Object.defineProperty(window, '__TAURI_INTERNALS__', {
      configurable: true,
      value: {},
    });

    expect(getRuntimeTarget()).toBe('tauri');
  });
});
