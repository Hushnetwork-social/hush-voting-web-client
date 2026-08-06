import { defineConfig, globalIgnores } from 'eslint/config';
import nextCoreWebVitals from 'eslint-config-next/core-web-vitals';
import nextTypeScript from 'eslint-config-next/typescript';

export default defineConfig([
  ...nextCoreWebVitals,
  ...nextTypeScript,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  globalIgnores([
    'node_modules/**',
    '.next/**',
    '.next-web/**',
    '.next-tauri/**',
    '.next-static/**',
    'out/**',
    'coverage/**',
    'src-tauri/target/**',
    'src-tauri/gen/**',
    'next-env.d.ts',
    'public/workers/**',
    'conformance/identity/v1/scripts/vendor/**',
  ]),
]);
