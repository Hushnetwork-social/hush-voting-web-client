import type { NextConfig } from 'next';
import { productionSecurityHeaderConfig } from './src/lib/browser-vault/deployment/headers';

const isStaticExport = process.env.STATIC_EXPORT === 'true';
const isStandaloneBuild = process.env.STANDALONE_BUILD === 'true';
const isTauriDevelopment = process.env.TAURI_DEV === 'true';

const nextConfig: NextConfig = {
  allowedDevOrigins: ['localhost', '127.0.0.1'],
  distDir: isStaticExport
    ? '.next-static'
    : isTauriDevelopment
      ? '.next-tauri'
      : isStandaloneBuild
        ? '.next-web'
        : '.next',
  output: isStaticExport ? 'export' : isStandaloneBuild ? 'standalone' : undefined,
  images: {
    unoptimized: isStaticExport,
  },
  poweredByHeader: false,
  turbopack: {
    root: process.cwd(),
  },
  // FEAT-004: restrictive security headers on the production web build only
  // (dev/HMR and test harnesses are unaffected). Static export cannot apply
  // Next.js headers, so the config is omitted there to avoid the
  // export-no-custom-routes warning (headers are never applied in export mode).
  ...(isStaticExport ? {} : { headers: productionSecurityHeaderConfig() }),
};

export default nextConfig;
