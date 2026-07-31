import type { NextConfig } from 'next';

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
};

export default nextConfig;
