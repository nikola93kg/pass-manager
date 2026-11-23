/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
        crypto: false,
      };
    }

    // Redirect all imports of argon2-browser to the self-contained bundled
    // version. The default lib/argon2.js uses require('../dist/argon2.wasm')
    // which webpack converts to an asset URL string; decodeWasmBinary() then
    // calls atob(url) and throws "string not correctly encoded".
    // The bundled version has the WASM embedded as base64 — no external file.
    config.resolve.alias = {
      ...config.resolve.alias,
      'argon2-browser': require.resolve(
        'argon2-browser/dist/argon2-bundled.min.js'
      ),
    };

    // Do not let webpack re-parse/transform the already-minified bundle.
    // This preserves the embedded base64 WASM string intact.
    const existing = config.module.noParse;
    const bundledRe = /argon2-bundled\.min\.js$/;
    config.module.noParse = existing
      ? (file) =>
          bundledRe.test(file) ||
          (typeof existing === 'function' ? existing(file) : existing.test(file))
      : bundledRe;

    return config;
  },
};

module.exports = nextConfig;
