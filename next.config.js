/** @type {import('next').NextConfig} */
const nextConfig = {
  // Full Next.js server runtime enables middleware, CSP nonces,
  // server-side Auth/MFA API routes, rate limiting, and dynamic /item/[id] deep links.
  poweredByHeader: false,
  reactStrictMode: true,
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

    // Redirect argon2-browser imports to the self-contained bundled build
    // (embedded base64 WASM, no external .wasm file fetch needed).
    config.resolve.alias = {
      ...config.resolve.alias,
      'argon2-browser': require.resolve(
        'argon2-browser/dist/argon2-bundled.min.js'
      ),
    };

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
