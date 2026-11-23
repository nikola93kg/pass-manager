import '@testing-library/jest-dom/vitest';
import { webcrypto, pbkdf2Sync } from 'node:crypto';
import { vi } from 'vitest';

// Ensure Web Crypto API is available on globalThis in jsdom
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
  });
}

// Deterministic, fast Argon2id substitute in jsdom tests so crypto tests run real
// WebCrypto AES-256-GCM + AAD + IV + salt + KDF parameter binding without requiring
// browser WASM instantiation in jsdom.
vi.mock('argon2-browser', () => ({
  ArgonType: {
    Argon2d: 0,
    Argon2i: 1,
    Argon2id: 2,
  },
  hash: vi.fn(
    async (opts: {
      pass: Uint8Array | string;
      salt: Uint8Array;
      mem: number;
      time: number;
      parallelism: number;
      hashLen: number;
    }) => {
      const passBuf =
        typeof opts.pass === 'string' ? Buffer.from(opts.pass, 'utf8') : Buffer.from(opts.pass);
      // Mix KDF params into salt so changing memory/iterations/parallelism changes derived key
      const paramSalt = Buffer.concat([
        Buffer.from(opts.salt),
        Buffer.from(`|m=${opts.mem}|t=${opts.time}|p=${opts.parallelism}`),
      ]);
      const derived = pbkdf2Sync(passBuf, paramSalt, 1000, opts.hashLen || 32, 'sha256');
      return {
        hash: new Uint8Array(derived),
        hashHex: derived.toString('hex'),
        encoded: `mock-argon2id:${derived.toString('base64')}`,
      };
    }
  ),
}));
