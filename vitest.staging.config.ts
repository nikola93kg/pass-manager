import { defineConfig } from 'vitest/config';
import path from 'path';

// Real staging integration test configuration (NO crypto/Supabase mocks).
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['tests/staging/**/*.integration.test.ts'],
    testTimeout: 30000,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
});
