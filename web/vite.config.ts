import { defineConfig } from 'vitest/config';
import preact from '@preact/preset-vite';

// base:'./' keeps asset URLs relative so the same build serves at "/" or
// under a prefix such as "/next/".
export default defineConfig({
  base: './',
  plugins: [preact()],
  server: {
    port: 5173,
    proxy: {
      // Dev loop: `npm run dev` here + `node server/index.js` (port 4040) +
      // an agent with KUBE_LOGGER_RELAY=http://localhost:4040.
      '/consumer': { target: 'ws://localhost:4040', ws: true },
      '/health': 'http://localhost:4040',
      '/stats': 'http://localhost:4040',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'fixtures/**/*.test.ts'],
    environmentMatchGlobs: [['src/components/**', 'jsdom']],
  },
});
