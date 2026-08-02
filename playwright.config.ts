import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  timeout: 60_000,
  use: {
    baseURL: 'http://localhost:4173/crypto-lab-chain-of-trust/',
    colorScheme: 'dark',
    contextOptions: { reducedMotion: 'reduce' }, // builder runs render instantly under the gate
  },
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: 'npm run build && npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173/crypto-lab-chain-of-trust/',
    reuseExistingServer: !process.env.CI,
  },
});
