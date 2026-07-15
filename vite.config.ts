import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-chain-of-trust/',
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
