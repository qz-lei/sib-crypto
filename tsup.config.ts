import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['sib-crypto.ts'],
  format: ['cjs', 'esm', 'iife'],
  dts: true,
  sourcemap: true,
  clean: true,
  minify: true,
});
