import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'crypto/index': 'src/crypto/index.ts',
    'vault/index': 'src/vault/index.ts',
    'utils/index': 'src/utils/index.ts',
    'fs/index': 'src/fs/index.ts',
  },
  format: ['esm', 'cjs'],
  platform: 'neutral',
  target: 'esnext',
  dts: true,
  sourcemap: false,
  clean: true,
  splitting: false,
  treeshake: true,
  outExtension({ format }) {
    return {
      js: format === 'esm' ? '.js' : '.cjs',
    };
  },
  esbuildOptions(options) {
    // Don't externalize packages - let bundler resolve them properly
    // This prevents directory import issues with ES modules
  },
});
