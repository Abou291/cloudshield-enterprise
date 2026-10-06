import { randomBytes } from 'node:crypto';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig(({ mode, command }) => {
  // Vite injects styles during development. A per-server nonce authorizes only
  // those style elements; the packaged build keeps its strict external CSS CSP.
  const nonce = command === 'serve' ? randomBytes(24).toString('base64') : undefined;
  return {
    base: mode === 'desktop' ? './' : '/',
    html: { cspNonce: nonce },
    plugins: [react(), {
      name: 'development-csp-nonce',
      transformIndexHtml(html: string) {
        return nonce ? html.replace("style-src 'self';", `style-src 'self' 'nonce-${nonce}';`)
          .replace("script-src 'self';", `script-src 'self' 'nonce-${nonce}';`) : html;
      },
    }],
    test: { environment: 'jsdom', setupFiles: './src/test-setup.ts', globals: true },
  };
});
