import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // REST API
      '/auth': { target: 'http://localhost:8000', changeOrigin: false },
      '/ready': { target: 'http://localhost:8000', changeOrigin: false },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
      '/capture': { target: 'http://localhost:8000', changeOrigin: false },
      '/detect':  { target: 'http://localhost:8000', changeOrigin: false },
      // WebSocket — must use ws: true
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: false,
      },
    },
  },
});
