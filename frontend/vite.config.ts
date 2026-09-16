import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // REST API
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
      '/capture': { target: 'http://localhost:8000', changeOrigin: true },
      '/detect':  { target: 'http://localhost:8000', changeOrigin: true },
      // WebSocket — must use ws: true
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
});
