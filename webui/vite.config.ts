import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: '',
  plugins: [
    {
      name: 'canonical-vue-line-endings',
      enforce: 'pre',
      transform(code, id) {
        // Vue's production scope IDs include the source text, including newlines.
        if (id.endsWith('.vue')) return code.replace(/\r\n?/g, '\n')
      },
    },
    vue(),
  ],
  build: {
    target: 'chrome94',
    cssTarget: 'chrome94',
    outDir: '../template/webroot',
    emptyOutDir: true,
    cssCodeSplit: false,
  },
})
