import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'
import config from './vite.config.ts'

const workspace = fileURLToPath(new URL('.', import.meta.url))
const root = await mkdtemp(join(workspace, '.webui-repro-'))
try {
  await writeFile(join(root, 'index.html'), '<div id="app"></div><script type="module" src="/main.js"></script>')
  await writeFile(join(root, 'main.js'), "import {createApp} from 'vue'; import App from './App.vue'; createApp(App).mount('#app')")
  const source = '<template>\n<p>Renewal</p>\n</template>\n<style scoped>\np { color: red; }\n</style>\n'
  const results = []
  for (const newline of ['\n', '\r\n']) {
    await writeFile(join(root, 'App.vue'), source.replaceAll('\n', newline))
    const result = await build({
      ...config,
      root,
      logLevel: 'silent',
      publicDir: false,
      build: { ...config.build, outDir: join(root, 'dist'), write: false },
    })
    assert(!Array.isArray(result) && 'output' in result)
    results.push(result.output.map(item => [
      item.fileName,
      item.type === 'chunk' ? item.code : Buffer.from(item.source).toString('utf8'),
    ]).sort(([a], [b]) => a.localeCompare(b)))
  }
  assert.deepEqual(results[0], results[1], 'LF and CRLF must produce identical JS, CSS and HTML')
  console.log('WebUI LF/CRLF build reproducibility passed')
} finally {
  assert.equal(dirname(root), workspace.replace(/[\\/]$/, ''))
  assert(basename(root).startsWith('.webui-repro-'))
  await rm(root, { recursive: true, force: true })
}
