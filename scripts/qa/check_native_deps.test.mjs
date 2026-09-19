import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'check_native_deps.mjs');
const host = process.platform === 'win32' ? 'win32-x64-msvc' : 'linux-x64-gnu';
const other = process.platform === 'win32' ? 'linux-x64-gnu' : 'win32-x64-msvc';

function packageAt(root, path, name) {
  const file = join(root, path, 'package.json');
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify({ name, main: 'index.js' }));
  writeFileSync(join(root, path, 'index.js'), 'module.exports = {};\n');
}

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'lumen-native-deps-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rolldown = 'apps/web/node_modules/vite/node_modules/rolldown';
  const tauri = 'apps/desktop/node_modules/@tauri-apps/cli';
  packageAt(root, 'apps/web/node_modules/vite', 'vite');
  packageAt(root, rolldown, 'rolldown');
  packageAt(root, tauri, '@tauri-apps/cli');
  return { root, rolldown, tauri };
}

function addBindings({ root, rolldown, tauri }, suffix) {
  packageAt(root, `${rolldown}/node_modules/@rolldown/binding-${suffix}`, `@rolldown/binding-${suffix}`);
  packageAt(root, `${tauri}/node_modules/@tauri-apps/cli-${suffix}`, `@tauri-apps/cli-${suffix}`);
}

function preflight(root) {
  return spawnSync(process.execPath, [script], { cwd: root, encoding: 'utf8' });
}

test('reports the host bindings missing from a wrong-platform tree', (t) => {
  const tree = fixture(t);
  addBindings(tree, other);
  const result = preflight(tree.root);
  assert.equal(result.status, 1);
  assert.match(result.stderr, new RegExp(`@rolldown/binding-${host}`));
  assert.match(result.stderr, new RegExp(`@tauri-apps/cli-${host}`));
  assert.match(result.stderr, /separate Windows and WSL checkouts/);
  assert.match(result.stderr, /corepack pnpm install --frozen-lockfile/);
});

test('accepts loadable host bindings', (t) => {
  const tree = fixture(t);
  addBindings(tree, host);
  const result = preflight(tree.root);
  assert.equal(result.status, 0, result.stderr);
});
