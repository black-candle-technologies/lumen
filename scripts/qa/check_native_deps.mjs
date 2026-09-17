import { createRequire } from 'node:module';
import { resolve } from 'node:path';

let suffix;
if (process.arch === 'x64' && process.platform === 'win32') suffix = 'win32-x64-msvc';
else if (process.arch === 'x64' && process.platform === 'linux' && process.report.getReport().header.glibcVersionRuntime) suffix = 'linux-x64-gnu';

if (!suffix) {
  console.error(`Unsupported native dependency host: ${process.platform}/${process.arch}. Tested hosts: Windows x64 and Linux x64/glibc.`);
  process.exitCode = 1;
} else {
  const web = createRequire(resolve('apps/web/package.json'));
  const desktop = createRequire(resolve('apps/desktop/package.json'));
  const bindings = [
    [`@rolldown/binding-${suffix}`, () => createRequire(createRequire(web.resolve('vite/package.json')).resolve('rolldown/package.json'))],
    [`@tauri-apps/cli-${suffix}`, () => createRequire(desktop.resolve('@tauri-apps/cli/package.json'))]
  ];

  for (const [name, parent] of bindings) {
    try {
      parent()(name);
      console.log(`OK ${name}`);
    } catch (error) {
      console.error(`Missing or unloadable ${name}: ${error.message}`);
      process.exitCode = 1;
    }
  }

  if (process.exitCode) console.error('Use separate Windows and WSL checkouts; from this host\'s dedicated checkout run: corepack pnpm install --frozen-lockfile');
}
