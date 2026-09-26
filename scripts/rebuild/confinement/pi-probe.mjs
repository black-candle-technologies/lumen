// Instrumented, deterministic model fixture. No provider credentials or HTTP.
// The real upstream CLI/agent loop calls the actual BCT requestRead bridge.
import { requestRead } from './host-client.mjs';
import { createRequire } from 'node:module';
import { readFileSync, writeSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const { probe: syscall } = createRequire(import.meta.url)('/guard/probe.node');

export default function probe(pi) {
  pi.registerTool({
    name: 'bct.read_file', label: 'Mediated test read', description: 'Request a kernel decision.',
    parameters: { type: 'object', additionalProperties: false, required: ['path', 'max_bytes'],
      properties: { path: { type: 'string' }, max_bytes: { type: 'integer' } } },
    execute(id, params, signal, _update, ctx) { return requestRead(id, params, signal, ctx.ui); },
  });
  pi.on('session_start', () => pi.setActiveTools(['bct.read_file']));
  pi.registerProvider('lumen-fixture', {
    baseUrl: 'https://invalid.invalid', apiKey: 'public-fixture-marker', api: 'lumen-fixture-api',
    models: [{ id: 'one', name: 'Deterministic Phase 0 probe', reasoning: false, input: ['text'],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 8192, maxTokens: 1024 }],
    streamSimple(model, context) {
      const finished = context.messages.some(message => message.role === 'toolResult');
      const user = context.messages.filter(message => message.role === 'user').at(-1);
      const text = typeof user.content === 'string' ? user.content : user.content.filter(c => c.type === 'text').map(c => c.text).join('');
      const path = JSON.parse(text).path;
      if (!finished) {
        let filesystemDenied = false;
        try { readFileSync(path); } catch { filesystemDenied = true; }
        const shell = spawnSync('/usr/bin/node', ['-e', "console.log('ESCAPED')"]);
        const names = ['socket_inet', 'socket_inet6', 'socket_unix', 'fork', 'clone_process',
          'execve', 'execveat', 'unshare', 'ptrace', 'io_uring', 'bpf', 'ioctl_inject'];
        writeSync(1, JSON.stringify({ type: 'lumen_phase0_bypass_probe',
          activeTools: pi.getActiveTools(), filesystemDenied, shellDenied: !!shell.error,
          syscalls: Object.fromEntries(names.map(name => [name, syscall(name)])),
          environment: Object.keys(process.env).sort() }) + '\n');
      }
      const message = { role: 'assistant', api: model.api, provider: model.provider, model: model.id,
        timestamp: 0, stopReason: finished ? 'stop' : 'toolUse',
        usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
        content: finished ? [{ type: 'text', text: 'Mediation probe completed.' }] :
          [{ type: 'toolCall', id: 'phase0-read-1', name: 'bct.read_file', arguments: { path, max_bytes: 65536 } }] };
      return { async *[Symbol.asyncIterator]() {
        yield { type: 'start', partial: message };
        yield { type: 'done', reason: message.stopReason, message };
      }, result: async () => message };
    },
  });
}
