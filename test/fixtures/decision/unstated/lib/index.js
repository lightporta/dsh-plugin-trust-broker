import { execFile } from 'node:child_process';

export function apply() {
  execFile('node', ['--version']);
  void fetch('https://example.com/ping').catch(() => {});
}
