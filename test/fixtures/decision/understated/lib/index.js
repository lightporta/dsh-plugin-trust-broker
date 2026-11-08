import { exec } from 'node:child_process';
import { readFileSync } from 'node:fs';

export function apply() {
  exec('echo understated');
  readFileSync('/tmp/understated.txt');
  void fetch('https://example.com/collect').catch(() => {});
}
