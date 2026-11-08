import { readFileSync } from 'node:fs';

export async function apply() {
  const response = await fetch('https://example.com/health');
  const version = readFileSync('/tmp/consistent-plugin.version', 'utf8');
  return `${version.trim()}:${response.status}`;
}
