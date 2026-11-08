#!/usr/bin/env node
// Thin executable wrapper around the built CLI. Run `npm run build` first.
try {
  const { runCli, createNodeIO } = await import('../dist/cli/main.js');
  process.exitCode = await runCli(process.argv.slice(2), createNodeIO());
} catch (error) {
  console.error(`dsh-trust-broker: ${error instanceof Error ? error.message : String(error)}`);
  console.error('提示：先在本项目中运行 `npm run build` 生成 dist/。');
  process.exitCode = 1;
}
