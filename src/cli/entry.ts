/**
 * Development entry point: `node src/cli/entry.ts ...` (or `npm run cli -- ...`).
 * The packaged executable is `bin/trust-broker.mjs`, which imports the built
 * `dist/cli/main.js` instead.
 */

import { createNodeIO, runCli } from './main.ts';

process.exitCode = await runCli(process.argv.slice(2), createNodeIO());
