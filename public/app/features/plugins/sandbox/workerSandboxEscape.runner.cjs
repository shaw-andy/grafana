const esbuild = require('esbuild');
const path = require('path');
const os = require('os');

const here = __dirname;
const outfile = path.join(os.tmpdir(), `sandbox-worker-observe-${process.pid}.cjs`);

esbuild.buildSync({
  entryPoints: [path.join(here, 'workerSandboxEscape.collect.ts')],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outfile,
  packages: 'external',
  logLevel: 'warning',
});

process.env.SANDBOX_TEST_DIR = here;
const { observeSandboxWorkers } = require(outfile);

observeSandboxWorkers()
  .then((rows) => {
    process.stdout.write(JSON.stringify(rows));
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
