import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../../../');
const outfile = process.argv[2];

if (!outfile) {
  throw new Error('usage: node sandboxDomInsertion.bundle.mjs <outfile>');
}

await esbuild.build({
  absWorkingDir: repoRoot,
  entryPoints: [path.join(here, 'sandboxDomInsertion.harness.ts')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'chrome120',
  outfile,
  conditions: ['@grafana-app/source', 'browser', 'import', 'module', 'default'],
  alias: {
    app: path.join(repoRoot, 'public/app'),
    '@grafana/runtime/internal': path.join(here, 'sandboxDomInsertion.runtimeInternal.ts'),
  },
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  loader: {
    '.svg': 'dataurl',
    '.ttf': 'dataurl',
    '.png': 'dataurl',
    '.gif': 'dataurl',
    '.css': 'empty',
    '.woff': 'dataurl',
    '.woff2': 'dataurl',
  },
  plugins: [
    {
      name: 'systemjs-extension',
      setup(build) {
        build.onResolve({ filter: /^systemjs\/dist\// }, (args) => {
          const specifier = args.path.endsWith('.js') ? args.path : `${args.path}.js`;
          return { path: require.resolve(specifier) };
        });
      },
    },
  ],
});
