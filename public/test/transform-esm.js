const ts = require('typescript');

// Jest's default transformer does not rewrite `.mjs` in node_modules. Mermaid 11
// and a few of its dependencies ship native ESM, which the security tests have to
// execute rather than mock.
module.exports = {
  process(src, filename) {
    const result = ts.transpileModule(src, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
        allowJs: true,
      },
      fileName: filename.replace(/\.mjs$/, '.js'),
    });
    return { code: result.outputText };
  },
};
