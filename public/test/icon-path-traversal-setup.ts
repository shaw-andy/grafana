// Webpack's publicPath is this relative directory (scripts/webpack/webpack.common.ts).
// The index template sets <base href="/"> when Grafana is not served from a subpath.
window.__grafana_build_path__ = 'public/build/';

const base = document.createElement('base');
base.href = '/';
document.head.appendChild(base);
window.history.replaceState({}, '', '/d/uid/dashboard-slug');
