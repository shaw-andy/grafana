import { spawnSync } from 'node:child_process';
import path from 'path';

/**
 * Spec for sandboxed plugin DOM insertion.
 *
 * These assertions describe the secure behavior. They fail while script elements
 * passed to append, prepend, before, after, and the other insertion methods below
 * still reach the host document and run there.
 *
 * Jest replaces @locker/near-membrane-dom with an empty stub, so the runner bundles
 * the real loader in a separate Node process and executes it in headless Chrome.
 * Chrome runs connected script elements in the page, which is the outcome under test.
 */

interface CaseResult {
  name: string;
  pluginRan: boolean;
  hostExecuted: boolean;
  connectedToHost: boolean;
  hostValue: string | null;
  error: string | null;
}

describe('sandboxed plugin script insertion', () => {
  let results: CaseResult[];

  beforeAll(() => {
    const runner = path.join(__dirname, 'scriptInsertionEscape.runner.cjs');
    const child = spawnSync(process.execPath, [runner], {
      cwd: path.resolve(__dirname, '../../../../../'),
      encoding: 'utf8',
      timeout: 120000,
      env: { ...process.env, NODE_ENV: 'production' },
    });

    if (child.error) {
      throw child.error;
    }

    let parsed: { results?: CaseResult[]; error?: string; errors?: string[] };
    try {
      parsed = JSON.parse(child.stdout);
    } catch {
      throw new Error(`runner output was not JSON:\n${child.stdout}\n${child.stderr}`);
    }

    if (parsed.error || !parsed.results) {
      throw new Error(parsed.error || `runner failed:\n${child.stderr}\n${(parsed.errors || []).join('\n')}`);
    }

    results = parsed.results;
  }, 120000);

  // Node.appendChild already keeps script elements out of the host document.
  // Document.append, Document.prepend, and Document.replaceChildren are not listed:
  // on a parsed page Chrome rejects them with HierarchyRequestError, so the script
  // never runs. Removing documentElement first makes Document.append succeed.
  // Every case below shares the missing script handling.
  const vulnerableCases = [
    'Element.append',
    'Element.append textContent',
    'Element.append child text',
    'Element.append with a sibling iframe',
    'Element.prepend',
    'Element.before',
    'Element.after',
    'Element.replaceChildren',
    'Element.replaceWith',
    'Element.insertAdjacentElement',
    'Document.append after removing documentElement',
    'Node.insertBefore',
    'Node.replaceChild',
    'CharacterData.before',
    'CharacterData.after',
    'DocumentFragment.append then Node.appendChild',
    'DocumentFragment.prepend then Node.appendChild',
  ];

  it.each(vulnerableCases)('%s does not run the script in the host page', (name) => {
    const result = results.find((item) => item.name === name);
    expect(result).toEqual({
      name,
      pluginRan: true,
      hostExecuted: false,
      connectedToHost: false,
      hostValue: null,
      error: null,
    });
  });

  it('Node.appendChild does not run the script in the host page', () => {
    const result = results.find((item) => item.name === 'Node.appendChild');
    expect(result).toEqual({
      name: 'Node.appendChild',
      pluginRan: true,
      hostExecuted: false,
      connectedToHost: false,
      hostValue: null,
      error: null,
    });
  });
});
