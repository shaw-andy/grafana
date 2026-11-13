// A console link is safe when the browser will not leave an AWS console host.
// An empty href or about:blank means the link was refused. Any other href must
// parse as https on a single-label region plus a known partition console suffix,
// with no userinfo. The check is applied to the string that is placed on the
// anchor, so a validation step that does not change that string still fails.
const CONSOLE_HOST =
  /^[a-z0-9-]+\.(?:console\.aws\.amazon\.com|console\.amazonaws-us-gov\.com|console\.amazonaws\.cn)$/;

export const hostileRegions = [
  'attacker.example#',
  'attacker.example?',
  'attacker.example/',
  'attacker.example\\',
  'attacker.example@',
  'attacker.example ',
  'attacker.example',
];

export function expectSafeConsoleHref(href: string | null | undefined, leakedText?: string): void {
  if (href == null || href === '' || href === 'about:blank') {
    return;
  }

  let url: URL;
  try {
    url = new URL(href);
  } catch {
    expect({ href, parseable: false }).toEqual({ href: '', parseable: true });
    return;
  }
  const carried = leakedText ? `${url.hash}${url.search}${url.pathname}`.includes(leakedText) : false;
  expect({
    protocol: url.protocol,
    username: url.username,
    password: url.password,
    hostname: url.hostname,
    leakedTextOnForeignHost: carried && !CONSOLE_HOST.test(url.hostname),
  }).toEqual({
    protocol: 'https:',
    username: '',
    password: '',
    hostname: expect.stringMatching(CONSOLE_HOST),
    leakedTextOnForeignHost: false,
  });
}
