import { isSafeIdPathSegment } from './pathSegment';

describe('isSafeIdPathSegment', () => {
  it.each(['1', '42', 'adm1n', 'ef3kq5b2ahdkwf', 'sa-1-my_service', 'user.name', 'a.b.c', 'generic_oauth'])(
    'accepts %p',
    (id) => {
      expect(isSafeIdPathSegment(id)).toBe(true);
    }
  );

  it.each([
    '',
    '.',
    '..',
    '.hidden',
    'trailing.',
    'a..b',
    '../../logout',
    '../../profile/switch-org/2',
    '../../../logout?',
    'abc/def',
    'abc\\def',
    'abc?x=1',
    'abc#frag',
    '%2e%2e',
    '..%2F..%2Flogout',
    'abc def',
    'abc\n',
  ])('rejects %p', (id) => {
    expect(isSafeIdPathSegment(id)).toBe(false);
  });

  it('rejects non-string values', () => {
    expect(isSafeIdPathSegment(undefined)).toBe(false);
    expect(isSafeIdPathSegment(null)).toBe(false);
  });
});
