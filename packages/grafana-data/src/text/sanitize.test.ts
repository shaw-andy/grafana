import {
  sanitizeTextPanelContent,
  sanitizeUrl,
  sanitize,
  textUtil,
  validatePath,
  PathValidationError,
} from './sanitize';

/**
 * The browser decodes CSS escapes before it fetches a style url, so a check for the
 * literal function name misses `\75 rl(/logout)`, which Chrome still requests.
 */
function decodeCssEscapes(value: string): string {
  return value.replace(/\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?|\\(.)/g, (_, hex: string | undefined, ch: string) =>
    hex !== undefined ? String.fromCodePoint(parseInt(hex, 16)) : ch
  );
}

function insertedMarkup(html: string): string {
  const root = document.createElement('div');
  root.innerHTML = html;
  return Array.from(root.querySelectorAll('*'))
    .flatMap((el) => [el.getAttribute('style'), el.getAttribute('background')])
    .filter((value): value is string => value != null)
    .map((value) => decodeCssEscapes(value))
    .join('\n');
}

function expectNoSessionCssRequest(html: string) {
  const markup = insertedMarkup(html);
  expect(markup).not.toMatch(/url\s*\(/i);
  expect(markup).not.toMatch(/image-set\s*\(/i);
  expect(markup).not.toMatch(/(?:^|[^a-z-])image\s*\(/i);
  expect(markup).not.toContain('/logout');
  expect(markup).not.toContain('/profile/switch-org/');
}

const sessionCssPayloads = [
  '<div style="background-image:url(/logout)"></div>',
  `<div style="background-image:url('/logout')"></div>`,
  '<div style="background-image:url(&quot;/profile/switch-org/2&quot;)"></div>',
  '<div style="background:url(/logout)"></div>',
  '<li style="list-style-image:url(/logout)"></li>',
  '<li style="list-style:url(/logout) inside"></li>',
  '<div style="border-image:url(/logout) 30 stretch"></div>',
  '<div style="border-image-source:url(/logout)"></div>',
  '<div style="background-image:image-set(url(/logout) 1x)"></div>',
  '<div style="background-image:image(url(/logout))"></div>',
  '<div style="background-image:URL( /logout )"></div>',
  '<div style="background-image:\\75 rl(/logout)"></div>',
  '<div style="background-image:url(/logout); color:red">kept</div>',
];

describe('sanitizeTextPanelContent', () => {
  it('should allow whitelisted styles in text panel', () => {
    const html =
      '<div style="display:flex; flex-direction: column; flex-wrap: wrap; justify-content: start; gap: 2px;"><div style="flex-basis: 50%"></div></div>';
    const str = sanitizeTextPanelContent(html);
    expect(str).toBe(
      '<div style="display:flex; flex-direction:column; flex-wrap:wrap; justify-content:start; gap:2px;"><div style="flex-basis:50%;"></div></div>'
    );
  });

  it('should escape xss payload', () => {
    const html = '<script>alert(1)</script>';
    const str = sanitizeTextPanelContent(html);
    expect(str).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('should allow markdown generated unstyled disabled checkbox inputs', () => {
    const str = sanitizeTextPanelContent(`<input disabled="" type="checkbox">
<input checked="" disabled="" type="checkbox">`);
    expect(str).toMatch(/<input disabled(="")? type="checkbox">/);
    expect(str).toMatch(/<input checked(="")? disabled(="")? type="checkbox">/);
  });

  it('should sanitize arbitrary input elements', () => {
    const str = sanitizeTextPanelContent(`<input>
        <input type="text">
        <input disabled="" type="radio">
        <input disabled="" type="checkbox" class="some-class">
        <input checked="" disabled="" type="checkbox" class="some-class">`);
    expect(str).not.toMatch(/<input/);
  });

  it('should allow button elements with safe attributes', () => {
    const str = sanitizeTextPanelContent(
      '<button class="btn" style="width: 100%; height: 50px; background-color: lightgrey; color: black" type="button">Click me</button>'
    );
    expect(str).toContain('<button');
    expect(str).toContain('class="btn"');
    expect(str).toContain('Click me');
  });

  it('should strip event handlers from button elements', () => {
    const str = sanitizeTextPanelContent('<button onclick="alert(1)">Click me</button>');
    expect(str).not.toContain('onclick');
    expect(str).toContain('<button');
    expect(str).toContain('Click me');
  });

  it.each(sessionCssPayloads)('drops a same-origin CSS request from %s', (html) => {
    const sanitized = sanitizeTextPanelContent(html);
    expectNoSessionCssRequest(sanitized);
    if (html.includes('color:red')) {
      expect(sanitized).toContain('color:red');
      expect(sanitized).toContain('kept');
    }
  });

  it('keeps color and keyword backgrounds that do not fetch', () => {
    const sanitized = sanitizeTextPanelContent(
      '<div style="background-color: red; background: none; color: black; list-style: disc; border: 1px solid red"></div>'
    );
    expect(sanitized).toContain('background-color:red');
    expect(sanitized).toContain('background:none');
    expect(sanitized).toContain('color:black');
    expect(sanitized).toContain('list-style:disc');
    expect(sanitized).toContain('border:1px solid red');
  });

  it('still drops a script-scheme CSS url', () => {
    const sanitized = sanitizeTextPanelContent('<div style="background-image:url(javascript:alert(1))">kept</div>');
    expect(sanitized).not.toMatch(/javascript/i);
    expect(sanitized).not.toMatch(/url\s*\(/i);
    expect(sanitized).toContain('kept');
  });
});

describe('sanitizeUrl', () => {
  it('sanitize javascript urls', () => {
    const url = 'javascript:alert(document.domain)';
    const str = sanitizeUrl(url);
    expect(str).toBe('about:blank');
  });
});

describe('sanitizeIframe', () => {
  it('should sanitize iframe tags', () => {
    const html = '<iframe src="javascript:alert(document.domain)"></iframe>';
    const str = sanitizeTextPanelContent(html);
    expect(str).toBe('<iframe src="about:blank" sandbox credentialless referrerpolicy=no-referrer></iframe>');
  });
});

describe('sanitize', () => {
  it.each(sessionCssPayloads)('drops a same-origin CSS request from %s', (html) => {
    expectNoSessionCssRequest(sanitize(html));
  });

  it('drops an HTML background attribute the browser fetches with the session', () => {
    const sanitized = sanitize(
      '<table background="/logout"><tr><td background="/profile/switch-org/2">x</td></tr></table><body background="/logout"></body>'
    );
    expectNoSessionCssRequest(sanitized);
    expect(insertedMarkup(sanitized)).not.toContain('/logout');
  });

  it('should sanitize xss payload', () => {
    const html = '<script>alert(1)</script>';
    const str = sanitize(html);
    expect(str).toBe('');
  });

  describe('should sanitize anchors with target="_blank"', () => {
    it('should add rel="noopener noreferrer" to target="_blank" links', () => {
      const html = '<a href="https://example.com" target="_blank">Link</a>';
      const str = sanitize(html);
      expect(str).toBe('<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>');
    });

    it('should preserve existing rel attributes and add noopener noreferrer, if not already added', () => {
      const html = '<a href="https://example.com" target="_blank" rel="external noreferrer">Link</a>';
      const str = sanitize(html);
      expect(str).toBe('<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>');
    });

    it('should not modify links without target="_blank"', () => {
      const html = '<a href="https://example.com">Link</a>';
      const str = sanitize(html);
      expect(str).toBe('<a href="https://example.com">Link</a>');
    });
  });
});

describe('sanitizeSVGContent', () => {
  it('drops a same-origin CSS request from an SVG style attribute', () => {
    const sanitized = textUtil.sanitizeSVGContent(
      '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10" style="background-image:url(/logout)" /></svg>'
    );
    expectNoSessionCssRequest(sanitized);
    expect(sanitized).toContain('<rect');
  });
});

describe('validatePath', () => {
  describe('path traversal protection', () => {
    it('should block simple path traversal attempts', () => {
      expect(() => validatePath('/api/../admin')).toThrow(PathValidationError);
      expect(() => validatePath('api/../admin')).toThrow(PathValidationError);
      expect(() => validatePath('../admin')).toThrow(PathValidationError);
    });

    it('should block URL encoded path traversal attempts', () => {
      expect(() => validatePath('/api/%2e%2e/admin')).toThrow(PathValidationError);
      expect(() => validatePath('/api/%252e%252e/admin')).toThrow(PathValidationError);
    });

    it('should block double encoded traversal attempts', () => {
      expect(() => validatePath('/api/%252e%252e/admin')).toThrow(PathValidationError);
    });

    it('should handle malformed URI encoding gracefully', () => {
      expect(() => validatePath('/api/%/admin')).toThrow(PathValidationError);
      expect(() => validatePath('/api/%2/admin')).toThrow(PathValidationError);
    });

    it('should block paths with tab characters', () => {
      expect(() => validatePath('/api/\tadmin')).toThrow(PathValidationError);
      expect(() => validatePath('/api/users\t/123')).toThrow(PathValidationError);
    });

    it('should block paths with newline characters', () => {
      expect(() => validatePath('/api/\nadmin')).toThrow(PathValidationError);
      expect(() => validatePath('/api/users\n/123')).toThrow(PathValidationError);
    });

    it('should block paths with carriage return characters', () => {
      expect(() => validatePath('/api/\radmin')).toThrow(PathValidationError);
      expect(() => validatePath('/api/users\r/123')).toThrow(PathValidationError);
    });

    it('should block URL encoded tab and newline characters', () => {
      expect(() => validatePath('/api/%09admin')).toThrow(PathValidationError); // tab
      expect(() => validatePath('/api/%0Aadmin')).toThrow(PathValidationError); // newline
      expect(() => validatePath('/api/%0Dadmin')).toThrow(PathValidationError); // carriage return
    });
  });

  describe('safe paths', () => {
    it('should preserve safe paths', () => {
      expect(validatePath('/api/users/123')).toBe('/api/users/123');
      expect(validatePath('/api/dashboard/save')).toBe('/api/dashboard/save');
      expect(validatePath('api/config')).toBe('api/config');
    });

    it('should preserve paths with file extensions', () => {
      expect(validatePath('/api/file.json')).toBe('/api/file.json');
      expect(validatePath('/static/image.png')).toBe('/static/image.png');
    });

    it('should preserve paths with query parameters', () => {
      expect(validatePath('/api/search?q=test')).toBe('/api/search?q=test');
      expect(validatePath('/api/file.json?version=1.2.3&format=compact')).toBe(
        '/api/file.json?version=1.2.3&format=compact'
      );
    });

    it('should handle empty and root paths', () => {
      expect(validatePath('')).toBe('');
      expect(validatePath('/')).toBe('/');
    });
  });

  describe('full URL handling', () => {
    it('should preserve safe full URLs', () => {
      const safeUrl = 'https://api.example.com/users/123';
      expect(validatePath(safeUrl)).toBe(safeUrl);
    });

    it('should preserve URLs with query parameters and fragments', () => {
      const urlWithQuery = 'https://api.example.com/search?q=test&limit=10#results';
      expect(validatePath(urlWithQuery)).toBe(urlWithQuery);
    });

    it('should block traversal in URL paths while preserving query params', () => {
      expect(() => validatePath('https://api.example.com/api/../admin?token=abc')).toThrow(PathValidationError);
      expect(() => validatePath('http://localhost:3000/api/%2e%2e/secrets?param=value')).toThrow(PathValidationError);
    });

    it('should allow legitimate dots in URL paths with query params', () => {
      const urlWithDots = 'https://cdn.example.com/files/document.v1.2.pdf?download=true';
      expect(validatePath(urlWithDots)).toBe(urlWithDots);
    });

    it('should block query parameters that contain path traversal', () => {
      const urlWithTraversalInQuery = 'https://api.example.com/search?version=1.2.3&file=../config';
      expect(() => validatePath(urlWithTraversalInQuery)).toThrow(PathValidationError);
    });

    it('should handle malformed URLs gracefully', () => {
      expect(() => validatePath('not-a-url://../admin')).toThrow(PathValidationError);
      expect(validatePath('://malformed')).toBe('://malformed'); // No traversal attempt, so it's allowed
    });

    it('should handle URLs with different protocols', () => {
      expect(validatePath('ftp://files.example.com/safe/path')).toBe('ftp://files.example.com/safe/path');
      expect(() => validatePath('ftp://files.example.com/../secrets')).toThrow(PathValidationError);
    });

    it('should handle URLs with backslashes', () => {
      expect(() => validatePath('https://api.example.com/\\example.com')).toThrow(PathValidationError);
    });

    it('should handle URLs with backslashes and dots in the path', () => {
      expect(() => validatePath('https://api.example.com/\\..\\/admin')).toThrow(PathValidationError);
    });
  });
});
