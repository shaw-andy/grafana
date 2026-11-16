import { renderMarkdown, renderTextPanelMarkdown } from './markdown';

describe('Markdown wrapper', () => {
  it('should be able to handle undefined value', () => {
    const str = renderMarkdown(undefined);
    expect(str).toBe('');
  });

  it('should sanitize by default', () => {
    const str = renderMarkdown('<script>alert()</script>');
    expect(str).toBe('&lt;script&gt;alert()&lt;/script&gt;');
  });

  it('should only escape (and not remove) code blocks inside markdown', () => {
    const inlineCodeBlock = renderMarkdown('This is a piece of code block: `<script>alert()</script>`');
    expect(inlineCodeBlock.trim()).toBe(
      '<p>This is a piece of code block: <code>&lt;script&gt;alert()&lt;/script&gt;</code></p>'
    );

    const multilineCodeBlock = renderMarkdown('This is a piece of code block: ```<script>alert()</script>```');
    expect(multilineCodeBlock.trim()).toBe(
      '<p>This is a piece of code block: <code>&lt;script&gt;alert()&lt;/script&gt;</code></p>'
    );
  });

  it('should allow markdown todo checkbox inputs', () => {
    const str = renderTextPanelMarkdown(`- [ ] unchecked
- [x] checked`);
    expect(str).toMatch(/<input disabled(="")? type="checkbox">/);
    expect(str).toMatch(/<input checked(="")? disabled(="")? type="checkbox">/);
  });

  it('should sanitize arbitrary input elements', () => {
    const str = renderTextPanelMarkdown(`<input>
      <input type="text">
      <input disabled="" type="radio">
      <input disabled="" type="checkbox" class="some-class">
      <input checked="" disabled="" type="checkbox" class="some-class">`);
    expect(str).not.toMatch(/<input/);
  });

  it('should sanitize content in text panel by default', () => {
    const str = renderTextPanelMarkdown('<script>alert()</script>');
    expect(str).toBe('&lt;script&gt;alert()&lt;/script&gt;');
  });

  it.each([
    ['renderMarkdown', renderMarkdown],
    ['renderTextPanelMarkdown', renderTextPanelMarkdown],
  ] as const)('%s drops a same-origin CSS url from raw HTML', (_name, render) => {
    const html = render(
      '<div style="background-image:url(/logout)"></div>\n\n<div style="background:url(/profile/switch-org/2)"></div>'
    );
    const root = document.createElement('div');
    root.innerHTML = html;
    const styles = Array.from(root.querySelectorAll('[style]')).map((el) => el.getAttribute('style') ?? '');
    expect(styles.join('\n')).not.toMatch(/url\s*\(/i);
    expect(html).not.toContain('/logout');
    expect(html).not.toContain('/profile/switch-org/');
  });
});
