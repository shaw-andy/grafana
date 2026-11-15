import { render, screen } from '@testing-library/react';

import { type DataFrame, type DataQueryError, type QueryResultMetaNotice } from '@grafana/data';

import { StandardErrorsAndNoticesInspector } from './StandardErrorsAndNoticesInspector';

function frameWithNotices(notices: QueryResultMetaNotice[]): DataFrame {
  return { name: 'A', fields: [], length: 0, meta: { notices } } as DataFrame;
}

function setup(data: DataFrame[] = [], errors: DataQueryError[] = []) {
  return render(<StandardErrorsAndNoticesInspector data={data} errors={errors} />);
}

describe('StandardErrorsAndNoticesInspector', () => {
  it('shows an empty state when there are no errors or notices', () => {
    setup();
    expect(screen.getByText('No errors or notices for this query.')).toBeInTheDocument();
  });

  it('renders a card per severity with its label', () => {
    setup(
      [
        frameWithNotices([
          { severity: 'info', text: 'An informational thing' },
          { severity: 'warning', text: 'A cautionary thing' },
        ]),
      ],
      [{ message: 'Query blew up', data: { message: 'upstream 500' } }]
    );

    expect(screen.getByText('Error')).toBeInTheDocument();
    expect(screen.getByText('Warning')).toBeInTheDocument();
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  it('sorts cards error > warning > info', () => {
    setup(
      [
        frameWithNotices([
          { severity: 'info', text: 'info note' },
          { severity: 'warning', text: 'warning note' },
        ]),
      ],
      [{ message: 'error note' }]
    );

    const errorLabel = screen.getByText('Error');
    const warningLabel = screen.getByText('Warning');
    const infoLabel = screen.getByText('Info');

    // Error comes before Warning, Warning before Info, in document order.
    expect(errorLabel.compareDocumentPosition(warningLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(warningLabel.compareDocumentPosition(infoLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('dedupes identical notices', () => {
    setup([
      frameWithNotices([
        { severity: 'warning', text: 'duplicate' },
        { severity: 'warning', text: 'duplicate' },
      ]),
    ]);

    expect(screen.getAllByText('duplicate')).toHaveLength(1);
  });

  it('renders notice text as markdown (links and bold)', () => {
    setup([
      frameWithNotices([{ severity: 'info', text: 'See [the docs](https://example.com/docs) and **note this**' }]),
    ]);

    const link = screen.getByRole('link', { name: 'the docs' });
    expect(link).toHaveAttribute('href', 'https://example.com/docs');
    expect(screen.getByText('note this').tagName.toLowerCase()).toBe('strong');
  });

  it('renders a "Learn more" link from notice.link', () => {
    setup([frameWithNotices([{ severity: 'info', text: 'has a link', link: 'https://example.com/more' }])]);

    expect(screen.getByRole('link', { name: 'Learn more' })).toHaveAttribute('href', 'https://example.com/more');
  });

  it('renders the raw error payload for errors', () => {
    setup([], [{ message: 'Query failed', data: { message: 'detailed upstream error' } }]);
    expect(screen.getByText(/detailed upstream error/)).toBeInTheDocument();
  });

  it('renders the error message above the raw payload', () => {
    setup([], [{ message: 'Query failed', data: { message: 'detailed upstream error' } }]);

    const message = screen.getByText('Query failed');
    const payload = screen.getByText(/detailed upstream error/);
    expect(message.compareDocumentPosition(payload) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('falls back to the data message when the error has no top-level message', () => {
    setup([], [{ data: { message: 'only in data' } }]);
    expect(screen.getAllByText(/only in data/).length).toBeGreaterThanOrEqual(1);
  });

  it('provides a copy-to-clipboard button per card', () => {
    setup([
      frameWithNotices([
        { severity: 'warning', text: 'one' },
        { severity: 'info', text: 'two' },
      ]),
    ]);

    expect(screen.getAllByRole('button', { name: 'Copy to clipboard' })).toHaveLength(2);
  });
});

// Paths of same-origin GETs that change the viewer's session. The browser
// sends the session cookie on an image, media, or CSS request to these paths.
const sessionRotatePath = '/user/auth-tokens/rotate';
const orgSwitchPath = '/profile/switch-org/2';

// The math expression copies a dropped series label into the result notice in
// this shape. See pkg/expr/mathexp/exp.go addDropNotices.
function droppedSeriesNotice(label: string): string {
  return `1 items dropped from union(s): ["$A + $B": ($A: {job=${label}})]`;
}

const droppedLabelPayloads = [
  `![x](${sessionRotatePath})`,
  `![x](${orgSwitchPath})`,
  `<img src="${sessionRotatePath}">`,
  `<img src="${orgSwitchPath}">`,
  `<video src="${sessionRotatePath}"></video>`,
  `<audio src="${orgSwitchPath}"></audio>`,
  `<div style="background-image: url(${sessionRotatePath})"></div>`,
  `<div style="background-image: url(${orgSwitchPath})"></div>`,
];

// Tags and style urls the browser fetches without a click. Iframes are omitted:
// the sanitizer marks them credentialless, so they do not send the session cookie.
const autoFetchSelector = 'img, video, audio, source, track, image, object, embed, link';

function urlsTheBrowserFetches(container: HTMLElement): string[] {
  const urls: string[] = [];
  container.querySelectorAll<HTMLElement>(autoFetchSelector).forEach((element) => {
    for (const name of ['src', 'href', 'poster', 'data', 'srcset']) {
      const value = element.getAttribute(name);
      if (value) {
        urls.push(value);
      }
    }
  });
  container.querySelectorAll<HTMLElement>('[style]').forEach((element) => {
    const style = element.getAttribute('style') ?? '';
    for (const match of style.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi)) {
      urls.push(match[2]);
    }
  });
  return urls;
}

describe('StandardErrorsAndNoticesInspector notice markup', () => {
  it.each(droppedLabelPayloads)(
    'does not request a same-origin state-changing GET from dropped label %s',
    (label) => {
      const { container } = setup([
        frameWithNotices([{ severity: 'warning', text: droppedSeriesNotice(label) }]),
      ]);

      const fetched = urlsTheBrowserFetches(container).filter(
        (url) => url.includes(sessionRotatePath) || url.includes(orgSwitchPath)
      );
      expect(fetched).toEqual([]);
    }
  );
});
