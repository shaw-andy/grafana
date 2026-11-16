import { render, screen } from '@testing-library/react';

import { RenderUserContentAsHTML } from './RenderUserContentAsHTML';

describe('RenderUserContentAsHTML', () => {
  it('does not insert a same-origin CSS url', () => {
    const { container } = render(
      <RenderUserContentAsHTML content='<div style="background-image:url(/logout)"></div>' />
    );

    expect(container.innerHTML).not.toMatch(/url\s*\(/i);
    expect(container.innerHTML).not.toContain('/logout');
  });

  it('should render html content', () => {
    render(<RenderUserContentAsHTML content='<a href="#">sample content</a>' />);
    expect(screen.getByRole('link', { name: /sample content/ })).toBeInTheDocument();
  });
  it('should render a raw string content', () => {
    render(<RenderUserContentAsHTML content="sample content" />);
    expect(screen.getByText(/sample content/)).toBeInTheDocument();
  });
});
