import { render, screen } from '@testing-library/react';

import { expectSafeConsoleHref, hostileRegions } from '../../utils/consoleLinkSafety.test-utils';

import { ThrottlingErrorMessage } from './ThrottlingErrorMessage';

describe('ThrottlingErrorMessage', () => {
  it('links a single-label region to the service quotas console', () => {
    render(<ThrottlingErrorMessage region="us-east-1" />);

    expectSafeConsoleHref(screen.getByRole('link', { name: /AWS Service Quotas console/ }).getAttribute('href'));
    expect(screen.getByRole('link', { name: /AWS Service Quotas console/ }).getAttribute('href')).toContain(
      'https://us-east-1.console.aws.amazon.com/servicequotas/home?region=us-east-1'
    );
  });

  it.each(hostileRegions)('does not let the region choose the quotas console host (%s)', (region) => {
    render(<ThrottlingErrorMessage region={region} />);

    expectSafeConsoleHref(screen.getByRole('link', { name: /AWS Service Quotas console/ }).getAttribute('href'));
  });
});
