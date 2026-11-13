import { render, screen } from '@testing-library/react';

import { ResourceDimensionMode } from '@grafana/schema';

import { defaultStyleConfig, type StyleConfigState } from '../style/types';

import { MarkersLegend } from './MarkersLegend';

function styleWithSymbol(symbol: string): StyleConfigState {
  return {
    config: { ...defaultStyleConfig, symbol: { mode: ResourceDimensionMode.Fixed, fixed: symbol } },
    base: { color: '#ff0000', opacity: 1 },
    maker: jest.fn(),
  };
}

describe('MarkersLegend', () => {
  beforeEach(() => {
    window.__grafana_build_path__ = 'public/build/';
  });

  it('shows the fixed symbol from the build folder', () => {
    render(<MarkersLegend layerName="Markers" styleConfig={styleWithSymbol('img/icons/marker/star.svg')} />);

    expect(screen.getByTitle('Symbol').closest('svg')).toHaveAttribute(
      'id',
      new URL('public/build/img/icons/marker/star.svg', document.baseURI).href
    );
  });

  it('does not show a symbol that resolves outside the public folder of this server', () => {
    render(<MarkersLegend layerName="Markers" styleConfig={styleWithSymbol('../../logout?.svg')} />);

    expect(screen.getByText('Markers')).toBeInTheDocument();
    expect(screen.queryByTitle('Symbol')).not.toBeInTheDocument();
  });
});
