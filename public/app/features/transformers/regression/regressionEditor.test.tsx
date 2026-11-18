import { fireEvent, render, screen } from '@testing-library/react';

import { FieldType, toDataFrame } from '@grafana/data';

import { ModelType } from './regression';
import { RegressionTransformerEditor } from './regressionEditor';

describe('FieldToConfigMappingEditor', () => {
  it('Should try to set the first time field as X and first number field as Y', async () => {
    const onChangeMock = jest.fn();

    const df = toDataFrame({
      name: 'data',
      refId: 'A',
      fields: [
        { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
        { name: 'not this', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
        { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        { name: 'not this either', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
      ],
    });

    render(<RegressionTransformerEditor input={[df]} onChange={onChangeMock} options={{}} />);

    expect(onChangeMock).toBeCalledTimes(1);
    expect(onChangeMock).toBeCalledWith({ xFieldName: 'time', yFieldName: 'value' });
  });

  it('Should set the first field as X and the second as Y if there are no time fields', async () => {
    const onChangeMock = jest.fn();

    const df = toDataFrame({
      name: 'data',
      refId: 'A',
      fields: [
        { name: 'not this', type: FieldType.string, values: [0, 1, 2, 3, 4, 5] },
        { name: 'foo', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        { name: 'bar', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        { name: 'not this either', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
      ],
    });

    render(<RegressionTransformerEditor input={[df]} onChange={onChangeMock} options={{}} />);

    expect(onChangeMock).toBeCalledTimes(1);
    expect(onChangeMock).toBeCalledWith({ xFieldName: 'foo', yFieldName: 'bar' });
  });

  it('should display degree if the model is polynomial', async () => {
    const onChangeMock = jest.fn();

    const df = toDataFrame({
      name: 'data',
      refId: 'A',
      fields: [
        { name: 'foo', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        { name: 'bar', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
      ],
    });

    render(
      <RegressionTransformerEditor input={[df]} onChange={onChangeMock} options={{ modelType: ModelType.polynomial }} />
    );

    expect(await screen.findByText('Degree')).toBeInTheDocument();
  });

  it('should not display degree if the model is linear', async () => {
    const onChangeMock = jest.fn();

    const df = toDataFrame({
      name: 'data',
      refId: 'A',
      fields: [
        { name: 'foo', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        { name: 'bar', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
      ],
    });

    render(
      <RegressionTransformerEditor input={[df]} onChange={onChangeMock} options={{ modelType: ModelType.linear }} />
    );

    expect(await screen.queryByText('Degree')).not.toBeInTheDocument();
  });
});

describe('Trendline predicted points input', () => {
  const inputFrame = toDataFrame({
    name: 'data',
    refId: 'A',
    fields: [
      { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
      { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
    ],
  });

  function renderEditor() {
    const onChange = jest.fn();
    render(
      <RegressionTransformerEditor
        input={[inputFrame]}
        onChange={onChange}
        options={{ modelType: ModelType.linear, xFieldName: 'time', yFieldName: 'value', predictionCount: 100 }}
      />
    );
    return { onChange, input: screen.getByRole('spinbutton') };
  }

  function commit(input: HTMLElement, value: string) {
    fireEvent.change(input, { target: { value } });
    fireEvent.blur(input);
  }

  function savedCounts(onChange: jest.Mock) {
    return onChange.mock.calls.map((call) => call[0].predictionCount as number | undefined);
  }

  it('does not save an uncapped predicted point count', () => {
    const { onChange, input } = renderEditor();

    commit(input, '100001');

    expect(Number((input as HTMLInputElement).value)).toBeGreaterThan(0);
    expect(Number((input as HTMLInputElement).value)).toBeLessThanOrEqual(10_000);
    for (const count of savedCounts(onChange)) {
      expect(count === undefined || (Number.isFinite(count) && count > 0 && count <= 10_000)).toBe(true);
    }
  });

  it.each([
    ['zero', '0'],
    ['a negative count', '-8'],
  ])('does not save %s as the predicted point count', (_label, value) => {
    const { onChange, input } = renderEditor();

    commit(input, value);

    const displayed = (input as HTMLInputElement).value;
    expect(displayed === '' || Number(displayed) > 0).toBe(true);
    for (const count of savedCounts(onChange)) {
      expect(count === undefined || (Number.isFinite(count) && count > 0 && count <= 10_000)).toBe(true);
    }
  });
});
