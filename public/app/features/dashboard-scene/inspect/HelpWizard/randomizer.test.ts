import { dataFrameToJSON, FieldType, toDataFrame, type DataFrameJSON } from '@grafana/data';

import { newLetterRandomizer, randomizeData } from './randomizer';

describe('Randomizer', () => {
  it('should randomize letters', () => {
    const rand = newLetterRandomizer();
    const a = rand('Hello-World');
    const b = rand('Hello-World');
    expect(a).toEqual(b);
    expect(a.indexOf('-')).toBe(5);
    // expect(a).toEqual('x');
  });

  it('should keep numbers', () => {
    const rand = newLetterRandomizer();
    const a = rand('123-Abc');
    const b = rand('123-Abc');
    expect(a).toEqual(b);
    expect(a.startsWith('123-')).toBeTruthy();
  });

  it('redacts label names with one stable mapping when labels are enabled', () => {
    const seriesA = toDataFrame({
      name: 'http_requests_total',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
        {
          name: 'Value',
          type: FieldType.number,
          values: [11, 22, 33],
          labels: {
            acctowner: 'aliceperson',
            hostbox: 'webnode',
            exemplar: 'morningshift',
            __name__: 'metricname',
          },
        },
      ],
    });
    const seriesB = toDataFrame({
      name: 'http_requests_total',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
        {
          name: 'Value',
          type: FieldType.number,
          values: [44, 55, 66],
          labels: {
            acctowner: 'carolperson',
            hostbox: 'webnode',
          },
        },
      ],
    });
    const annotation = toDataFrame({
      name: 'annotation',
      fields: [
        {
          name: 'text',
          type: FieldType.string,
          values: ['note'],
          labels: {
            namespaceid: 'prodcluster',
            owner_id: 'patperson',
          },
        },
      ],
    });

    const [redactedA, redactedB, redactedAnnotation] = randomizeData(
      [dataFrameToJSON(seriesA), dataFrameToJSON(seriesB), dataFrameToJSON(annotation)],
      { labels: true }
    );

    const labelsA = redactedA.schema?.fields[1].labels ?? {};
    const labelsB = redactedB.schema?.fields[1].labels ?? {};
    const labelsAnnotation = redactedAnnotation.schema?.fields[0].labels ?? {};

    const acctowner = keyMatching(labelsA, /^[a-z]{9}$/);
    const hostbox = keyMatching(labelsA, /^[a-z]{7}$/);
    const exemplar = keyMatching(labelsA, /^[a-z]{8}$/);
    const metric = keyMatching(labelsA, /^__[a-z]{4}__$/);
    expect(keyMatching(labelsB, /^[a-z]{9}$/)).toBe(acctowner);
    expect(keyMatching(labelsB, /^[a-z]{7}$/)).toBe(hostbox);
    expect(acctowner).not.toBe('acctowner');
    expect(hostbox).not.toBe('hostbox');
    expect(exemplar).not.toBe('exemplar');
    expect(metric).not.toBe('__name__');
    expect(Object.keys(labelsA).sort()).toEqual([acctowner, exemplar, hostbox, metric].sort());

    expect(labelsA[acctowner]).toMatch(/^[a-z]{11}$/);
    expect(labelsA[acctowner]).not.toBe('aliceperson');
    expect(labelsB[acctowner]).toMatch(/^[a-z]{11}$/);
    expect(labelsB[acctowner]).not.toBe('carolperson');
    expect(labelsB[acctowner]).not.toBe(labelsA[acctowner]);
    expect(labelsA[hostbox]).toMatch(/^[a-z]{7}$/);
    expect(labelsA[hostbox]).not.toBe('webnode');
    expect(labelsB[hostbox]).toBe(labelsA[hostbox]);
    expect(labelsA[exemplar]).toMatch(/^[a-z]{12}$/);
    expect(labelsA[exemplar]).not.toBe('morningshift');
    expect(labelsA[metric]).toMatch(/^[a-z]{10}$/);
    expect(labelsA[metric]).not.toBe('metricname');

    const namespaceid = keyMatching(labelsAnnotation, /^[a-z]{11}$/);
    const ownerId = keyMatching(labelsAnnotation, /^[a-z]{5}_[a-z]{2}$/);
    expect(namespaceid).not.toBe('namespaceid');
    expect(ownerId).not.toBe('owner_id');
    expect(labelsAnnotation[namespaceid]).toMatch(/^[a-z]{11}$/);
    expect(labelsAnnotation[namespaceid]).not.toBe('prodcluster');
    expect(labelsAnnotation[ownerId]).toMatch(/^[a-z]{9}$/);
    expect(labelsAnnotation[ownerId]).not.toBe('patperson');

    expect(seriesA.fields[1].labels).toEqual({
      acctowner: 'aliceperson',
      hostbox: 'webnode',
      exemplar: 'morningshift',
      __name__: 'metricname',
    });
    expect(annotation.fields[0].labels).toEqual({
      namespaceid: 'prodcluster',
      owner_id: 'patperson',
    });
  });

  it('leaves label names unchanged when the labels option is off', () => {
    const frame = labeledFrame({
      acctowner: 'aliceperson',
      owner_id: 'patperson',
    });

    const [namedOnly] = randomizeData([frame], { names: true });
    expect(namedOnly.schema?.fields[1].labels).toEqual({
      acctowner: 'aliceperson',
      owner_id: 'patperson',
    });

    const [valuesOnly] = randomizeData([labeledFrame({ acctowner: 'aliceperson' })], { values: true });
    expect(valuesOnly.schema?.fields[1].labels).toEqual({ acctowner: 'aliceperson' });

    const [untouched] = randomizeData([labeledFrame({ namespaceid: 'prodcluster' })], {});
    expect(untouched.schema?.fields[1].labels).toEqual({ namespaceid: 'prodcluster' });
  });
});

function labeledFrame(labels: Record<string, string>): DataFrameJSON {
  return dataFrameToJSON(
    toDataFrame({
      name: 'series',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1] },
        { name: 'Value', type: FieldType.number, values: [1], labels },
      ],
    })
  );
}

function keyMatching(labels: Record<string, string>, pattern: RegExp): string {
  const keys = Object.keys(labels).filter((key) => pattern.test(key));
  expect(keys).toHaveLength(1);
  return keys[0];
}
