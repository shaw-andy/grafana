import { isArray } from 'lodash';
import { useState } from 'react';

import { dataFrameToJSON, toDataFrame, toDataFrameDTO } from '@grafana/data';
import { toDataQueryResponse } from '@grafana/runtime';
import { Alert, CodeEditor } from '@grafana/ui';

import { type EditorProps } from '../QueryEditor';
import {
  assertQueryResultsWithinLimits,
  assertRawFramesWithinLimits,
  isJSONObject,
  isRawFrameContentTooLarge,
  MAX_RAW_FRAME_CONTENT_BYTES,
  parseRawFrameContent,
  RawFrameLimitError,
} from '../rawFrameLimits';

export const RawFrameEditor = ({ onChange, query }: EditorProps) => {
  const [error, setError] = useState<string>();
  const [warning, setWarning] = useState<string>();

  const onSaveFrames = (rawFrameContent: string) => {
    try {
      const json = parseRawFrameContent(rawFrameContent);
      if (isArray(json)) {
        assertRawFramesWithinLimits(json);
        setError(undefined);
        setWarning(undefined);
        onChange({ ...query, rawFrameContent });
        return;
      }

      let data = undefined;
      const body = isJSONObject(json) ? json : {};

      // Copy paste from panel json
      if (isArray(body.series) && body.state) {
        data = assertRawFramesWithinLimits(body.series).map((v) => toDataFrameDTO(toDataFrame(v)));
      } else if (body.results) {
        // Chek if it is a copy of the raw resuls
        const { results } = body;
        assertQueryResultsWithinLimits(results);
        const v = toDataQueryResponse({ data: { results } });
        if (v.data?.length && !v.error) {
          data = v.data.map((f) => dataFrameToJSON(f));
        }
      }

      if (data) {
        const converted = JSON.stringify(data, null, 2);
        if (isRawFrameContentTooLarge(converted)) {
          throw new RawFrameLimitError(`Converted frames are larger than ${MAX_RAW_FRAME_CONTENT_BYTES} bytes`);
        }
        console.log('Original', json);
        console.log('Save', data);
        setError(undefined);
        setWarning('Converted to direct frame result');
        onChange({ ...query, rawFrameContent: converted });
        return;
      }

      setError('Unable to read dataframes in text');
    } catch (e) {
      if (e instanceof RawFrameLimitError) {
        setError(e.message);
        setWarning(undefined);
        return;
      }
      console.log('Error parsing json', e);
      setError('Enter JSON array of data frames (or raw query results body)');
      setWarning(undefined);
    }
  };

  return (
    <>
      {error && <Alert title={error} severity="error" />}
      {warning && <Alert title={warning} severity="warning" />}
      <CodeEditor
        height={300}
        language="json"
        value={query.rawFrameContent ?? '[]'}
        onBlur={onSaveFrames}
        onSave={onSaveFrames}
        showMiniMap={true}
        showLineNumbers={true}
      />
    </>
  );
};
