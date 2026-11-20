import { useState } from 'react';

import { Alert, CodeEditor } from '@grafana/ui';

import { type EditorProps } from '../QueryEditor';
import { TestDataQueryType } from '../dataquery';
import { parseStepsLines, stepsLimitMessage } from '../steps';

export const CSVContentEditor = ({ onChange, query }: EditorProps) => {
  const [error, setError] = useState<string>();

  const onSaveCSV = (csvContent: string) => {
    if (query.scenarioId === TestDataQueryType.Steps && !parseStepsLines(csvContent)) {
      setError(stepsLimitMessage);
      return;
    }
    setError(undefined);
    onChange({ ...query, csvContent });
  };

  return (
    <>
      {error && <Alert title={error} severity="error" />}
      <CodeEditor
        height={300}
        language="csv"
        value={query.csvContent ?? ''}
        onBlur={onSaveCSV}
        onSave={onSaveCSV}
        showMiniMap={false}
        showLineNumbers={true}
      />
    </>
  );
};
