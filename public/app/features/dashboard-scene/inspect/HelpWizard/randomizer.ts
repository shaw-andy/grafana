import { type DataFrameJSON, type Labels, FieldType } from '@grafana/data';

export function newLetterRandomizer(): (v: string) => string {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const charactersLength = upper.length;

  const history = new Map<string, string>();
  return (v: string) => {
    const old = history.get(v);
    if (old != null) {
      return old;
    }
    const r = [...v]
      .map((c) => {
        if (c !== c.toUpperCase()) {
          return lower.charAt(Math.floor(Math.random() * charactersLength));
        }
        if (c !== c.toLowerCase()) {
          return upper.charAt(Math.floor(Math.random() * charactersLength));
        }
        return c;
      })
      .join('');
    history.set(v, r);
    return r;
  };
}

export interface Randomize {
  names?: boolean;
  labels?: boolean;
  values?: boolean;
}

// Dataplane logs frames carry per-row labels as objects in a field with this name and type
const LOGS_LABELS_FIELD_NAME = 'labels';

function isLabels(v: unknown): v is Labels {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

function randomizeLabels(labels: Labels, rand: (v: string) => string): Labels {
  const result: Labels = {};
  for (const [key, value] of Object.entries(labels)) {
    result[rand(key)] = rand(String(value));
  }
  return result;
}

export function randomizeData(data: DataFrameJSON[], opts: Randomize): DataFrameJSON[] {
  if (!(opts.labels || opts.names || opts.values)) {
    return data;
  }

  const keepNames = new Set(['time', 'value', 'exemplar', 'traceid', 'id', 'uid', 'uuid', '__name__', 'le', 'name']);
  const rand = newLetterRandomizer();
  return data.map((s) => {
    let { schema, data } = s;
    if (schema && data) {
      if (opts.labels) {
        schema.fields.forEach((f, idx) => {
          if (f.labels) {
            f.labels = randomizeLabels(f.labels, rand);
          }
          if (f.type === FieldType.other && f.name === LOGS_LABELS_FIELD_NAME && data?.values[idx]) {
            data.values[idx] = data.values[idx].map((v) => (isLabels(v) ? randomizeLabels(v, rand) : v));
          }
        });
      }
      if (opts.names) {
        for (const f of schema.fields) {
          if (f.name?.length && !keepNames.has(f.name.toLowerCase())) {
            f.name = rand(f.name);
          }
        }
      }

      // Change values
      if (opts.values) {
        schema.fields.forEach((f, idx) => {
          if (f.type === FieldType.string && data) {
            const v = data.values[idx].map((v) => rand(String(v)));
            data.values[idx] = v;
          }
        });
      }
    }
    return { schema, data };
  });
}
