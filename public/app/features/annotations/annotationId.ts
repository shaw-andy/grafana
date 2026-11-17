// Annotation ids end up as a URL path segment, and annotation frames can come from any
// data source. Only accept what the annotation APIs issue: a positive decimal id from the
// legacy API, or a resource name made of letters, digits, `-` and `_`. Dots, slashes and
// percent signs are rejected so the id can never act as a dot-segment or an encoded one.
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,252}$/;

export function isAnnotationId(id: unknown): id is string | number {
  if (typeof id === 'number') {
    return Number.isSafeInteger(id) && id > 0;
  }
  return typeof id === 'string' && NAME_PATTERN.test(id);
}

export function annotationIdPathSegment(id: unknown): string {
  if (!isAnnotationId(id)) {
    throw new Error('Invalid annotation id');
  }
  return encodeURIComponent(String(id));
}
