// Every steps line becomes a dataframe field in the viewer's browser.
export const MAX_STEPS_LINES = 100;

export const stepsLimitMessage = `Steps scenario supports at most ${MAX_STEPS_LINES} non-empty lines`;

/**
 * Returns the trimmed non-empty lines, or undefined as soon as more than maxLines are found.
 * Scans incrementally so oversized input is rejected without materializing every line.
 */
export function parseStepsLines(csvContent: string, maxLines = MAX_STEPS_LINES): string[] | undefined {
  const steps: string[] = [];
  let start = 0;
  while (start <= csvContent.length) {
    let end = csvContent.indexOf('\n', start);
    if (end === -1) {
      end = csvContent.length;
    }
    const line = csvContent.slice(start, end).trim();
    if (line.length) {
      if (steps.length >= maxLines) {
        return undefined;
      }
      steps.push(line);
    }
    start = end + 1;
  }
  return steps;
}
