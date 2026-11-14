function noop(): void {}

export function getLogger(): {
  logWarning: () => void;
  logError: () => void;
  logInfo: () => void;
} {
  return {
    logWarning: noop,
    logError: noop,
    logInfo: noop,
  };
}
