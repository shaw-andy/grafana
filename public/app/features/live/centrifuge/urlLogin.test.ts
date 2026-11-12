import { of } from 'rxjs';

import { CentrifugeService } from './service';

const placeholderToken = 'placeholder-token';

describe('CentrifugeService URL login', () => {
  const OriginalWebSocket = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = OriginalWebSocket;
  });

  it('does not put the URL login value on the live websocket', () => {
    const opened: string[] = [];
    class RecordingSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSING = 2;
      static CLOSED = 3;
      readyState = 0;
      url: string;
      onopen: ((event: unknown) => void) | null = null;
      onerror: ((event: unknown) => void) | null = null;
      onclose: ((event: unknown) => void) | null = null;
      onmessage: ((event: unknown) => void) | null = null;
      constructor(url: string) {
        this.url = url;
        opened.push(url);
      }
      send(): void {}
      close(): void {
        this.readyState = 3;
      }
      addEventListener(): void {}
      removeEventListener(): void {}
    }
    globalThis.WebSocket = RecordingSocket as unknown as typeof WebSocket;

    const service = new CentrifugeService({
      grafanaAuthToken: placeholderToken,
      appUrl: 'http://grafana.example',
      namespace: '1',
      orgRole: 'Viewer',
      liveEnabled: true,
      dataStreamSubscriberReadiness: of(true),
    });

    try {
      expect(opened.length).toBeGreaterThan(0);
      for (const url of opened) {
        expect(url).not.toContain(placeholderToken);
        expect(url).not.toContain('auth_token');
      }
    } finally {
      service.centrifuge.disconnect();
    }
  });
});
