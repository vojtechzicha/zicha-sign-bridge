// The extension is a relay and a gate, and deliberately nothing else.
//
// It performs no cryptography, stores no secret, and interprets no payload. Its
// entire job is to be the thing the browser will only let approved origins talk
// to, and to hand what they say to the native host along with who said it.
// Every decision that matters — whether an origin is paired, whether a
// signature happens, what the person is shown before it does — is taken by the
// host, where the PIN is typed.
//
// That split is why this file has no tests worth writing and the host has many.

/** Native messaging host id, matching packaging/*.json. */
const HOST = 'dev.zicha.signbridge';

/** The oldest host this extension knows how to talk to. */
const REQUIRED_HOST_VERSION = '0.1.0';

/** Where the page is sent when the host is missing or too old. */
const INSTALL_URL = 'https://github.com/vojtechzicha/zicha-sign-bridge/releases/latest';

interface HostResponse {
  id: string;
  ok: boolean;
  code?: string;
  message?: string;
  hostVersion?: string;
  [key: string]: unknown;
}

/**
 * One native-messaging exchange.
 *
 * A fresh port per request rather than a long-lived one. Chrome starts a host
 * process per port, and a port kept open would keep that process — and its
 * PKCS#11 session — alive for as long as the tab, which is exactly the lifetime
 * the design does not want a card session to have.
 *
 * `pair` is the one request that answers twice (the code, then the outcome), so
 * the caller says how many frames to expect.
 */
function callHost(request: unknown, frames = 1): Promise<HostResponse[]> {
  return new Promise((resolve, reject) => {
    let port: chrome.runtime.Port;
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      reject(new Error('helper-missing'));
      return;
    }

    const received: HostResponse[] = [];
    let settled = false;

    port.onMessage.addListener((message: HostResponse) => {
      received.push(message);
      // A failure ends the exchange whatever was expected — a refused pairing
      // has no second frame to wait for.
      if (received.length >= frames || message.ok === false) {
        settled = true;
        port.disconnect();
        resolve(received);
      }
    });

    port.onDisconnect.addListener(() => {
      if (settled) return;
      // connectNative resolves lazily: a missing or unlaunchable host shows up
      // here rather than as a throw above.
      const error = chrome.runtime.lastError?.message ?? '';
      if (received.length) {
        resolve(received);
      } else {
        reject(new Error(error.includes('not found') ? 'helper-missing' : error || 'helper-missing'));
      }
    });

    port.postMessage(request);
  });
}

/** Semantic-ish comparison, enough for "is the host at least this old". */
function atLeast(version: string, required: string): boolean {
  const a = version.split('.').map(Number);
  const b = required.split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const left = a[i] ?? 0;
    const right = b[i] ?? 0;
    if (left !== right) return left > right;
  }
  return true;
}

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
  // The browser guarantees this against externally_connectable; it cannot be
  // set by the page. Passing it on is the extension's whole contribution to
  // the security model.
  const origin = sender.origin ?? '';
  if (!origin) {
    sendResponse({ id: request?.id ?? '0', ok: false, code: 'bad_request', message: 'No origin.' });
    return false;
  }

  const frames = request?.type === 'pair' ? 2 : 1;

  callHost({ ...request, origin }, frames).then(
    (responses) => {
      const last = responses[responses.length - 1];
      // The version gate lives here, not in the page: the extension and the
      // host ship together and know what they need of each other, while the
      // page only needs to be told which of the two to install.
      if (request?.type === 'hello' && last?.ok && last.hostVersion) {
        if (!atLeast(last.hostVersion, REQUIRED_HOST_VERSION)) {
          sendResponse({
            id: request.id,
            ok: false,
            code: 'helper_outdated',
            have: last.hostVersion,
            need: REQUIRED_HOST_VERSION,
            installUrl: INSTALL_URL,
          });
          return;
        }
      }
      // `pair` needs both frames: the code has to reach the page while the
      // person is still looking at the host's window.
      sendResponse(frames > 1 ? { ...last, frames: responses } : last);
    },
    (error: Error) => {
      sendResponse({
        id: request?.id ?? '0',
        ok: false,
        code: error.message === 'helper-missing' ? 'helper_missing' : 'host_error',
        message: error.message,
        installUrl: INSTALL_URL,
      });
    }
  );

  // Keeps the message channel open for the async sendResponse above.
  return true;
});
