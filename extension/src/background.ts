// The extension is a relay and a gate, and deliberately nothing else.
//
// It performs no cryptography, stores no secret, and interprets no payload. Its
// entire job is to be the thing the browser will only let approved origins talk
// to, and to hand what they say to the native host along with who said it.
// Every decision that matters — whether an origin is paired, whether a
// signature happens, what the person is shown before it does — is taken by the
// host, where the PIN is typed.
//
// Pages connect with a long-lived Port rather than sendMessage. That is not a
// style choice: pairing has to put a code on the page WHILE the host's window
// is on screen, and a request/response call cannot deliver anything until the
// request has finished — by which time the window it was to be compared with
// is gone.

/** Native messaging host id, matching packaging/native-messaging/*.json. */
const HOST = 'dev.zicha.signbridge';

/** The oldest host this extension knows how to talk to. */
const REQUIRED_HOST_VERSION = '0.1.0';

/** Where the page is sent when the host is missing or too old. */
const INSTALL_URL = 'https://github.com/vojtechzicha/zicha-sign-bridge/releases/latest';

interface Frame {
  id: string;
  ok: boolean;
  /** Present on news, absent on the answer. See protocol/protocol.md. */
  event?: string;
  code?: string;
  message?: string;
  hostVersion?: string;
  [key: string]: unknown;
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

chrome.runtime.onConnectExternal.addListener((page) => {
  // The browser guarantees this against externally_connectable, and page
  // script cannot set it. Passing it on is the extension's whole contribution
  // to the security model.
  const origin = page.sender?.origin ?? '';
  if (!origin) {
    page.disconnect();
    return;
  }

  page.onMessage.addListener((request: { id?: string; type?: string }) => {
    const id = request?.id ?? '0';

    let host: chrome.runtime.Port;
    try {
      host = chrome.runtime.connectNative(HOST);
    } catch {
      page.postMessage({ id, ok: false, code: 'helper_missing', installUrl: INSTALL_URL });
      return;
    }

    let answered = false;

    host.onMessage.addListener((frame: Frame) => {
      // News is forwarded and the exchange stays open; the answer closes it.
      if (frame.event) {
        page.postMessage(frame);
        return;
      }

      // The version gate lives here, not in the page: the extension and the
      // host ship together and know what they need of each other, while the
      // page only needs telling which of the two to install.
      if (request?.type === 'hello' && frame.ok && frame.hostVersion) {
        if (!atLeast(frame.hostVersion, REQUIRED_HOST_VERSION)) {
          answered = true;
          page.postMessage({
            id,
            ok: false,
            code: 'helper_outdated',
            have: frame.hostVersion,
            need: REQUIRED_HOST_VERSION,
            installUrl: INSTALL_URL,
          });
          host.disconnect();
          return;
        }
      }

      answered = true;
      page.postMessage(frame);
      // One host process per request. Chrome starts one per native port, and a
      // port kept open would keep that process — and its view of the card —
      // alive for as long as the tab.
      host.disconnect();
    });

    host.onDisconnect.addListener(() => {
      if (answered) return;
      // connectNative resolves lazily: a missing or unlaunchable host shows up
      // here rather than as a throw above.
      const error = chrome.runtime.lastError?.message ?? '';
      page.postMessage({
        id,
        ok: false,
        code: 'helper_missing',
        message: error || 'The Sign Bridge helper is not installed.',
        installUrl: INSTALL_URL,
      });
    });

    host.postMessage({ ...request, origin });
  });
});
