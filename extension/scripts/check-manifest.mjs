// Checks the extension manifest against the things that are true elsewhere.
//
// The extension id is derived from the pinned key and then repeated in the
// native host manifest, in the web app, and in any policy install. Nothing
// enforces that they agree, and when they stop agreeing the symptom is a
// silence — the page decides the extension is not installed. So: derive the id
// here, and assert every copy of it.

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');

let checks = 0;
const failures = [];
const ok = (condition, message) => {
  checks += 1;
  if (!condition) failures.push(message);
};

const manifest = JSON.parse(readFileSync(join(here, '..', 'manifest.json'), 'utf8'));

/** Chrome's id: SHA-256 of the DER public key, first 16 bytes, each nibble mapped onto a–p. */
function extensionId(base64Key) {
  const digest = createHash('sha256').update(Buffer.from(base64Key, 'base64')).digest();
  return [...digest.subarray(0, 16)]
    .map((b) => String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 0xf)))
    .join('');
}

ok(manifest.manifest_version === 3, 'the manifest is MV3');
ok(typeof manifest.key === 'string' && manifest.key.length > 100, 'the extension key is pinned');

const id = extensionId(manifest.key);

// externally_connectable is the browser-enforced half of the security model.
// A wildcard here would hand the token to any page that asked.
const matches = manifest.externally_connectable?.matches ?? [];
ok(matches.length > 0, 'externally_connectable lists the origins allowed to connect');
ok(
  !matches.some((m) => m === '<all_urls>' || m.startsWith('*://*/')),
  'and no pattern opens it to every site'
);
ok(
  matches.every((m) => m.startsWith('https://') || m.startsWith('http://localhost') || m.startsWith('http://127.0.0.1')),
  'and every non-loopback origin is https'
);

ok(
  (manifest.permissions ?? []).includes('nativeMessaging'),
  'the extension may talk to the native host'
);
// Anything beyond nativeMessaging would be a capability nobody asked for, on
// an extension that pages are invited to trust with a signing key.
ok(
  (manifest.permissions ?? []).length === 1,
  'and asks for no other permission'
);
ok(!manifest.host_permissions, 'and no host permissions at all');

// Every native host manifest must name exactly this extension and nothing else.
const packaging = join(repo, 'packaging', 'native-messaging');
for (const file of readdirSync(packaging).filter((f) => f.endsWith('.json'))) {
  const host = JSON.parse(readFileSync(join(packaging, file), 'utf8'));
  ok(
    JSON.stringify(host.allowed_origins) === JSON.stringify([`chrome-extension://${id}/`]),
    `${file} allows this extension (${id}) and only this extension`
  );
  ok(host.type === 'stdio', `${file} uses stdio`);
}

if (failures.length) {
  console.error(`\n✗ ${failures.length} of ${checks} manifest checks failed:\n`);
  for (const failure of failures) console.error(`  • ${failure}`);
  process.exit(1);
}
console.log(`✓ ${checks} manifest checks passed (extension id ${id})`);
