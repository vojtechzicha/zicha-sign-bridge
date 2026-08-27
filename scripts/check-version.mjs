#!/usr/bin/env node
// The version lives in four places. This asserts they agree.
//
//   scripts/check-version.mjs 1.2.3      # against a specific version
//   scripts/check-version.mjs            # just that the four match each other
//
// Why it matters more than tidiness: the host reports `hostVersion` in its
// `hello` reply, and the page compares that against the minimum the EXTENSION
// declares in order to decide whether to tell someone their helper is out of
// date (see the app's BridgeReadiness → 'helper-outdated'). A release where the
// numbers drift ships a helper that misreports itself, and the symptom is an
// install prompt that will not go away no matter what the user installs.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const want = process.argv[2]?.replace(/^v/, '');

const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

const sources = {
  'extension/manifest.json': JSON.parse(read('extension/manifest.json')).version,
  'extension/package.json': JSON.parse(read('extension/package.json')).version,
  'agent/Sources/SignBridgeCore/Protocol.swift':
    /hostVersion\s*=\s*"([^"]+)"/.exec(read('agent/Sources/SignBridgeCore/Protocol.swift'))?.[1],
};

let bad = false;
const fail = (msg) => {
  console.error(`version  ERROR  ${msg}`);
  bad = true;
};

for (const [file, found] of Object.entries(sources)) {
  if (!found) fail(`could not find a version in ${file}`);
}

const distinct = [...new Set(Object.values(sources).filter(Boolean))];
if (distinct.length > 1) {
  fail(`the sources disagree: ${JSON.stringify(sources, null, 2)}`);
}

if (want) {
  // Chrome Web Store versions are 1–4 dot-separated integers and nothing else:
  // no pre-release suffix, no build metadata. A tag like v1.2.3-rc1 builds a
  // pkg happily and then cannot be uploaded to the store, which is a discovery
  // best made here rather than at the end of a release.
  if (!/^\d+(\.\d+){0,3}$/.test(want)) {
    fail(`"${want}" is not a version the Chrome Web Store accepts (1-4 integers, no suffix)`);
  }
  for (const [file, found] of Object.entries(sources)) {
    if (found && found !== want) fail(`${file} says ${found}, the release says ${want}`);
  }
}

if (bad) {
  console.error('version  Bump them together — see docs/RELEASING.md.');
  process.exit(1);
}
console.log(`✓ version ${distinct[0]} is consistent across ${Object.keys(sources).length} files`);
