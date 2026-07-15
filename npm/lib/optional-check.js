#!/usr/bin/env node

"use strict";

// Skip install in CI or whenDPNDON_SKIP_DOWNLOAD is set
if (process.env.CI || process.env.DPNDON_SKIP_DOWNLOAD) {
  process.exit(0);
}

// Only install on supported platforms
const { platform, arch } = process;
const supported = [
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
];
const key = `${platform}-${arch}`;

if (!supported.includes(key)) {
  console.log(
    `dpndon: platform ${key} is not prebuilt. You can build from source: https://github.com/dpndon/dpndon`
  );
  process.exit(0);
}
