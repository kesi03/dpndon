#!/usr/bin/env node

"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
const { chmodSync, existsSync, mkdirSync } = fs;
const { arch, platform } = process;

const REPO = "kesi03/dpndon";
const RELEASE_TAG = require("../package.json").version;

const BINARY_NAME = platform === "win32" ? "dpndon.exe" : "dpndon";

const PLATFORM_MAP = {
  linux: "linux",
  darwin: "darwin",
  win32: "windows",
};

const ARCH_MAP = {
  x64: "amd64",
  arm64: "arm64",
};

function getDownloadURL() {
  const os = PLATFORM_MAP[platform];
  const goArch = ARCH_MAP[arch];

  if (!os || !goArch) {
    throw new Error(
      `Unsupported platform: ${platform}-${arch}. Build from source: https://github.com/${REPO}`
    );
  }

  const archiveExt = os === "windows" ? "zip" : "tar.gz";
  const fileName = `dpndon-v${RELEASE_TAG}-${os}-${goArch}.${archiveExt}`;
  return `https://github.com/${REPO}/releases/download/v${RELEASE_TAG}/${fileName}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https") ? https : http;
    mod
      .get(url, { headers: { "User-Agent": "dpndon-npm" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return download(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function extractTarGz(buffer, destDir) {
  const { execSync } = require("child_process");
  const tmpFile = path.join(destDir, "_dpndon_tmp.tar.gz");
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(`tar -xzf "${tmpFile}" -C "${destDir}" dpndon`, { stdio: "ignore" });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  const { execSync } = require("child_process");
  const tmpFile = path.join(destDir, "_dpndon_tmp.zip");
  fs.writeFileSync(tmpFile, buffer);
  try {
    execSync(`powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}' -Force"`, {
      stdio: "ignore",
    });
    // Rename if needed
    const extracted = path.join(destDir, "dpndon.exe");
    if (!existsSync(extracted)) {
      // Try from nested dpndon/ directory
      const nested = path.join(destDir, "dpndon", "dpndon.exe");
      if (existsSync(nested)) {
        fs.copyFileSync(nested, extracted);
        fs.rmSync(path.join(destDir, "dpndon"), { recursive: true, force: true });
      }
    }
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function main() {
  const binDir = path.join(__dirname, "..", "bin");
  const binPath = path.join(binDir, BINARY_NAME);

  // Skip if binary already exists (e.g. from a previous install)
  if (existsSync(binPath)) {
    try {
      execSync(`"${binPath}" version`, { stdio: "ignore" });
      return;
    } catch {
      // Binary is broken, re-download
    }
  }

  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: true });
  }

  const url = getDownloadURL();
  console.log(`dpndon: downloading ${url}`);

  try {
    const buffer = await download(url);
    if (platform === "win32") {
      extractZip(buffer, binDir);
    } else {
      extractTarGz(buffer, binDir);
    }
    chmodSync(binPath, 0o755);
    console.log("dpndon: installation complete");
  } catch (err) {
    console.error(`dpndon: failed to download binary: ${err.message}`);
    console.error(
      `dpndon: you can build from source: https://github.com/${REPO}#install`
    );
    process.exit(1);
  }
}

main();
