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

function getArchiveName(version, os, goArch) {
  const archiveExt = os === "windows" ? "zip" : "tar.gz";
  return `dpndon-v${version}-${os}-${goArch}.${archiveExt}`;
}

function getDownloadURL(version) {
  const os = PLATFORM_MAP[platform];
  const goArch = ARCH_MAP[arch];

  if (!os || !goArch) {
    throw new Error(
      `Unsupported platform: ${platform}-${arch}. Build from source: https://github.com/${REPO}`
    );
  }

  const fileName = getArchiveName(version, os, goArch);
  return `https://github.com/${REPO}/releases/download/v${version}/${fileName}`;
}

function decrementVersion(version) {
  const parts = version.split(".").map(Number);
  if (parts.length !== 3) return null;

  if (parts[2] > 0) {
    parts[2]--;
  } else if (parts[1] > 0) {
    parts[1]--;
    parts[2] = 9;
  } else if (parts[0] > 0) {
    parts[0]--;
    parts[1] = 9;
    parts[2] = 9;
  } else {
    return null;
  }

  return parts.join(".");
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

async function tryDownload(version) {
  const url = getDownloadURL(version);
  console.log(`dpndon: downloading ${url}`);

  const buffer = await download(url);
  const binDir = path.join(__dirname, "..", "bin");
  if (platform === "win32") {
    extractZip(buffer, binDir);
  } else {
    extractTarGz(buffer, binDir);
  }
  chmodSync(path.join(binDir, BINARY_NAME), 0o755);
  console.log("dpndon: installation complete");
}

async function main() {
  const binDir = path.join(__dirname, "..", "bin");
  const binPath = path.join(binDir, BINARY_NAME);

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

  // Try current version, then decrement until we find an existing release
  let version = RELEASE_TAG;
  console.log(`dpndon: attempting to download version ${version}`);
  let lastErr;
  while (version) {
    try {
      await tryDownload(version);
      return;
    } catch (err) {
      lastErr = err;
      console.warn(`dpndon: v${version} not available, trying previous version...`);
      version = decrementVersion(version);
    }
  }

  console.error(`dpndon: failed to download binary: ${lastErr.message}`);
  console.error(
    `dpndon: you can build from source: https://github.com/${REPO}#install`
  );
  process.exit(1);
}

main();
