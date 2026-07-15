#!/usr/bin/env node

"use strict";

const { execSync, spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const BINARY = path.join(__dirname, "dpndon");
const BINARY_EXE = path.join(__dirname, "dpndon.exe");
const binary = fs.existsSync(BINARY_EXE) ? BINARY_EXE : BINARY;

const args = process.argv.slice(2);

// dpndon start — use pm2
if (args[0] === "start") {
  const pm2 = require("pm2");
  const port = args.find((a) => a.startsWith("-p")) || "8080";
  const portNum = args.includes("-p") ? args[args.indexOf("-p") + 1] : "8080";

  pm2.connect((err) => {
    if (err) {
      console.error("Failed to connect to pm2:", err);
      process.exit(1);
    }

    pm2.start(
      {
        name: "dpndon",
        script: binary,
        args: ["serve", "-t", "sse", "-p", portNum],
        autorestart: true,
      },
      (err) => {
        if (err) {
          console.error("Failed to start dpndon:", err);
          pm2.disconnect();
          process.exit(1);
        }
        console.log(`dpndon started on port ${portNum}`);
        pm2.disconnect();
      }
    );
  });
}
// dpndon stop — use pm2
else if (args[0] === "stop") {
  const pm2 = require("pm2");
  pm2.connect((err) => {
    if (err) {
      console.error("Failed to connect to pm2:", err);
      process.exit(1);
    }
    pm2.stop("dpndon", (err) => {
      if (err) {
        console.error("Failed to stop dpndon:", err);
        pm2.disconnect();
        process.exit(1);
      }
      console.log("dpndon stopped");
      pm2.disconnect();
    });
  });
}
// dpndon status — use pm2
else if (args[0] === "status") {
  const pm2 = require("pm2");
  pm2.connect((err) => {
    if (err) {
      console.error("Failed to connect to pm2:", err);
      process.exit(1);
    }
    pm2.list((err, list) => {
      if (err) {
        console.error("Failed to list processes:", err);
        pm2.disconnect();
        process.exit(1);
      }
      const dpndon = list.find((p) => p.name === "dpndon");
      if (dpndon) {
        console.log(`dpndon: ${dpndon.pm2_env.status} (pid: ${dpndon.pid})`);
      } else {
        console.log("dpndon: not running");
      }
      pm2.disconnect();
    });
  });
}
// dpndon logs — use pm2
else if (args[0] === "logs") {
  const pm2 = require("pm2");
  pm2.connect((err) => {
    if (err) {
      console.error("Failed to connect to pm2:", err);
      process.exit(1);
    }
    pm2.launchDaemon({ pm2Home: path.join(require("os").homedir(), ".pm2") }, () => {
      pm2.streamLogs("dpndon", 0);
    });
  });
}
// Everything else — pass through to binary
else {
  const child = spawn(binary, args, { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code));
}
