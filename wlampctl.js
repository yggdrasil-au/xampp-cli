#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const isWin = os.platform() === 'win32';
let binaryPath;

if (isWin) {
    // Windows: Look for the binary in the local build directory
    binaryPath = path.join(
        __dirname,
        'source',
        'xampp-build',
        'Built',
        'installed-xampp',
        'wlampctl.exe'
    );
} else {
    // Linux: Look for the binary in the standard /opt/lampp location
    binaryPath = '/opt/lampp/wlampctl';
}

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
    console.error(`\x1b[31m[wlampctl] ERROR: Binary not found at:\x1b[0m`);
    console.error(`  ${binaryPath}`);
    if (isWin) {
        console.error(`\nPlease run "pnpm build" to compile the binary.`);
    } else {
        console.error(`\nPlease ensure the Linux version is installed in /opt/lampp.`);
    }
    process.exit(1);
}

// Spawn the binary with arguments
const child = spawn(binaryPath, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env
});

child.on('close', (code) => {
    process.exit(code);
});