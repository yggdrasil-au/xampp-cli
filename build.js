// this scritpt is called by postinstall in package.json
// and will run every time pnpm install is run


// detect OS, if windows, run build-win, else build-linux
const { execSync } = require('child_process');
const os = require('os');
const platform = os.platform();

//add pre check for cargo installation
try {
    execSync('cargo --version', { stdio: 'ignore' });
} catch (error) {
    console.error('Cargo is not installed or not found in PATH. Please install Rust and Cargo to proceed with the build.');
    process.exit(1);
}

if (platform === 'win32') {
    execSync('pnpm run build-win', { stdio: 'inherit' });
}
else if (platform === 'linux') {
    execSync('pnpm run build-linux', { stdio: 'inherit' });
}
else {
    console.error('Unsupported OS for build script.');
    process.exit(1);
}
