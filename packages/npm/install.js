'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const VERSION = '0.1.0';
const REPO = 'ioni-dev/mati';

function getTarget() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'darwin') {
    if (arch === 'arm64') return 'aarch64-apple-darwin';
    if (arch === 'x64') return 'x86_64-apple-darwin';
    throw new Error(`mati: unsupported macOS architecture: ${arch}`);
  }

  if (platform === 'linux') {
    if (arch === 'arm64') return 'aarch64-unknown-linux-musl';
    if (arch === 'x64') return 'x86_64-unknown-linux-musl';
    throw new Error(`mati: unsupported Linux architecture: ${arch}`);
  }

  if (platform === 'win32') {
    throw new Error(
      'mati is not supported on Windows.\n' +
      'Please use WSL2 (Windows Subsystem for Linux) to run mati.\n' +
      'See https://github.com/ioni-dev/mati for details.'
    );
  }

  throw new Error(`mati: unsupported platform: ${platform}`);
}

function download(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);

    function get(url) {
      https.get(url, (res) => {
        // Follow redirects (GitHub releases redirect to S3)
        if (res.statusCode === 301 || res.statusCode === 302) {
          const location = res.headers.location;
          if (!location) {
            reject(new Error(`mati: redirect with no Location header (HTTP ${res.statusCode})`));
            return;
          }
          res.resume();
          get(location);
          return;
        }

        if (res.statusCode !== 200) {
          reject(new Error(`mati: download failed with HTTP ${res.statusCode} from ${url}`));
          return;
        }

        res.pipe(file);
        file.on('finish', () => file.close(resolve));
        file.on('error', (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    }

    get(url);
  });
}

async function install() {
  let target;
  try {
    target = getTarget();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  const tarballName = `mati-${target}.tar.gz`;
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${tarballName}`;

  const binDir = path.join(__dirname, 'bin');
  const binaryPath = path.join(binDir, 'mati');
  const tmpTarball = path.join(os.tmpdir(), tarballName);

  // Ensure bin/ directory exists
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  console.log(`mati: downloading ${tarballName}...`);

  try {
    await download(downloadUrl, tmpTarball);
  } catch (err) {
    console.error(`mati: failed to download binary: ${err.message}`);
    console.error(`  URL: ${downloadUrl}`);
    process.exit(1);
  }

  console.log('mati: extracting binary...');

  try {
    // Extract only the `mati` binary from the tarball into bin/
    execSync(`tar -xzf ${tmpTarball} -C ${binDir} --strip-components=0 mati`, {
      stdio: 'inherit',
    });
  } catch {
    // Some tarballs nest the binary one level deep; try without --strip-components
    try {
      execSync(`tar -xzf ${tmpTarball} -C ${binDir}`, { stdio: 'inherit' });
    } catch (err2) {
      console.error(`mati: failed to extract tarball: ${err2.message}`);
      process.exit(1);
    }
  } finally {
    // Clean up temp tarball regardless of extraction result
    try { fs.unlinkSync(tmpTarball); } catch {}
  }

  if (!fs.existsSync(binaryPath)) {
    console.error(
      'mati: extraction succeeded but binary not found at expected path.\n' +
      `  Expected: ${binaryPath}\n` +
      '  The tarball layout may have changed. Please file an issue at https://github.com/ioni-dev/mati/issues'
    );
    process.exit(1);
  }

  fs.chmodSync(binaryPath, 0o755);
  console.log(`mati: installed successfully -> ${binaryPath}`);
}

install();
