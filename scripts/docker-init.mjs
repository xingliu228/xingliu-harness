#!/usr/bin/env node
// Initialize only the dsh-passwords gateway state. dsh is managed separately.
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function nonEmpty(value, fallback) {
  return (value ?? '').trim() || fallback;
}

function envValue(contents, name) {
  for (const line of contents.split(/\r?\n/)) {
    const match = new RegExp(`^\\s*${name}\\s*=\\s*(.*?)\\s*$`).exec(line);
    if (match && !line.trimStart().startsWith('#')) {
      return match[1].replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '').trim();
    }
  }
  return '';
}

function hasEnvKey(contents, name) {
  return contents.split(/\r?\n/).some((line) =>
    new RegExp(`^\\s*${name}\\s*=`).test(line) && !line.trimStart().startsWith('#'),
  );
}

function secureFile(file) {
  if (process.platform !== 'win32') chmodSync(file, 0o600);
}

function appendMissingEnv(file, values) {
  const raw = readFileSync(file, 'utf8');
  const missing = Object.entries(values)
    .filter(([name]) => !hasEnvKey(raw, name))
    .map(([name, value]) => `${name}=${value}`);
  if (missing.length > 0) {
    writeFileSync(file, `${raw.replace(/\s*$/, '')}\n${missing.join('\n')}\n`, 'utf8');
    secureFile(file);
  }
}

/**
 * Creates persistent gateway configuration and a one-time setup key.
 * dsh, its profile, and its remote-settings patch are managed outside this image.
 */
export function initializeDocker({
  env = process.env,
  log = console.log,
  error = console.error,
} = {}) {
  const envFile = nonEmpty(env.DSH_PASSWORDS_ENV_FILE, '/data/dsh-passwords/.env');
  const stateDir = path.dirname(envFile);
  const dbPath = nonEmpty(env.MCP_DB_PATH, path.join(stateDir, 'platform.db'));
  const upstream = nonEmpty(env.MCP_GATEWAY_UPSTREAM, 'http://127.0.0.1:3080');
  const setupKeyFile = path.join(stateDir, 'setup-key.txt');

  mkdirSync(stateDir, { recursive: true });
  mkdirSync(path.dirname(dbPath), { recursive: true });

  let firstInitialization = false;
  let setupKey = '';
  if (existsSync(envFile)) {
    secureFile(envFile);
    setupKey = envValue(readFileSync(envFile, 'utf8'), 'SETUP_KEY');
    if (setupKey === '') {
      error(`[dsh-passwords] ${envFile} exists but has no usable SETUP_KEY; refusing to replace persistent configuration`);
      return false;
    }
    appendMissingEnv(envFile, {
      MCP_DB_ENC_KEY: randomBytes(32).toString('hex'),
      MCP_DB_PATH: dbPath,
      MCP_GATEWAY_AUTO_TLS: '0',
      MCP_GATEWAY_HOST: '0.0.0.0',
      MCP_GATEWAY_PORT: '3088',
      MCP_GATEWAY_UPSTREAM: upstream,
      MCP_DSH_RESTART_SERVICE: '',
      DSH_PASSWORDS_RUNTIME: 'docker',
    });
  } else {
    firstInitialization = true;
    setupKey = randomBytes(24).toString('hex');
    const dbEncKey = randomBytes(32).toString('hex');
    writeFileSync(
      envFile,
      [
        `SETUP_KEY=${setupKey}`,
        `MCP_DB_ENC_KEY=${dbEncKey}`,
        `MCP_DB_PATH=${dbPath}`,
        'DSH_PASSWORDS_RUNTIME=docker',
        'MCP_GATEWAY_AUTO_TLS=0',
        'MCP_GATEWAY_HOST=0.0.0.0',
        'MCP_GATEWAY_PORT=3088',
        `MCP_GATEWAY_UPSTREAM=${upstream}`,
        'MCP_DSH_RESTART_SERVICE=',
        '',
      ].join('\n'),
      { encoding: 'utf8', mode: 0o600 },
    );
    secureFile(envFile);
    log(`[dsh-passwords] created persistent configuration: ${envFile}`);
  }

  if (firstInitialization && !existsSync(setupKeyFile)) {
    writeFileSync(
      setupKeyFile,
      [
        'dsh-passwords Docker first-time setup key',
        '=========================================',
        '',
        `SETUP_KEY = ${setupKey}`,
        '',
        'Open the HTTPS address served by your reverse proxy, then use this key once to create the owner account.',
        'Delete this file after setup.',
        '',
      ].join('\n'),
      { encoding: 'utf8', mode: 0o600 },
    );
    secureFile(setupKeyFile);
    log(`[dsh-passwords] first-time setup key written to ${setupKeyFile}`);
  }

  return true;
}

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  process.exit(initializeDocker() ? 0 : 1);
}
