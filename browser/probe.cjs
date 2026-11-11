'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const MAX_WIDTHS = 800;
const MAX_WITNESSES = 8;
const MAX_REQUESTS = 128;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 48 * 1024 * 1024;
const BROWSER_TIMEOUT = 8_000;
const RUN_TIMEOUT = 39_000;
const LOOPBACK = new Map([
  ['127.0.0.1', '127.0.0.1'],
  ['localhost', '127.0.0.1'],
  ['[::1]', '::1']
]);
const REQUEST_HEADERS = new Set([
  'accept', 'accept-language', 'cookie', 'range', 'referer', 'user-agent'
]);
const RESPONSE_HEADERS_TO_DROP = new Set([
  'alt-svc', 'connection', 'content-length', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'trailer', 'transfer-encoding', 'upgrade'
]);

function boundedInteger(value, name, low, high) {
  if (!Number.isInteger(value) || value < low || value > high) {
    throw new Error(`${name} must be an integer from ${low} through ${high}.`);
  }
  return value;
}

function boundedText(value, name, max) {
  if (typeof value !== 'string' || !value.trim() || value.length > max || value.includes('\0')) {
    throw new Error(`${name} must be nonempty text up to ${max} characters.`);
  }
  return value.trim();
}

function parseConfig(input) {
  if (Buffer.byteLength(input) > 16_384) throw new Error('Probe request is too large.');
  const params = JSON.parse(input);
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new Error('Probe request must be a JSON object.');
  }
  const url = new URL(boundedText(params.url, 'url', 2048));
  const address = LOOPBACK.get(url.hostname);
  if (url.protocol !== 'http:' || !address || url.username || url.password) {
    throw new Error('Use an HTTP URL on 127.0.0.1, localhost, or [::1], without credentials.');
  }
  const minWidth = boundedInteger(params.minWidth, 'minWidth', 240, 2560);
  const maxWidth = boundedInteger(params.maxWidth, 'maxWidth', minWidth, 2560);
  if (maxWidth - minWidth + 1 > MAX_WIDTHS) {
    throw new Error(`A sweep can include at most ${MAX_WIDTHS} integer widths.`);
  }
  const witnessWidths = params.witnessWidths ?? [];
  if (!Array.isArray(witnessWidths) || witnessWidths.length > MAX_WITNESSES ||
      new Set(witnessWidths).size !== witnessWidths.length) {
    throw new Error(`witnessWidths must contain up to ${MAX_WITNESSES} distinct widths.`);
  }
  for (const width of witnessWidths) boundedInteger(width, 'Witness width', minWidth, maxWidth);
  return {
    url,
    address,
    selector: boundedText(params.selector, 'selector', 512),
    readySelector: params.readySelector == null
      ? null : boundedText(params.readySelector, 'readySelector', 512),
    minWidth,
    maxWidth,
    height: boundedInteger(params.height ?? 800, 'height', 240, 1600),
    witnessWidths,
    witnessDir: params.witnessDir == null
      ? null : path.resolve(boundedText(params.witnessDir, 'witnessDir', 2048))
  };
}

// Use a literal loopback socket. Redirects, browser proxy settings and DNS
// cannot cause this transport to send a request to another destination.
function fetchLoopback(url, address, method, browserHeaders, limits) {
  const headers = Object.fromEntries(
    Object.entries(browserHeaders).filter(([name]) => REQUEST_HEADERS.has(name))
  );
  headers.host = url.host;
  headers['accept-encoding'] = 'identity';
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: address,
      port: url.port || 80,
      path: url.pathname + url.search,
      method,
      headers,
      agent: false
    }, (response) => {
      const status = response.statusCode;
      if (status < 200 || (status >= 300 && status < 400)) {
        response.destroy();
        reject(new Error('The local document returned a redirect or unsupported status.'));
        return;
      }
      const chunks = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        limits.bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES || limits.bytes > MAX_TOTAL_BYTES) {
          response.destroy(new Error('The local page exceeded the response size limit.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        const responseHeaders = {};
        for (const [name, value] of Object.entries(response.headers)) {
          if (value != null && !RESPONSE_HEADERS_TO_DROP.has(name)) {
            responseHeaders[name] = Array.isArray(value) ? value.join('\n') : value;
          }
        }
        resolve({ status, headers: responseHeaders, body: Buffer.concat(chunks, bytes) });
      });
    });
    const timer = setTimeout(() => request.destroy(new Error('A local request timed out.')), BROWSER_TIMEOUT);
    request.on('error', reject);
    request.on('close', () => clearTimeout(timer));
    request.end();
  });
}

async function lockNetwork(context, config) {
  const limits = { bytes: 0, requests: 0 };
  const denied = new Set();
  await context.routeWebSocket('**/*', (socket) => {
    denied.add('WebSocket connection');
    socket.close();
  });
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    if (url.origin !== config.url.origin || url.username || url.password) {
      denied.add('cross-origin request');
      await route.abort('blockedbyclient');
      return;
    }
    if (method !== 'GET' && method !== 'HEAD') {
      denied.add(`${method} request`);
      await route.abort('blockedbyclient');
      return;
    }
    if (++limits.requests > MAX_REQUESTS) {
      denied.add('request count limit');
      await route.abort('blockedbyclient');
      return;
    }
    let response;
    try {
      response = await fetchLoopback(url, config.address, method, await request.allHeaders(), limits);
    } catch (error) {
      denied.add(error.message);
      await route.abort('failed');
      return;
    }
    if (response.status >= 400 && request.resourceType() !== 'image') {
      denied.add(`HTTP ${response.status} loading ${request.resourceType()}`);
    }
    await route.fulfill(response);
  });
  return denied;
}

function measure({ selector, width }) {
  function describe(element) {
    if (!element) return null;
    const tag = element.localName || element.tagName.toLowerCase();
    const id = element.id.slice(0, 160);
    const classes = Array.from(element.classList).slice(0, 3).map(value => value.slice(0, 100));
    const label = id ? `#${CSS.escape(id)}` : classes.map(value => `.${CSS.escape(value)}`).join('');
    return { tag, id, classes, selector: tag + label };
  }
  const result = (reason, fields = {}) => ({ width, state: 'inconclusive', reason, ...fields });

  window.scrollTo({ left: 0, top: 0, behavior: 'instant' });
  if (window.innerWidth !== width) {
    return result('viewport-mismatch', { actualWidth: window.innerWidth });
  }
  const matches = document.querySelectorAll(selector);
  if (!matches.length) return result('absent');
  if (matches.length > 1) return result('ambiguous', { matches: matches.length });

  const target = matches[0];
  const rect = target.getBoundingClientRect();
  if (!rect.width || !rect.height || !target.checkVisibility({
    opacityProperty: true,
    visibilityProperty: true,
    contentVisibilityAuto: true
  })) return result('hidden');
  if (target.matches(':disabled') || target.closest('[inert], [aria-disabled="true"]')) {
    return result('disabled');
  }

  const point = { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  const geometry = { rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height }, point };
  if (point.x < 0 || point.y < 0 ||
      point.x >= document.documentElement.clientWidth || point.y >= document.documentElement.clientHeight) {
    return result('offscreen', geometry);
  }
  const hit = document.elementFromPoint(point.x, point.y);
  if (!hit) return result('no-hit', geometry);
  if (target === hit || target.contains(hit)) {
    return { width, state: 'pass', reason: 'hit', ...geometry };
  }
  return { width, state: 'blocked', reason: 'intercepted', culprit: describe(hit), ...geometry };
}

function signature(row) {
  return JSON.stringify([row.state, row.reason, row.culprit?.selector ?? null]);
}

function collectBands(rows) {
  const bands = [];
  for (const row of rows) {
    const band = bands.at(-1);
    if (band && signature(band) === signature(row)) {
      band.end = row.width;
    } else {
      const { width, state, reason, culprit } = row;
      bands.push({ start: width, end: width, state, reason, ...(culprit ? { culprit } : {}) });
    }
  }
  return bands;
}

function witnessWidths(bands, requested) {
  const widths = new Set(requested);
  const blocked = bands.filter(band => band.state === 'blocked').slice(0, 3);
  for (const band of blocked) {
    widths.add(Math.floor((band.start + band.end) / 2));
  }
  const pass = bands.find(band => band.state === 'pass');
  if (pass) widths.add(Math.floor((pass.start + pass.end) / 2));
  for (const band of blocked) {
    widths.add(band.start);
    widths.add(band.end);
  }
  if (!widths.size) widths.add(bands[0].start);
  return [...widths].slice(0, MAX_WITNESSES);
}

function verifyNetwork(denied) {
  if (denied.size) {
    throw new Error(`The local document could not be fully rendered under the network boundary: ${[...denied].slice(0, 4).join(', ')}.`);
  }
}

async function verifyWitnesses(page, config, rows) {
  const witnesses = [];
  for (const width of witnessWidths(collectBands(rows), config.witnessWidths)) {
    await page.setViewportSize({ width, height: config.height });
    await page.evaluate(() => new Promise(resolve => {
      requestAnimationFrame(() => requestAnimationFrame(resolve));
    }));
    const row = rows[width - config.minWidth];
    const repeat = await page.evaluate(measure, { selector: config.selector, width });
    if (signature(row) !== signature(repeat)) {
      rows[width - config.minWidth] = { width, state: 'inconclusive', reason: 'unstable' };
      continue;
    }
    if (!config.witnessDir) continue;
    const image = await page.screenshot({ type: 'png', scale: 'css', timeout: BROWSER_TIMEOUT });
    const filename = path.join(config.witnessDir, `width-${width}.png`);
    fs.writeFileSync(filename, image, { flag: 'wx' });
    witnesses.push({
      width,
      state: row.state,
      reason: row.reason,
      path: filename,
      sha256: crypto.createHash('sha256').update(image).digest('hex')
    });
  }
  return witnesses;
}

async function run(config, setBrowser) {
  let chromium;
  try {
    ({ chromium } = require('playwright-core'));
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') throw error;
    throw new Error('Playwright Core is missing. Run npm ci --omit=dev --ignore-scripts in the browser folder.');
  }
  const browser = await chromium.launch({
    channel: 'msedge',
    headless: true,
    timeout: BROWSER_TIMEOUT,
    args: ['--no-proxy-server', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']
  });
  setBrowser(browser);
  const context = await browser.newContext({
    viewport: { width: config.minWidth, height: config.height },
    deviceScaleFactor: 1,
    serviceWorkers: 'block',
    acceptDownloads: false
  });
  const denied = await lockNetwork(context, config);
  const page = await context.newPage();
  page.setDefaultTimeout(BROWSER_TIMEOUT);
  page.setDefaultNavigationTimeout(BROWSER_TIMEOUT);
  let response;
  try {
    response = await page.goto(config.url.href, { waitUntil: 'load' });
  } catch (error) {
    verifyNetwork(denied);
    throw error;
  }
  if (!response || !response.ok()) {
    throw new Error(`The local document did not load successfully${response ? ` (HTTP ${response.status()})` : ''}.`);
  }
  if (config.readySelector) await page.locator(config.readySelector).waitFor({ state: 'visible' });
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  verifyNetwork(denied);

  const rows = [];
  for (let width = config.minWidth; width <= config.maxWidth; width++) {
    await page.setViewportSize({ width, height: config.height });
    rows.push(await page.evaluate(measure, { selector: config.selector, width }));
  }
  verifyNetwork(denied);
  if (config.witnessDir) fs.mkdirSync(config.witnessDir, { recursive: true });
  const witnesses = await verifyWitnesses(page, config, rows);
  verifyNetwork(denied);
  return {
    ok: true,
    engine: { name: 'Microsoft Edge (Chromium)', version: browser.version() },
    url: config.url.href,
    selector: config.selector,
    height: config.height,
    minWidth: config.minWidth,
    maxWidth: config.maxWidth,
    rows,
    bands: collectBands(rows),
    witnesses
  };
}

async function main() {
  let browser;
  let timer;
  try {
    const config = parseConfig(fs.readFileSync(0, 'utf8'));
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('The browser probe exceeded its 39-second time limit.')), RUN_TIMEOUT);
    });
    const result = await Promise.race([run(config, instance => { browser = instance; }), deadline]);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (error) {
    const message = (error instanceof Error ? error.message : String(error)).split('\n')[0];
    process.stdout.write(JSON.stringify({ ok: false, error: message.slice(0, 600) }) + '\n');
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
    if (browser) await browser.close().catch(() => {});
  }
}

void main();
