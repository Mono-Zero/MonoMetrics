// Run: node server.js
// Env vars:
//   PORT=3000       — port to listen on
//   TRUST_PROXY=1   — trust X-Forwarded-For for the real IP (only if you're
//                     actually behind a reverse proxy that sets it — otherwise
//                     clients can spoof their own IP with this header

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

// SECTION 1: DAILY SALT
//
// 32 random bytes, generated fresh once per UTC day, kept only in memory 
// never logged or written to disk. When the day rolls over, the old salt is
// gone for good. That's what makes today's hash and tomorrow's hash of the
// same IP unlinkable: the only thing that could prove they're related no
// longer exists anywhere.

let currentSalt = null;
let currentSaltDate = null; // 'YYYY-MM-DD', UTC

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

// Returns today's salt, generating a new one if the UTC date has changed.
function getCurrentSalt() {
  const today = todayUTC();
  if (today !== currentSaltDate) {
    currentSaltDate = today;
    currentSalt = crypto.randomBytes(32).toString('hex');
  }
  return { salt: currentSalt, date: currentSaltDate };
}

// SECTION 2: IP HASHING
//
// SHA-256(ip + salt + date) — turns an identifying IP into a hash that isn't.
// The salt makes it unreversible and unlinkable across days; the date is
// cheap insurance in case a salt ever got reused. Raw IPs are never stored,
// logged, or passed anywhere past this function.

function hashVisitorIP(ip) {
  const { salt, date } = getCurrentSalt();
  const hash = crypto
    .createHash('sha256')
    .update(ip + salt + date)
    .digest('hex');
  return { hash, date };
}

// Picks which IP to use for a request. Default: the socket's remote address
// (correct if this server faces the internet directly). With TRUST_PROXY=1,
// reads X-Forwarded-For instead only safe behind a proxy that sets that
// header itself, since otherwise a client can fake it.
function getClientIP(req) {
  const forwardedHeader = req.headers['x-forwarded-for'];
  if (process.env.TRUST_PROXY === '1' && forwardedHeader) {
    return forwardedHeader.split(',')[0].trim();
  }
  return req.socket.remoteAddress;
}

// SECTION 3: HYPERLOGLOG
//
// Estimates "how many distinct hashes have I seen" without keeping a list.
// Each hash is split into a bucket index + a leading-zero-bit streak length;
// each of the 16,384 buckets just remembers the longest streak that's landed
// in it. Longer streaks are rarer, so the longest streak seen roughly implies
// how many hashes it took to find one combine all 16,384 buckets and you
// get an estimate accurate to about 0.8%

const HLL_REGISTER_BITS = 14; // 2^14 = 16,384 buckets
const HLL_NUM_REGISTERS = 1 << HLL_REGISTER_BITS;

// Standard bias-correction constant from the HyperLogLog paper, for this register count.
const HLL_ALPHA = 0.7213 / (1 + 1.079 / HLL_NUM_REGISTERS);

class HyperLogLog {
  constructor() {
    this.registers = new Uint8Array(HLL_NUM_REGISTERS);
  }

  // Feed one hash in. After this call, the hash is gone only its effect
  // on (at most) one bucket remains.
  add(hashHex) {
    const hashAsBigInt = BigInt('0x' + hashHex);
    const totalBits = BigInt(hashHex.length * 4);

    // Top bits pick the bucket.
    const bucketIndex = Number(
      hashAsBigInt >> (totalBits - BigInt(HLL_REGISTER_BITS))
    );

    // Remaining bits give the leading-zero streak length.
    const remainingBitCount = Number(totalBits) - HLL_REGISTER_BITS;
    const remainingBits =
      hashAsBigInt & ((1n << BigInt(remainingBitCount)) - 1n);
    const streakLength = countLeadingZeroBits(remainingBits, remainingBitCount) + 1;

    // Same visitor hitting twice today produces the same hash, same
    // bucket, same streak — so duplicates never increase anything.
    if (streakLength > this.registers[bucketIndex]) {
      this.registers[bucketIndex] = streakLength;
    }
  }

  // Combines all 16,384 bucket values into one estimated unique count.
  estimate() {
    let sumOfInverses = 0;
    let emptyBucketCount = 0;

    for (let i = 0; i < HLL_NUM_REGISTERS; i++) {
      sumOfInverses += 1 / Math.pow(2, this.registers[i]);
      if (this.registers[i] === 0) emptyBucketCount++;
    }

    let rawEstimate =
      (HLL_ALPHA * HLL_NUM_REGISTERS * HLL_NUM_REGISTERS) / sumOfInverses;

    // For small true counts, most buckets are still empty and the raw
    // formula above is inaccurate — fall back to linear counting instead.
    if (rawEstimate <= 2.5 * HLL_NUM_REGISTERS && emptyBucketCount > 0) {
      rawEstimate =
        HLL_NUM_REGISTERS * Math.log(HLL_NUM_REGISTERS / emptyBucketCount);
    }

    return Math.round(rawEstimate);
  }
}

// Counts leading zero bits in `value`, treated as a `bitLength`-bit number.
function countLeadingZeroBits(value, bitLength) {
  if (value === 0n) return bitLength;
  let zeroCount = 0;
  for (let bitPosition = bitLength - 1; bitPosition >= 0; bitPosition--) {
    const bit = (value >> BigInt(bitPosition)) & 1n;
    if (bit === 1n) break;
    zeroCount++;
  }
  return zeroCount;
}

// SECTION 4: STORAGE
//
// One HyperLogLog per (day, url, device), kept in an in-memory Map nothing
// written to disk or a database. Counts reset on restart, and won't be
// shared across multiple server instances. Fine for a minimal version; if you
// need persistence, serialize each HyperLogLog's `registers` array (e.g.
// base64) to a file/DB periodically and reload it on startup.

const dailyCounters = new Map(); // "date|urlAndDevice" -> HyperLogLog

function makeStorageKey(date, urlAndDevice) {
  return `${date}|${urlAndDevice}`;
}

function recordHit(date, urlAndDevice, hash) {
  const key = makeStorageKey(date, urlAndDevice);
  if (!dailyCounters.has(key)) {
    dailyCounters.set(key, new HyperLogLog());
  }
  dailyCounters.get(key).add(hash);
}

function getUniqueCount(date, urlAndDevice) {
  const key = makeStorageKey(date, urlAndDevice);
  const hll = dailyCounters.get(key);
  return hll ? hll.estimate() : 0;
}

// Drops counters older than `days` days, to cap memory on long-running
// servers. Not called automatically wire it up below if you want it.
function pruneCountersOlderThan(days) {
  const cutoffTimestamp = Date.now() - days * 24 * 60 * 60 * 1000;
  for (const key of dailyCounters.keys()) {
    const dateOnlyPart = key.split('|')[0];
    const dateTimestamp = new Date(dateOnlyPart + 'T00:00:00Z').getTime();
    if (dateTimestamp < cutoffTimestamp) {
      dailyCounters.delete(key);
    }
  }
}

// SECTION 5: HTTP SERVER
//
// Thin on purpose the actual logic already happened in sections 1-4. No
// framework, just Node's built-in http module: fewer dependencies, nothing
// between you and what's happening on the wire.
//
//   POST /hit    { url, device: "mobile"|"desktop" } -> records one hit, 204
//   GET  /count?url=...&device=...&date=...          -> { url, date, uniques }

function sendJSONResponse(res, statusCode, bodyObject) {
  const bodyText = JSON.stringify(bodyObject);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(bodyText),
  });
  res.end(bodyText);
}

// Collects the streamed request body into one string, capped at 100KB as a
// basic guard (a real hit payload is only a few dozen bytes).
function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let collectedText = '';
    req.on('data', (chunk) => {
      collectedText += chunk;
      if (collectedText.length > 100_000) {
        req.destroy();
      }
    });
    req.on('end', () => resolve(collectedText));
    req.on('error', reject);
  });
}

async function handleHitRequest(req, res) {
  let parsedBody;
  try {
    const rawBody = await readRequestBody(req);
    parsedBody = rawBody ? JSON.parse(rawBody) : {};
  } catch (err) {
    return sendJSONResponse(res, 400, { error: 'malformed JSON body' });
  }

  // Path only, capped at 500 chars as a sanity limit.
  const pageURL = String(parsedBody.url || '').slice(0, 500);
  if (!pageURL) {
    return sendJSONResponse(res, 400, { error: 'missing "url" in body' });
  }

  // Anything other than "mobile" normalizes to "desktop".
  const device = parsedBody.device === 'mobile' ? 'mobile' : 'desktop';

  const visitorIP = getClientIP(req);
  const { hash, date } = hashVisitorIP(visitorIP);

  const urlAndDevice = `${pageURL}::${device}`;
  recordHit(date, urlAndDevice, hash);

  // Nothing meaningful to send back the client script doesn't read this.
  return sendJSONResponse(res, 204, {});
}

function handleCountRequest(req, res, requestURL) {
  const pageURL = requestURL.searchParams.get('url');
  if (!pageURL) {
    return sendJSONResponse(res, 400, {
      error: 'missing "url" query parameter',
    });
  }

  const date = requestURL.searchParams.get('date') || todayUTC();
  const deviceFilter = requestURL.searchParams.get('device');

  let uniqueCount;
  if (deviceFilter === 'mobile' || deviceFilter === 'desktop') {
    uniqueCount = getUniqueCount(date, `${pageURL}::${deviceFilter}`);
  } else {
    // No filter: mobile + desktop added together (simple sum of two
    // separate estimates, not a true HLL merge close enough here).
    uniqueCount =
      getUniqueCount(date, `${pageURL}::mobile`) +
      getUniqueCount(date, `${pageURL}::desktop`);
  }

  return sendJSONResponse(res, 200, {
    url: pageURL,
    date,
    uniques: uniqueCount,
  });
}

const server = http.createServer(async (req, res) => {
  const requestURL = new URL(req.url, `http://${req.headers.host}`);

  // Allow any origin  this is meant to be embedded on whatever site you
  // put the script tag on, and there's no cookie/session for CORS to protect.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (req.method === 'POST' && requestURL.pathname === '/hit') {
    try {
      return await handleHitRequest(req, res);
    } catch (err) {
      return sendJSONResponse(res, 500, { error: 'internal server error' });
    }
  }

  if (req.method === 'GET' && requestURL.pathname === '/count') {
    try {
      return handleCountRequest(req, res, requestURL);
    } catch (err) {
      return sendJSONResponse(res, 500, { error: 'internal server error' });
    }
  }

  return sendJSONResponse(res, 404, { error: 'not found' });
});

// Optional daily prune of counters older than 30 days. Adjust or remove as needed.
setInterval(() => pruneCountersOlderThan(30), 24 * 60 * 60 * 1000);

server.listen(PORT, () => {
  console.log(`MonoMetrics listening on :${PORT}`);
});
