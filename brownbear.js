//Brownbear security ʕ´• ᴥ•̥`ʔ
//API/Lib free, pure JS
//2025

//<(---- 1. BROWNBEAR CRYPTOGRAPHIC ----)>

// 1.1 ROTR ʕ´• ᴥ•̥`ʔ
//https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf?utm_source=chatgpt.com
function ROTR(x, n) {
  return (x >>> n) | (x << (32 - n));
}

// 1.2 SHA-256 (FIPS 180-4) ʕ´• ᴥ•̥`ʔ
function sha256(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  // Pre-processing
  const l = bytes.length * 8;
  let withOne = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  withOne.set(bytes);
  withOne[bytes.length] = 0x80;
  const dv = new DataView(withOne.buffer);
  dv.setUint32(withOne.length - 4, l >>> 0);
  dv.setUint32(withOne.length - 8, Math.floor(l / 0x100000000));

  // Process each 512-bit chunk
  for (let i = 0; i < withOne.length; i += 64) {
    const W = new Uint32Array(64);
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    H = [
      (H[0] + a) >>> 0, (H[1] + b) >>> 0, (H[2] + c) >>> 0, (H[3] + d) >>> 0,
      (H[4] + e) >>> 0, (H[5] + f) >>> 0, (H[6] + g) >>> 0, (H[7] + h) >>> 0
    ];
  }

  const hash = new Uint8Array(32);
  H.forEach((h, i) => hash.set([h >>> 24, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff], i * 4));
  return hash;
}

// 1.3 HMAC-SHA256 ʕ´• ᴥ•̥`ʔ
function hmacSha256(key, message) {
  let keyBytes = key;
  if (typeof key === 'string') keyBytes = new TextEncoder().encode(key);
  const blockSize = 64;
  if (keyBytes.length > blockSize) keyBytes = sha256(keyBytes);
  if (keyBytes.length < blockSize) {
    const tmp = new Uint8Array(blockSize);
    tmp.set(keyBytes);
    keyBytes = tmp;
  }
  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = keyBytes[i] ^ 0x5c;
    iKeyPad[i] = keyBytes[i] ^ 0x36;
  }
  const innerHash = sha256(concatBuffers(iKeyPad, message));
  return sha256(concatBuffers(oKeyPad, innerHash));
}

// 1.4 concatBuffers ʕ´• ᴥ•̥`ʔ
function concatBuffers(...buffers) {
  const total = buffers.reduce((sum, b) => sum + b.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const b of buffers) {
    result.set(b, offset);
    offset += b.length;
  }
  return result;
}

// 1.5 Base64 utils ʕ´• ᴥ•̥`ʔ
function bufferToBase64(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}
function base64ToBuffer(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

//<(---- 2. PBKDF2 (RFC 8018) ----)>
async function pbkdf2(passphrase, salt, iterations, dkLen) {
  const pass = new TextEncoder().encode(passphrase);
  const HLen = 32;
  const l = Math.ceil(dkLen / HLen);
  const DK = new Uint8Array(l * HLen);
  for (let i = 1; i <= l; i++) {
    const intBuf = new Uint8Array(4);
    new DataView(intBuf.buffer).setUint32(0, i);
    let U = hmacSha256(pass, concatBuffers(salt, intBuf));
    let T = new Uint8Array(U);
    for (let j = 1; j < iterations; j++) {
      U = hmacSha256(pass, U);
      for (let k = 0; k < HLen; k++) T[k] ^= U[k];
    }
    DK.set(T, (i - 1) * HLen);
    zeroize(U);
    zeroize(T);
    zeroize(passphrase);
  }
  return DK.slice(0, dkLen);
}

//<(---- 3. AES-256 (FIPS 197) ----)>
// 3.1 Key schedule ʕ´• ᴥ•̥`ʔ
// AES-256 Key Schedule
function aesKeySchedule(keyBytes) {
  const Nk = 8, Nb = 4, Nr = 14;
  const Rcon = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
    0xab000000, 0x4d000000, 0x9a000000
  ];

  const W = new Uint32Array(Nb * (Nr + 1));
  const dv = new DataView(keyBytes.buffer, keyBytes.byteOffset, keyBytes.byteLength);
  for (let i = 0; i < Nk; i++) W[i] = dv.getUint32(i * 4, false);

  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = W[i - 1];
    if (i % Nk === 0) temp = subWord(rotWord(temp)) ^ Rcon[(i / Nk) - 1];
    else if (Nk > 6 && i % Nk === 4) temp = subWord(temp);
    W[i] = W[i - Nk] ^ temp;
  }
  return W;
}

function rotWord(w) {
  return ((w << 8) | (w >>> 24)) >>> 0;
}

function subWord(w) {
  return (
    (SBOX[w >>> 24] << 24) |
    (SBOX[(w >>> 16) & 0xff] << 16) |
    (SBOX[(w >>> 8) & 0xff] << 8) |
    SBOX[w & 0xff]
  ) >>> 0;
}

// S-Box 256
const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

// 3.2 AES block operations ʕ´• ᴥ•̥`ʔ
function addRoundKey(state, roundKeyWords) {
  for (let i = 0; i < 4; i++) {
    const word = roundKeyWords[i];
    state[i * 4 + 0] ^= (word >>> 24) & 0xff;
    state[i * 4 + 1] ^= (word >>> 16) & 0xff;
    state[i * 4 + 2] ^= (word >>> 8) & 0xff;
    state[i * 4 + 3] ^= word & 0xff;
  }
}

function subBytes(state) {
  for (let i = 0; i < 16; i++) {
    state[i] = SBOX[state[i]];
  }
}

function shiftRows(s) {
  const t = new Uint8Array(s);
  s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
  s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
  s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
}

function xtime(a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

function mixColumns(s) {
  for (let i = 0; i < 4; i++) {
    const a = [], b = [], col = i * 4;
    for (let j = 0; j < 4; j++) {
      a[j] = s[col + j];
      b[j] = xtime(a[j]);
    }
    s[col] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    s[col + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    s[col + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    s[col + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
  }
}

function aesEncryptBlock(input, W) {
  if (input.length !== 16 || W.length !== 60) {
    zeroize(input);
    zeroize(W);
    throw new Error("Input must be 16 bytes and W must contain 60 words (AES-256 key schedule).");
  }

  let state = new Uint8Array(input);

  // Add initial round key
  addRoundKey(state, W.subarray(0, 4));

  for (let round = 1; round < 14; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, W.subarray(round * 4, round * 4 + 4));
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, W.subarray(14 * 4, 14 * 4 + 4));

  return state;
}

//<(---- 4. GCM (NIST SP 800-38D) ----)>
function gfMul(X, Y) {
  let Z = new Uint8Array(16), V = X.slice();
  for (let i = 0; i < 128; i++) {
    if ((Y[Math.floor(i / 8)] & (1 << (7 - (i % 8)))) !== 0) {
      Z = xor16(Z, V);
    }
    V = xtimeBlock(V);
  }
  return Z;
}
function xor16(a, b) {
  const r = new Uint8Array(16);
  for (let i = 0; i < 16; i++) r[i] = a[i] ^ b[i];
  return r;
}
function xtimeBlock(block) {
  const R = 0xe1;
  let carry = 0;
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    const b = block[i];
    out[i] = ((b << 1) | carry) & 0xff;
    carry = (b & 0x80) ? 1 : 0;
  }
  if (carry) out[15] ^= R;
  return out;
}
function ghash(H, A, C) {
  const lenA = to64bit(A.length * 8), lenC = to64bit(C.length * 8);
  let Y = new Uint8Array(16);
  [A, C, lenA, lenC].forEach(data => {
    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      Y = gfMul(xor16(Y, block.length === 16 ? block : pad16(block)), H);
    }
  });
  return Y;
}
function pad16(block) {
  const p = new Uint8Array(16);
  p.set(block);
  return p;
}
function to64bit(x) {
  const res = new Uint8Array(16);
  // first 8 bytes zeros
  const dv = new DataView(res.buffer);
  dv.setBigUint64(8, BigInt(x));
  return res;
}

function aesGcmEncrypt(key, plaintext, aad = new Uint8Array()) {
  const maxBlocks = 0xFFFFFFFF - 1; // per spec
  if (Math.ceil(plaintext.length / 16) > maxBlocks) {
    throw new Error("Plaintext too long for AES-GCM with 96-bit IV");
  }

  const schedule = aesKeySchedule(key);
  const iv = randomBytes(12);
  const H = aesEncryptBlock(new Uint8Array(16), schedule);
  const J0 = new Uint8Array(16);
  J0.set(iv);
  J0[15] = 1;

  const C = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    const ctr = J0.slice();
    new DataView(ctr.buffer).setUint32(12, Math.floor(i / 16) + 1);
    const S = aesEncryptBlock(ctr, schedule);
    C[i] = plaintext[i] ^ S[i % 16];
  }

  const tagMask = aesEncryptBlock(J0, schedule);
  const tag = xor16(tagMask, ghash(H, aad, C));
  return { iv, ciphertext: C, tag };
}

function aesGcmDecrypt(key, ciphertext, iv, aad = new Uint8Array(), tag) {
  const schedule = aesKeySchedule(key);
  const H = aesEncryptBlock(new Uint8Array(16), schedule);
  const J0 = new Uint8Array(16);
  J0.set(iv); J0[15] = 1;

  const P = new Uint8Array(ciphertext.length);
  ciphertext.forEach((_, i) => {
    const ctr = J0.slice();
    new DataView(ctr.buffer).setUint32(12, Math.floor(i / 16) + 1);
    const S = aesEncryptBlock(ctr, schedule);
    P[i] = ciphertext[i] ^ S[i % 16];
  });

  const tagMask = aesEncryptBlock(J0, aesKeySchedule(key));
  const computedTag = xor16(tagMask, ghash(H, aad, ciphertext));
  //computedTag.every((b, i) => b === tag[i]) can be shorted early-exit. It is better to compare in constant time
  let valid = 0;
  for (let i = 0; i < tag.length; i++) valid |= computedTag[i] ^ tag[i];
  valid = (valid === 0);
  return { plaintext: P, valid };
}

// 4.1 Pseudo-random (HMAC-DRBG) ʕ´• ᴥ•̥`ʔ
//https://stackoverflow.com/questions/5651789/is-math-random-cryptographically-secure
// Global entropy pool
let entropyPool = [];

// DRBG internal state
let drbgKey = null;
let drbgV = null;

// Reseed controls
const RESEED_THRESHOLD = 128;        // min entropy-events before we reseed
const MIN_RESEED_INTERVAL = 1000;    // ms between reseeds
let lastReseedTime = 0;

// Collect entropy from mouse movements
window.addEventListener('mousemove', e => {
  entropyPool.push(e.screenX ^ e.screenY ^ Date.now());
  trimEntropy();
});
// Collect entropy from keyboard timing
let lastKeyTime = Date.now();
window.addEventListener('keydown', () => {
  const now = Date.now();
  entropyPool.push(now - lastKeyTime);
  lastKeyTime = now;
  trimEntropy();
});
// Keep the pool bounded
function trimEntropy() {
  if (entropyPool.length > 1024) {
    entropyPool = entropyPool.slice(-1024);
  }
}

// Zeroize a Uint8Array (wipe sensitive data)
function zeroize(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
}

// --- HMAC-DRBG helpers ---
// Update drbgKey & drbgV with optional seed
function updateDRBG(seedBytes) {
  drbgKey = hmacSha256(drbgKey, concatBuffers(drbgV, new Uint8Array([0x00]), seedBytes));
  drbgV = hmacSha256(drbgKey, drbgV);
  if (seedBytes.length) {
    drbgKey = hmacSha256(drbgKey, concatBuffers(drbgV, new Uint8Array([0x01]), seedBytes));
    drbgV = hmacSha256(drbgKey, drbgV);
  }
}

// Generate len bytes via HMAC-DRBG
function drbgGenerate(len) {
  const out = new Uint8Array(len);
  let generated = 0;
  while (generated < len) {
    drbgV = hmacSha256(drbgKey, drbgV);
    const chunk = drbgV.subarray(0, Math.min(len - generated, drbgV.length));
    out.set(chunk, generated);
    generated += chunk.length;
  }
  // Post-update for forward security
  updateDRBG(new Uint8Array());
  return out;
}

// Fold entropyPool into 32 bytes via your SHA-256
function foldEntropyPool() {
  const text = entropyPool.join(',');
  const data = new TextEncoder().encode(text);
  return sha256(data);
}

// Reseed DRBG: zeroize old state, then init+update with new seed
function reseedDRBG() {
  // wipe old state
  zeroize(drbgKey);
  zeroize(drbgV);

  // fold collected events into seed
  const seed = foldEntropyPool();

  // init state
  drbgKey = new Uint8Array(32).fill(0);
  drbgV = new Uint8Array(32).fill(1);

  updateDRBG(seed);

  // clear pool and record time
  entropyPool = [];
  lastReseedTime = Date.now();
}

// Public API unchanged
function randomBytes(len) {
  const now = Date.now();
  // reseed on first use, or if enough events AND enough time has passed
  if (
    !drbgKey ||
    (entropyPool.length >= RESEED_THRESHOLD &&
      (now - lastReseedTime) >= MIN_RESEED_INTERVAL)
  ) {
    reseedDRBG();
  }
  return drbgGenerate(len);
}

//<(---- 5. MODULE BrownBear ----)>
let _keyBytes = null;
let _salt = null;

const BrownBear = {
  async setPassword(pass, customSalt) {
    _salt = customSalt ? base64ToBuffer(customSalt) : randomBytes(16);
    _keyBytes = await pbkdf2(pass, _salt, 100000, 32);
    zeroize(pass);
    return bufferToBase64(_salt);
  },
  async encrypt(plaintext) {
    if (!_keyBytes) throw new Error('Password not set');
    const pt = new TextEncoder().encode(plaintext);
    const { iv, ciphertext, tag } = aesGcmEncrypt(_keyBytes, pt);
    return {
      data: bufferToBase64(ciphertext),
      iv: bufferToBase64(iv),
      tag: bufferToBase64(tag),
      salt: bufferToBase64(_salt)
    };
  },
  async decrypt(dataB64, ivB64, tagB64) {
    if (!_keyBytes) throw new Error('Password not set');
    const C = base64ToBuffer(dataB64);
    const iv = base64ToBuffer(ivB64);
    const tag = base64ToBuffer(tagB64);
    const { plaintext, valid } = aesGcmDecrypt(_keyBytes, C, iv, new Uint8Array(), tag);
    if (!valid) {
      zeroize(U);
      zeroize(T);
      throw new Error('Authentication failed');
    }
    return new TextDecoder().decode(plaintext);
  }
};
const key = new Uint8Array(32);
const input = new Uint8Array(16);
const expandedKey = aesKeySchedule(key);
const encrypted = aesEncryptBlock(input, expandedKey);
console.log("Code :", Array.from(encrypted).map(b => b.toString(16).padStart(2, '0')).join(' '));

export default BrownBear;