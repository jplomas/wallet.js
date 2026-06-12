import { shake256 } from '@noble/hashes/sha3.js';
import { CryptoPublicKeyBytes, cryptoSignKeypair, CryptoSecretKeyBytes, cryptoSign, CryptoBytes, cryptoSignVerify } from '@theqrl/mldsa87';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';

/**
 * Constants used across wallet components.
 * @module wallet/common/constants
 */

/** @type {number} Size in bytes of the 3-byte descriptor */
const DESCRIPTOR_SIZE = 3;

/**
 * @type {number} QRL address length in bytes. 64 bytes (512 bits)
 * exceeds NIST Category 5 collision targets and produces a `Q` + 128
 * hex-character address string. Matches go-qrllib's `AddressSize` and
 * rust-qrllib's `ADDRESS_SIZE` constants — one canonical size across
 * implementations.
 */
const ADDRESS_SIZE = 64;

/** @type {number} Seed length in bytes */
const SEED_SIZE = 48;

/** @type {number} Extended seed length in bytes */
const EXTENDED_SEED_SIZE = DESCRIPTOR_SIZE + SEED_SIZE;

/**
 * Address helpers.
 * @module wallet/common/address
 *
 * Address Format:
 *   - Byte form: `ADDRESS_SIZE`-byte SHAKE-256 hash of (descriptor || public key).
 *   - String form: "Q" prefix followed by `2 × ADDRESS_SIZE` hex
 *     characters. At the canonical 64-byte size this is a 129-character string.
 *   - `addressToString` emits lowercase hex; `toChecksumAddress` emits the
 *     EIP-55-style mixed-case checksummed form. The `Q` prefix is always
 *     uppercase on output; input parsing accepts `Q` or `q`.
 *
 * EIP-55 Checksum (QRL variant):
 *   - Hash: SHAKE-256 of the UTF-8 bytes of the 128-character lowercase hex
 *     (no `Q` prefix), with dkLen = `ADDRESS_SIZE`, giving exactly one nibble
 *     per hex character.
 *   - For each hex character: if it is a letter (`a`-`f`) and the
 *     corresponding nibble of the hash is ≥ 8, uppercase it; otherwise leave
 *     it lowercase.
 *   - `stringToAddress` / `isValidAddress` accept all-lowercase and
 *     all-uppercase hex unchanged (legacy / case-uniform forms). Mixed-case
 *     hex must match the checksum exactly, otherwise the address is
 *     rejected. This mirrors EIP-55 semantics.
 *
 * All helpers operate at the single canonical {@link ADDRESS_SIZE}; addresses
 * of other sizes are rejected. This matches go-qrllib (`AddressSize`) and
 * rust-qrllib (`ADDRESS_SIZE`).
 */


const HEX_LEN = ADDRESS_SIZE * 2;
const HEX_REGEX = /^[0-9a-fA-F]+$/;

/**
 * @param {Uint8Array} bytes
 * @returns {string} lowercase hex, two characters per byte.
 */
function bytesToLowerHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Compute the EIP-55-style mixed-case form of a lowercase hex string.
 * Internal helper; assumes `lowerHex` is exactly `HEX_LEN` lowercase hex
 * characters.
 * @param {string} lowerHex
 * @returns {string}
 */
function checksummedHex(lowerHex) {
  const input = new Uint8Array(lowerHex.length);
  for (let i = 0; i < lowerHex.length; i += 1) {
    input[i] = lowerHex.charCodeAt(i);
  }
  const hash = shake256.create({ dkLen: ADDRESS_SIZE }).update(input).digest();
  let out = '';
  for (let i = 0; i < lowerHex.length; i += 1) {
    const ch = lowerHex.charCodeAt(i);
    // letters a..f are 0x61..0x66; digits 0..9 are 0x30..0x39
    if (ch >= 0x61 && ch <= 0x66) {
      const nibble = (i & 1) === 0 ? hash[i >> 1] >> 4 : hash[i >> 1] & 0x0f;
      if (nibble >= 8) {
        out += lowerHex[i].toUpperCase();
        continue;
      }
    }
    out += lowerHex[i];
  }
  return out;
}

/**
 * Convert address bytes to string form (lowercase hex).
 * @param {Uint8Array} addrBytes - Exactly {@link ADDRESS_SIZE} bytes.
 * @returns {string}
 * @throws {Error} If input is not a Uint8Array of exactly ADDRESS_SIZE bytes.
 */
function addressToString(addrBytes) {
  if (!(addrBytes instanceof Uint8Array)) {
    throw new Error('address must be a Uint8Array');
  }
  if (addrBytes.length !== ADDRESS_SIZE) {
    throw new Error(`address must be exactly ${ADDRESS_SIZE} bytes, got ${addrBytes.length}`);
  }
  return `Q${bytesToLowerHex(addrBytes)}`;
}

/**
 * Convert an address (bytes or string) to its EIP-55-style mixed-case
 * checksummed string form. The returned string always uses uppercase `Q`.
 *
 * - Uint8Array input: must be exactly {@link ADDRESS_SIZE} bytes.
 * - String input: parsed via {@link stringToAddress} first, so mixed-case
 *   inputs must already carry a valid checksum (otherwise the call throws).
 *   All-lowercase, all-uppercase, and correctly-checksummed inputs are all
 *   accepted and re-emitted in canonical checksummed form.
 *
 * @param {Uint8Array|string} addr
 * @returns {string} Checksummed address: `Q` + 128 mixed-case hex chars.
 * @throws {Error} If the input is the wrong type, wrong length, contains
 *   invalid hex, or is a mixed-case string with a bad checksum.
 */
function toChecksumAddress(addr) {
  let bytes;
  if (addr instanceof Uint8Array) {
    if (addr.length !== ADDRESS_SIZE) {
      throw new Error(`address must be exactly ${ADDRESS_SIZE} bytes, got ${addr.length}`);
    }
    bytes = addr;
  } else if (typeof addr === 'string') {
    bytes = stringToAddress(addr);
  } else {
    throw new Error('address must be a Uint8Array or string');
  }
  return `Q${checksummedHex(bytesToLowerHex(bytes))}`;
}

/**
 * Convert address string to bytes.
 *
 * The `Q` prefix is case-insensitive. The hex body must be one of:
 *   - all lowercase (case-uniform), OR
 *   - all uppercase (case-uniform), OR
 *   - mixed-case matching the EIP-55-style checksum (see module docs).
 *
 * Mixed-case strings that do not match the checksum are rejected, mirroring
 * Ethereum tooling behavior for EIP-55 addresses.
 *
 * @param {string} addrStr - Address string: 'Q'/'q' followed by exactly
 *   `2 × ADDRESS_SIZE` (= 128) hex characters.
 * @returns {Uint8Array} Decoded ADDRESS_SIZE-byte address.
 * @throws {Error} If address format or checksum is invalid.
 */
function stringToAddress(addrStr) {
  if (typeof addrStr !== 'string') {
    throw new Error('address must be a string');
  }
  const trimmed = addrStr.trim();
  if (!trimmed.startsWith('Q') && !trimmed.startsWith('q')) {
    throw new Error('address must start with Q');
  }
  const hex = trimmed.slice(1);
  if (hex.length !== HEX_LEN) {
    throw new Error(`address must be Q + exactly ${HEX_LEN} hex characters, got ${hex.length}`);
  }
  if (!HEX_REGEX.test(hex)) {
    throw new Error('address contains invalid characters');
  }
  const hexLower = hex.toLowerCase();
  const hexUpper = hex.toUpperCase();
  if (hex !== hexLower && hex !== hexUpper) {
    // Mixed case — must satisfy the EIP-55-style checksum.
    if (hex !== checksummedHex(hexLower)) {
      throw new Error('address has invalid EIP-55 checksum');
    }
  }
  const bytes = new Uint8Array(ADDRESS_SIZE);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hexLower.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Check if a string is a valid QRL address. Requires exactly `Q`/`q` + `2 ×
 * ADDRESS_SIZE` hex characters. Mixed-case hex must satisfy the EIP-55-style
 * checksum; all-lowercase and all-uppercase forms are accepted unconditionally.
 *
 * This is a permissive check: it accepts un-checksummed (case-uniform) inputs.
 * Use {@link isValidChecksumAddress} to require a properly-checksummed string.
 *
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if the address parses successfully.
 */
function isValidAddress(addrStr) {
  try {
    stringToAddress(addrStr);
    return true;
  } catch {
    return false;
  }
}

/**
 * Strict check: returns true only when `addrStr` exactly matches the
 * canonical checksummed form produced by {@link toChecksumAddress}. This
 * means:
 *   - The `Q` prefix must be uppercase.
 *   - The hex body must match the EIP-55-style mixed-case checksum
 *     character-for-character.
 *
 * All-lowercase or all-uppercase addresses that contain letters return
 * `false` even though they are otherwise valid (use {@link isValidAddress}
 * for the permissive check). Digit-only hex bodies have no checksum
 * information and return `true` when the rest of the format is valid.
 *
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean}
 */
function isValidChecksumAddress(addrStr) {
  if (typeof addrStr !== 'string') return false;
  const trimmed = addrStr.trim();
  if (!trimmed.startsWith('Q')) return false;
  const hex = trimmed.slice(1);
  if (hex.length !== HEX_LEN) return false;
  if (!HEX_REGEX.test(hex)) return false;
  return hex === checksummedHex(hex.toLowerCase());
}

/**
 * Derive an address from a public key and descriptor.
 * @param {Uint8Array} pk - Public key for the wallet type encoded in the descriptor.
 * @param {Descriptor} descriptor
 * @returns {Uint8Array} {@link ADDRESS_SIZE}-byte address.
 * @throws {Error} If pk is not a Uint8Array of the expected length.
 */
function getAddressFromPKAndDescriptor(pk, descriptor) {
  if (!(pk instanceof Uint8Array)) throw new Error('pk must be Uint8Array');

  const walletType = descriptor.type();
  let expectedPKLen;
  switch (walletType) {
    default:
      expectedPKLen = CryptoPublicKeyBytes;
  }
  if (pk.length !== expectedPKLen) {
    throw new Error(`pk must be ${expectedPKLen} bytes for wallet type ${walletType}`);
  }

  const descBytes = descriptor.toBytes();
  const input = new Uint8Array(descBytes.length + pk.length);
  input.set(descBytes, 0);
  input.set(pk, descBytes.length);
  return shake256.create({ dkLen: ADDRESS_SIZE }).update(input).digest();
}

/**
 * Shared byte/hex utils used across modules.
 * @module utils/bytes
 */


/**
 * Type guard: true when `input` is a Uint8Array (including Buffer).
 * @param {unknown} input
 * @returns {input is Uint8Array}
 */
function isUint8(input) {
  return input instanceof Uint8Array;
}

/**
 * Type guard: true when `input` is a hex-like string.
 * Accepts strings with optional 0x/0X prefix and separators(space, :, _, -).
 * @param {unknown} input
 * @returns {input is string}
 */
function isHexLike(input) {
  if (typeof input !== 'string') return false;
  const s = input.trim().replace(/^0x/i, '');
  return /[0-9a-fA-F]/.test(s) && /^[0-9a-fA-F\s:_-]+$/.test(s);
}

/**
 * Remove 0x prefix and all non-hex chars.
 * @param {string} hex
 * @returns {string}
 */
function cleanHex(hex) {
  return hex.replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '');
}

/**
 * Convert various inputs to a fixed-length byte array.
 * Supports hex string(with/without 0x), Uint8Array, Buffer, number[].
 *
 * The `number[]` path requires every element to be an integer in
 * [0, 255]; out-of-range or non-integer elements throw instead of being
 * silently coerced modulo 256 by `Uint8Array.from` (e.g. 256→0, -1→255,
 * 1.5→1 would all corrupt key/descriptor material undetected).
 *
 * @param {string|Uint8Array|Buffer|number[]} input
 * @param {number} expectedLen
 * @param {string} [label='bytes']
 * @returns {Uint8Array}
 */
function toFixedU8(input, expectedLen, label = 'bytes') {
  let bytes;
  if (isUint8(input)) {
    bytes = new Uint8Array(input);
  } else if (isHexLike(input)) {
    bytes = hexToBytes(cleanHex(input));
  } else if (Array.isArray(input)) {
    for (let i = 0; i < input.length; i += 1) {
      const v = input[i];
      if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 255) {
        throw new Error(`${label}: array element at index ${i} must be an integer in [0, 255], got ${String(v)}`);
      }
    }
    bytes = Uint8Array.from(input);
  } else {
    throw new Error(`${label}: unsupported input type; pass hex string or Uint8Array/Buffer`);
  }
  if (bytes.length !== expectedLen) {
    throw new Error(`${label}: expected ${expectedLen} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Wallet type enumeration.
 * @module wallet/common/wallettype
 */

/**
 * @readonly
 * @enum {number}
 */
const WalletType = Object.freeze({
  SPHINCSPLUS_256S: 0,
  ML_DSA_87: 1,
});

/**
 * @param {number} t
 * @return {boolean}
 */
function isValidWalletType(t) {
  return t === WalletType.ML_DSA_87;
}

/**
 * 3-byte descriptor for a wallet:
 *  - byte 0: wallet type (e.g. ML_DSA_87)
 *  - bytes 1..2: 2 bytes metadata — **reserved, must be zero**
 *
 * Non-zero metadata is rejected everywhere a descriptor enters the API,
 * matching go-qrllib's `Descriptor.IsValid` (bytes 1–2 must be 0).
 * Without this, one keypair could enroll under many sibling addresses,
 * and a non-zero-metadata wallet would be invalid to go-qrllib/rust-qrllib
 * nodes — i.e. potentially unspendable.
 * @module wallet/common/descriptor
 */


class Descriptor {
  /**
   * @param {Uint8Array|number[]} bytes Must be exactly 3 bytes.
   * @throws {Error} If size is not 3, wallet type is invalid, or the
   *   reserved metadata bytes (1–2) are non-zero.
   */
  constructor(bytes) {
    if (!bytes || bytes.length !== DESCRIPTOR_SIZE) {
      throw new Error(`Descriptor must be ${DESCRIPTOR_SIZE} bytes`);
    }
    /** @private @type {Uint8Array} */
    this.bytes = Uint8Array.from(bytes);
    if (!isValidWalletType(this.bytes[0])) {
      throw new Error('Invalid wallet type in descriptor');
    }
    if (this.bytes[1] !== 0 || this.bytes[2] !== 0) {
      throw new Error('Descriptor metadata bytes are reserved and must be zero');
    }
  }

  /**
   * @returns {number}
   */
  type() {
    return this.bytes[0] >>> 0;
  }

  /**
   * Copy of internal bytes.
   * @returns {Uint8Array}
   */
  toBytes() {
    return this.bytes.slice();
  }

  /**
   * Constructor: accepts hex string / Uint8Array / Buffer / number[].
   * @param {string|Uint8Array|Buffer|number[]} input
   * @returns {Descriptor}
   */
  static from(input) {
    return new Descriptor(toFixedU8(input, DESCRIPTOR_SIZE, 'Descriptor'));
  }
}

/**
 * Build descriptor bytes from parts.
 * @param {number} walletType byte.
 * @param {[number, number]} [metadata=[0,0]] Two metadata bytes — reserved,
 *   must both be zero (the parameter is kept for API compatibility).
 * @returns {Uint8Array} 3 bytes.
 * @throws {Error} If the wallet type is invalid or metadata is non-zero.
 */
function getDescriptorBytes(walletType, metadata = [0, 0]) {
  if (!isValidWalletType(walletType)) {
    throw new Error('Invalid wallet type in descriptor');
  }
  const m0 = metadata?.[0] ?? 0;
  const m1 = metadata?.[1] ?? 0;
  if (m0 !== 0 || m1 !== 0) {
    throw new Error('Descriptor metadata bytes are reserved and must be zero');
  }
  const out = new Uint8Array(DESCRIPTOR_SIZE);
  out[0] = walletType >>> 0;
  out[1] = 0;
  out[2] = 0;
  return out;
}

/**
 * Seed(48 bytes) and ExtendedSeed(51 bytes) with constructors.
 * @module wallet/common/seed
 */


class Seed {
  /**
   * @param {Uint8Array} bytes Exactly 48 bytes.
   * @throws {Error} If size mismatch.
   */
  constructor(bytes) {
    if (!bytes || bytes.length !== SEED_SIZE) {
      throw new Error(`Seed must be ${SEED_SIZE} bytes`);
    }
    this.bytes = Uint8Array.from(bytes);
    // Hide raw seed bytes from Object.keys / JSON.stringify / spread /
    // default util.inspect — defense-in-depth against accidental leakage.
    Object.defineProperty(this, 'bytes', { enumerable: false });
  }

  /** @returns {Uint8Array} */
  hashSHA256() {
    return Uint8Array.from(sha256(this.bytes));
  }

  /**
   * Copy of internal seed bytes.
   * @returns {Uint8Array}
   */
  toBytes() {
    return this.bytes.slice();
  }

  /**
   * Best-effort zeroize internal seed bytes.
   */
  zeroize() {
    this.bytes.fill(0);
  }

  /**
   * Redacted JSON shape used by `JSON.stringify`. Raw seed bytes are
   * never serialized; callers must explicitly call `toBytes()`.
   * @returns {{type: string, redacted: true}}
   */
  toJSON() {
    return { type: 'Seed', redacted: true };
  }

  /** @returns {string} */
  [Symbol.for('nodejs.util.inspect.custom')]() {
    return 'Seed { <redacted> }';
  }

  /**
   * Constructor: accepts hex string / Uint8Array / Buffer / number[].
   * @param {string|Uint8Array|Buffer|number[]} input
   * @returns {Seed}
   */
  static from(input) {
    return new Seed(toFixedU8(input, SEED_SIZE, 'Seed'));
  }
}

class ExtendedSeed {
  /**
   * Layout: [3 bytes descriptor] || [48 bytes seed].
   * @param {Uint8Array} bytes Exactly 51 bytes.
   * @throws {Error} If size mismatch, invalid wallet type, or non-zero
   *   reserved descriptor metadata bytes (1–2) — matching go-qrllib
   *   descriptor validation.
   */
  constructor(bytes) {
    if (!bytes || bytes.length !== EXTENDED_SEED_SIZE) {
      throw new Error(`ExtendedSeed must be ${EXTENDED_SEED_SIZE} bytes`);
    }
    /** @private @type {Uint8Array} */
    this.bytes = Uint8Array.from(bytes);
    if (!isValidWalletType(this.bytes[0])) {
      throw new Error('Invalid wallet type in descriptor');
    }
    if (this.bytes[1] !== 0 || this.bytes[2] !== 0) {
      throw new Error('Descriptor metadata bytes are reserved and must be zero');
    }
    // Hide raw extended-seed bytes from Object.keys / JSON.stringify /
    // spread / default util.inspect.
    Object.defineProperty(this, 'bytes', { enumerable: false });
  }

  /**
   * @returns {Descriptor}
   */
  getDescriptor() {
    return new Descriptor(this.getDescriptorBytes());
  }

  /**
   * @returns {Uint8Array} Descriptor(3 bytes).
   */
  getDescriptorBytes() {
    return this.bytes.slice(0, DESCRIPTOR_SIZE);
  }

  /**
   * @returns {Uint8Array} Seed bytes(48 bytes).
   */
  getSeedBytes() {
    return this.bytes.slice(DESCRIPTOR_SIZE);
  }

  /**
   * @returns {Seed}
   */
  getSeed() {
    return new Seed(this.getSeedBytes());
  }

  /**
   * Copy of internal seed bytes.
   * @returns {Uint8Array}
   */
  toBytes() {
    return this.bytes.slice();
  }

  /**
   * Build from components.
   * @param {Descriptor} desc
   * @param {Seed} seed
   * @returns {ExtendedSeed}
   */
  static newExtendedSeed(desc, seed) {
    const out = new Uint8Array(EXTENDED_SEED_SIZE);
    out.set(desc.toBytes(), 0);
    out.set(seed.toBytes(), DESCRIPTOR_SIZE);
    try {
      return new ExtendedSeed(out);
    } finally {
      out.fill(0);
    }
  }

  /**
   * Constructor: accepts hex string / Uint8Array / Buffer / number[].
   * @param {string|Uint8Array|Buffer|number[]} input
   * @returns {ExtendedSeed}
   */
  static from(input) {
    return new ExtendedSeed(toFixedU8(input, EXTENDED_SEED_SIZE, 'ExtendedSeed'));
  }

  /**
   * Best-effort zeroize internal extended seed bytes.
   */
  zeroize() {
    this.bytes.fill(0);
  }

  /**
   * Redacted JSON shape used by `JSON.stringify`. Raw bytes are never
   * serialized; callers must explicitly call `toBytes()`.
   * @returns {{type: string, redacted: true}}
   */
  toJSON() {
    return { type: 'ExtendedSeed', redacted: true };
  }

  /** @returns {string} */
  [Symbol.for('nodejs.util.inspect.custom')]() {
    return 'ExtendedSeed { <redacted> }';
  }
}

/**
 * Domain-separated signing-context construction.
 *
 * Wallet-level sign/verify bind every signature to its descriptor via a
 * fixed 8-byte context:
 *
 *   "ZOND" || SIGNING_CONTEXT_VERSION || descriptor  (4 + 1 + 3 = 8 bytes)
 *
 * ML-DSA-87 passes this as the FIPS 204 ctx parameter; SPHINCS+-256s
 * (if added later) prepends it to the message. Callers do not usually
 * need to construct the context themselves — wallet helpers do it
 * internally — but the helper is exported for parity with go-qrllib
 * and rust-qrllib and for advanced callers who sign outside the Wallet
 * class.
 *
 * Bumping SIGNING_CONTEXT_VERSION is a hard break of the signature wire
 * format: all signatures produced under a new version will fail to
 * verify under the old one. A version bump must coincide with a
 * coordinated consensus / library activation.
 *
 * @module wallet/common/context
 */


/** @type {number} Current signing-context format version. */
const SIGNING_CONTEXT_VERSION = 0x01;

/** @type {Uint8Array} Application-domain tag embedded in every context. */
const SIGNING_CONTEXT_PREFIX = new Uint8Array([0x5a, 0x4f, 0x4e, 0x44]); // "ZOND"

/** @type {number} Fixed on-wire length of a signing context (8 bytes). */
const SIGNING_CONTEXT_SIZE = SIGNING_CONTEXT_PREFIX.length + 1 + DESCRIPTOR_SIZE;

/**
 * Build the domain-separated bytes that bind a signature to its
 * descriptor: `"ZOND" || SIGNING_CONTEXT_VERSION || descriptor` (8 bytes).
 *
 * @param {Descriptor} descriptor
 * @returns {Uint8Array} exactly {@link SIGNING_CONTEXT_SIZE} bytes.
 * @throws {Error} if descriptor is not a Descriptor instance.
 */
function signingContext(descriptor) {
  if (!(descriptor instanceof Descriptor)) {
    throw new Error('descriptor must be a Descriptor instance');
  }
  const out = new Uint8Array(SIGNING_CONTEXT_SIZE);
  out.set(SIGNING_CONTEXT_PREFIX, 0);
  out[SIGNING_CONTEXT_PREFIX.length] = SIGNING_CONTEXT_VERSION;
  out.set(descriptor.toBytes(), SIGNING_CONTEXT_PREFIX.length + 1);
  return out;
}

/**
 * ML-DSA-87-specific descriptor helpers.
 * @module /wallet/ml_dsa_87/descriptor
 */


/**
 * New ML-DSA-87 descriptor with optional 2-byte metadata.
 * @param {[number, number]} [metadata=[0,0]]
 * @returns {Descriptor}
 */
function newMLDSA87Descriptor(metadata = [0, 0]) {
  return new Descriptor(getDescriptorBytes(WalletType.ML_DSA_87, metadata));
}

/**
 * Secure random number generation for browser and Node.js environments.
 * Requires Web Crypto API (globalThis.crypto.getRandomValues).
 * @module utils/random
 */

const MAX_BYTES = 65536;

function getWebCrypto() {
  if (typeof globalThis === 'object' && globalThis.crypto) return globalThis.crypto;
  return null;
}

/**
 * Generate cryptographically secure random bytes.
 *
 * Uses Web Crypto API (getRandomValues) exclusively.
 * Throws if Web Crypto API is unavailable.
 *
 * @param {number} size - Number of random bytes to generate
 * @returns {Uint8Array} Random bytes
 * @throws {RangeError} If size is invalid or too large
 * @throws {Error} If no secure random source is available or RNG output is suspect
 */
function randomBytes(size) {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('size must be a non-negative integer');
  }

  const cryptoObj = getWebCrypto();
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i += MAX_BYTES) {
      cryptoObj.getRandomValues(out.subarray(i, Math.min(size, i + MAX_BYTES)));
    }
    {
      let acc = 0;
      for (let i = 0; i < size; i++) acc |= out[i];
      if (acc === 0) throw new Error('getRandomValues returned all zeros');
    }
    return out;
  }

  throw new Error('Secure random number generation is not supported by this environment');
}

/**
 * Mnemonic word list used by encoding/decoding utilities.
 * @module qrl/wordlist
 */

/**
 * Ordered list of mnemonic words.
 * @readonly
 * @type {string[]}
 */
const WordList = [
  'aback',
  'abbey',
  'abbot',
  'abide',
  'ablaze',
  'able',
  'aboard',
  'abode',
  'abort',
  'abound',
  'about',
  'above',
  'abra',
  'abroad',
  'abrupt',
  'absent',
  'absorb',
  'absurd',
  'accent',
  'accept',
  'access',
  'accord',
  'accuse',
  'ace',
  'ache',
  'aching',
  'acid',
  'acidic',
  'acorn',
  'acre',
  'across',
  'act',
  'action',
  'active',
  'actor',
  'actual',
  'acute',
  'adam',
  'adapt',
  'add',
  'added',
  'adept',
  'adhere',
  'adjust',
  'admire',
  'admit',
  'adobe',
  'adopt',
  'adrift',
  'adverb',
  'advert',
  'aedes',
  'aerial',
  'afar',
  'affair',
  'affect',
  'afford',
  'afghan',
  'afield',
  'afloat',
  'afraid',
  'afresh',
  'after',
  'again',
  'age',
  'agency',
  'agenda',
  'agent',
  'aghast',
  'agile',
  'ago',
  'agony',
  'agree',
  'agreed',
  'aha',
  'ahead',
  'aid',
  'aide',
  'aim',
  'air',
  'airman',
  'airy',
  'akin',
  'alarm',
  'alaska',
  'albeit',
  'album',
  'alert',
  'alibi',
  'alice',
  'alien',
  'alight',
  'align',
  'alike',
  'alive',
  'alkali',
  'all',
  'allars',
  'allay',
  'alley',
  'allied',
  'allot',
  'allow',
  'alloy',
  'ally',
  'almond',
  'almost',
  'aloft',
  'alone',
  'along',
  'aloof',
  'aloud',
  'alpha',
  'alpine',
  'also',
  'altar',
  'alter',
  'always',
  'amaze',
  'amazon',
  'amber',
  'ambush',
  'amen',
  'amend',
  'amid',
  'amidst',
  'amiss',
  'among',
  'amount',
  'ample',
  'amuse',
  'anchor',
  'and',
  'andrew',
  'anew',
  'angel',
  'anger',
  'angle',
  'anglo',
  'angola',
  'animal',
  'ankle',
  'annoy',
  'annual',
  'answer',
  'anthem',
  'anti',
  'antony',
  'anubis',
  'any',
  'anyhow',
  'anyway',
  'apart',
  'apathy',
  'apex',
  'apiece',
  'appeal',
  'appear',
  'apple',
  'apply',
  'april',
  'apron',
  'arcade',
  'arcane',
  'arch',
  'arctic',
  'ardent',
  'are',
  'area',
  'argue',
  'arid',
  'arise',
  'arm',
  'armful',
  'armpit',
  'army',
  'aroma',
  'around',
  'arouse',
  'array',
  'arrest',
  'arrive',
  'arrow',
  'arson',
  'art',
  'artery',
  'artful',
  'artist',
  'ascent',
  'ashen',
  'ashore',
  'aside',
  'ask',
  'asleep',
  'aspect',
  'assay',
  'assent',
  'assert',
  'assess',
  'asset',
  'assign',
  'assist',
  'assume',
  'assure',
  'asthma',
  'astute',
  'asylum',
  'ate',
  'athens',
  'atlas',
  'atom',
  'atomic',
  'atop',
  'attach',
  'attain',
  'attend',
  'attic',
  'auburn',
  'audio',
  'audit',
  'augite',
  'august',
  'aunt',
  'auntie',
  'aura',
  'austin',
  'auteur',
  'author',
  'auto',
  'autumn',
  'avail',
  'avenge',
  'avenue',
  'avert',
  'avid',
  'avoid',
  'await',
  'awake',
  'awaken',
  'award',
  'aware',
  'awash',
  'away',
  'awful',
  'awhile',
  'axes',
  'axiom',
  'axis',
  'axle',
  'aye',
  'baby',
  'bach',
  'back',
  'backup',
  'bacon',
  'bad',
  'badge',
  'badly',
  'bag',
  'baggy',
  'bail',
  'bait',
  'bake',
  'baker',
  'bakery',
  'bald',
  'ball',
  'ballad',
  'ballet',
  'ballot',
  'baltic',
  'bamboo',
  'ban',
  'banal',
  'banana',
  'band',
  'banjo',
  'bank',
  'bar',
  'barber',
  'bare',
  'barely',
  'barge',
  'baric',
  'bark',
  'barley',
  'barn',
  'baron',
  'barrel',
  'barren',
  'basalt',
  'base',
  'basic',
  'basil',
  'basin',
  'basis',
  'basket',
  'basque',
  'bass',
  'bat',
  'batch',
  'bath',
  'bathe',
  'baton',
  'battle',
  'bay',
  'beach',
  'beacon',
  'beak',
  'beam',
  'bean',
  'bear',
  'beard',
  'beat',
  'beauty',
  'become',
  'bed',
  'beech',
  'beef',
  'beefy',
  'beep',
  'beer',
  'beet',
  'beetle',
  'before',
  'beggar',
  'begin',
  'behalf',
  'behave',
  'behind',
  'beige',
  'being',
  'belfry',
  'belief',
  'bell',
  'belly',
  'belong',
  'below',
  'belt',
  'bench',
  'bend',
  'bended',
  'benign',
  'bent',
  'berlin',
  'berry',
  'berth',
  'beset',
  'beside',
  'best',
  'bestow',
  'bet',
  'beta',
  'betray',
  'better',
  'betty',
  'beware',
  'beyond',
  'bias',
  'biceps',
  'bicker',
  'bid',
  'big',
  'bike',
  'bile',
  'bill',
  'binary',
  'bind',
  'biopsy',
  'birch',
  'bird',
  'birdie',
  'birth',
  'bishop',
  'bit',
  'bite',
  'bitter',
  'blade',
  'blame',
  'bland',
  'blaser',
  'blast',
  'blaze',
  'bleak',
  'blend',
  'bless',
  'blew',
  'blink',
  'blip',
  'bliss',
  'blitz',
  'block',
  'blond',
  'blood',
  'bloom',
  'blot',
  'blouse',
  'blue',
  'bluff',
  'blunt',
  'blur',
  'blush',
  'boar',
  'board',
  'boast',
  'boat',
  'bocage',
  'bodily',
  'body',
  'bogus',
  'boil',
  'bold',
  'bolt',
  'bombay',
  'bond',
  'bone',
  'bonn',
  'bonnet',
  'bonus',
  'bony',
  'book',
  'boost',
  'boot',
  'booth',
  'booze',
  'bop',
  'border',
  'bore',
  'borrow',
  'bosom',
  'boss',
  'boston',
  'both',
  'bother',
  'bottle',
  'bottom',
  'bought',
  'bounce',
  'bound',
  'bounty',
  'bout',
  'bovine',
  'bow',
  'bowel',
  'bowl',
  'box',
  'boy',
  'boyish',
  'brace',
  'brain',
  'brainy',
  'brake',
  'bran',
  'branch',
  'brand',
  'brandy',
  'brass',
  'brave',
  'bravo',
  'brazil',
  'breach',
  'bread',
  'break',
  'breath',
  'bred',
  'breed',
  'breeze',
  'brew',
  'brick',
  'bride',
  'bridge',
  'brief',
  'bright',
  'brim',
  'brine',
  'bring',
  'brink',
  'brisk',
  'briton',
  'broad',
  'broke',
  'broken',
  'bronze',
  'brook',
  'broom',
  'brown',
  'bruise',
  'brush',
  'brutal',
  'brute',
  'bubble',
  'buck',
  'bucket',
  'buckle',
  'buddha',
  'budget',
  'buen',
  'buffet',
  'buggy',
  'build',
  'bulb',
  'bulge',
  'bulk',
  'bulky',
  'bull',
  'bullet',
  'bully',
  'bump',
  'bumpy',
  'bunch',
  'bundle',
  'bunk',
  'bunny',
  'burden',
  'bureau',
  'burial',
  'burly',
  'burma',
  'burned',
  'burnt',
  'burrow',
  'burst',
  'bury',
  'bus',
  'bush',
  'bust',
  'bustle',
  'busy',
  'but',
  'butler',
  'butter',
  'button',
  'buy',
  'buyer',
  'buzz',
  'bye',
  'byte',
  'byways',
  'cab',
  'cabin',
  'cable',
  'cache',
  'cactus',
  'caesar',
  'cage',
  'cagey',
  'cahot',
  'cain',
  'cairo',
  'cake',
  'cakile',
  'calf',
  'call',
  'caller',
  'calm',
  'calmly',
  'came',
  'camel',
  'camera',
  'camp',
  'campus',
  'can',
  'canada',
  'canary',
  'cancel',
  'candid',
  'candle',
  'candy',
  'cane',
  'canine',
  'canna',
  'canoe',
  'canopy',
  'canvas',
  'canyon',
  'cap',
  'cape',
  'car',
  'carbon',
  'card',
  'care',
  'career',
  'caress',
  'cargo',
  'carl',
  'carnal',
  'carol',
  'carp',
  'carpet',
  'carrot',
  'carry',
  'cart',
  'cartel',
  'case',
  'cash',
  'cask',
  'cast',
  'castle',
  'casual',
  'cat',
  'catch',
  'cater',
  'cattle',
  'caught',
  'causal',
  'cause',
  'cave',
  'cease',
  'celery',
  'cell',
  'cellar',
  'celtic',
  'cement',
  'censor',
  'census',
  'cereal',
  'cervix',
  'chain',
  'chair',
  'chalet',
  'chalk',
  'chalky',
  'champ',
  'chance',
  'change',
  'chant',
  'chaos',
  'chap',
  'chapel',
  'charge',
  'charm',
  'chart',
  'chase',
  'chat',
  'cheap',
  'cheat',
  'check',
  'cheek',
  'cheeky',
  'cheer',
  'cheery',
  'cheese',
  'chef',
  'cherry',
  'chess',
  'chest',
  'chew',
  'chic',
  'chick',
  'chief',
  'child',
  'chile',
  'chill',
  'chilly',
  'china',
  'chip',
  'choice',
  'choir',
  'choose',
  'chop',
  'choppy',
  'chord',
  'chorus',
  'chose',
  'chosen',
  'choux',
  'chrome',
  'chunk',
  'chunky',
  'cider',
  'cigar',
  'cinema',
  'circa',
  'circle',
  'circus',
  'cite',
  'city',
  'civic',
  'civil',
  'clad',
  'claim',
  'clammy',
  'clan',
  'clap',
  'clash',
  'clasp',
  'class',
  'clause',
  'claw',
  'clay',
  'clean',
  'clear',
  'clergy',
  'clerk',
  'clever',
  'click',
  'client',
  'cliff',
  'climax',
  'climb',
  'clinch',
  'cling',
  'clinic',
  'clip',
  'cloak',
  'clock',
  'clone',
  'close',
  'closer',
  'closet',
  'cloth',
  'cloud',
  'cloudy',
  'clout',
  'clown',
  'club',
  'clue',
  'clumsy',
  'clung',
  'clutch',
  'coach',
  'coal',
  'coast',
  'coat',
  'coax',
  'cobalt',
  'cobble',
  'cobra',
  'coca',
  'cocoa',
  'code',
  'coffee',
  'coffin',
  'cohort',
  'coil',
  'coin',
  'coke',
  'cold',
  'collar',
  'colon',
  'colony',
  'colt',
  'column',
  'comb',
  'combat',
  'come',
  'comedy',
  'comes',
  'comic',
  'commit',
  'common',
  'compel',
  'comply',
  'concur',
  'cone',
  'confer',
  'congo',
  'consul',
  'convex',
  'convey',
  'convoy',
  'cook',
  'cool',
  'cope',
  'copper',
  'copy',
  'coral',
  'cord',
  'core',
  'cork',
  'corn',
  'corner',
  'corps',
  'corpse',
  'corpus',
  'cortex',
  'cosmic',
  'cosmos',
  'cost',
  'costia',
  'costly',
  'cosy',
  'cotton',
  'couch',
  'cough',
  'could',
  'count',
  'county',
  'coup',
  'couple',
  'coupon',
  'course',
  'court',
  'cousin',
  'cove',
  'cover',
  'covert',
  'cow',
  'coward',
  'cowboy',
  'crab',
  'cradle',
  'craft',
  'crafty',
  'crag',
  'crane',
  'crate',
  'crater',
  'crawl',
  'crazy',
  'creak',
  'cream',
  'create',
  'credit',
  'creed',
  'creek',
  'creep',
  'creepy',
  'creole',
  'crept',
  'crest',
  'crew',
  'cried',
  'crisis',
  'crisp',
  'critic',
  'croft',
  'crook',
  'crop',
  'cross',
  'crow',
  'crowd',
  'crown',
  'crude',
  'cruel',
  'cruise',
  'crunch',
  'crush',
  'crust',
  'crux',
  'cry',
  'crypt',
  'cuba',
  'cube',
  'cubic',
  'cuckoo',
  'cuff',
  'cult',
  'cup',
  'curb',
  'cure',
  'curfew',
  'curl',
  'curlew',
  'curry',
  'curse',
  'cursor',
  'curve',
  'custom',
  'cut',
  'cute',
  'cycle',
  'cyclic',
  'cynic',
  'cyprus',
  'czech',
  'dad',
  'daddy',
  'dagger',
  'daily',
  'dairy',
  'daisy',
  'dale',
  'dallas',
  'damage',
  'damp',
  'dampen',
  'dance',
  'danger',
  'daniel',
  'danish',
  'dare',
  'dark',
  'darken',
  'darwin',
  'dash',
  'data',
  'date',
  'david',
  'dawn',
  'day',
  'deadly',
  'deaf',
  'deal',
  'dealer',
  'dean',
  'dear',
  'debar',
  'debate',
  'debit',
  'debris',
  'debt',
  'debtor',
  'decade',
  'decay',
  'decent',
  'decide',
  'deck',
  'decor',
  'decree',
  'deduce',
  'deed',
  'deep',
  'deeply',
  'deer',
  'defeat',
  'defect',
  'defend',
  'defer',
  'define',
  'defy',
  'degree',
  'deity',
  'delay',
  'delete',
  'delhi',
  'delphi',
  'delta',
  'demand',
  'demise',
  'demo',
  'demure',
  'denial',
  'denote',
  'dense',
  'dental',
  'deny',
  'depart',
  'depend',
  'depict',
  'deploy',
  'depot',
  'depth',
  'deputy',
  'derby',
  'derive',
  'desert',
  'design',
  'desist',
  'desk',
  'detail',
  'detect',
  'deter',
  'detest',
  'detour',
  'device',
  'devise',
  'devoid',
  'devote',
  'devour',
  'dial',
  'diana',
  'diary',
  'dice',
  'dictum',
  'did',
  'diesel',
  'diet',
  'differ',
  'digest',
  'digit',
  'dine',
  'dinghy',
  'dingus',
  'dinner',
  'diode',
  'dire',
  'direct',
  'dirt',
  'disc',
  'disco',
  'dish',
  'disk',
  'dismal',
  'dispel',
  'ditch',
  'divert',
  'divide',
  'divine',
  'dizzy',
  'docile',
  'dock',
  'doctor',
  'dog',
  'dogger',
  'dogma',
  'dole',
  'doll',
  'dollar',
  'dolly',
  'domain',
  'dome',
  'domino',
  'donate',
  'done',
  'donkey',
  'donor',
  'door',
  'dorsal',
  'dose',
  'dote',
  'double',
  'doubt',
  'dough',
  'dour',
  'dove',
  'dower',
  'down',
  'dozen',
  'draft',
  'drag',
  'dragon',
  'drain',
  'drama',
  'drank',
  'draper',
  'draw',
  'drawer',
  'dread',
  'dream',
  'dreamy',
  'dreary',
  'dress',
  'drew',
  'dried',
  'drift',
  'drill',
  'drink',
  'drip',
  'drive',
  'driver',
  'drool',
  'drop',
  'drove',
  'drown',
  'drum',
  'dry',
  'dual',
  'dublin',
  'duck',
  'duct',
  'due',
  'duel',
  'duet',
  'duke',
  'dull',
  'duly',
  'dummy',
  'dump',
  'dune',
  'dung',
  'duress',
  'during',
  'dusk',
  'dust',
  'dusty',
  'dutch',
  'duty',
  'dwarf',
  'dwell',
  'dyer',
  'dying',
  'dynamo',
  'each',
  'eager',
  'eagle',
  'ear',
  'earl',
  'early',
  'earn',
  'earth',
  'ease',
  'easel',
  'easily',
  'east',
  'easter',
  'easy',
  'eat',
  'eaten',
  'eater',
  'echo',
  'eddy',
  'eden',
  'edge',
  'edible',
  'edict',
  'edit',
  'editor',
  'edward',
  'eerie',
  'eerily',
  'effect',
  'effort',
  'egg',
  'ego',
  'egypt',
  'eight',
  'eighth',
  'eighty',
  'either',
  'elbow',
  'elder',
  'eldest',
  'elect',
  'eleven',
  'elicit',
  'elite',
  'eloge',
  'else',
  'elude',
  'elves',
  'embark',
  'emblem',
  'embryo',
  'emerge',
  'emit',
  'empire',
  'employ',
  'empty',
  'enable',
  'enamel',
  'end',
  'endure',
  'energy',
  'engage',
  'engine',
  'enjoy',
  'enlist',
  'enough',
  'ensure',
  'entail',
  'enter',
  'entire',
  'entre',
  'entry',
  'envoy',
  'envy',
  'enzyme',
  'epic',
  'epoch',
  'equal',
  'equate',
  'equip',
  'equity',
  'era',
  'erase',
  'eric',
  'erode',
  'erotic',
  'errant',
  'error',
  'escape',
  'essay',
  'essex',
  'estate',
  'esteem',
  'ethic',
  'etoile',
  'eundo',
  'europe',
  'evade',
  'eve',
  'even',
  'event',
  'ever',
  'every',
  'evict',
  'evil',
  'evoke',
  'evolve',
  'exact',
  'exam',
  'exceed',
  'excel',
  'except',
  'excess',
  'excise',
  'excite',
  'excuse',
  'exempt',
  'exert',
  'exile',
  'exist',
  'exit',
  'exodus',
  'exotic',
  'expand',
  'expect',
  'expert',
  'expire',
  'export',
  'expose',
  'extend',
  'extra',
  'exulat',
  'eye',
  'eyed',
  'fabric',
  'face',
  'facer',
  'facial',
  'fact',
  'factor',
  'fade',
  'fail',
  'faint',
  'fair',
  'fairly',
  'fake',
  'falcon',
  'fall',
  'false',
  'falter',
  'fame',
  'family',
  'famine',
  'famous',
  'fan',
  'fancy',
  'far',
  'farce',
  'fare',
  'farm',
  'farmer',
  'fast',
  'fasten',
  'faster',
  'fatal',
  'fate',
  'father',
  'fatty',
  'fault',
  'faulty',
  'fauna',
  'feast',
  'feat',
  'fed',
  'fee',
  'feeble',
  'feed',
  'feel',
  'feels',
  'feet',
  'fell',
  'fellow',
  'felt',
  'female',
  'femur',
  'fence',
  'fend',
  'ferry',
  'fetal',
  'fetch',
  'feudal',
  'fever',
  'few',
  'fewer',
  'fiance',
  'fiasco',
  'fiddle',
  'field',
  'fiend',
  'fierce',
  'fiery',
  'fifth',
  'fifty',
  'fig',
  'figure',
  'file',
  'fill',
  'filled',
  'filler',
  'film',
  'filter',
  'filth',
  'filthy',
  'final',
  'finale',
  'find',
  'fine',
  'finish',
  'finite',
  'firm',
  'firmly',
  'first',
  'fiscal',
  'fish',
  'fisher',
  'fit',
  'fitful',
  'five',
  'fix',
  'flag',
  'flair',
  'flak',
  'flame',
  'flank',
  'flare',
  'flash',
  'flask',
  'flat',
  'flaw',
  'fled',
  'flee',
  'fleece',
  'fleet',
  'flesh',
  'fleshy',
  'flew',
  'flick',
  'flight',
  'flimsy',
  'flint',
  'flirt',
  'float',
  'flock',
  'floe',
  'flood',
  'floor',
  'floppy',
  'flora',
  'floral',
  'flour',
  'flow',
  'flower',
  'fluent',
  'fluffy',
  'fluid',
  'flung',
  'flurry',
  'flush',
  'flute',
  'flux',
  'fly',
  'flyer',
  'foal',
  'foam',
  'foamy',
  'focal',
  'focus',
  'fog',
  'foil',
  'foin',
  'fold',
  'folk',
  'follow',
  'folly',
  'fond',
  'fondly',
  'font',
  'food',
  'fool',
  'foot',
  'for',
  'forbid',
  'force',
  'ford',
  'forest',
  'forge',
  'forget',
  'fork',
  'form',
  'formal',
  'format',
  'former',
  'fort',
  'forth',
  'forty',
  'forum',
  'fossil',
  'foster',
  'foul',
  'found',
  'four',
  'fourth',
  'fox',
  'foyer',
  'frail',
  'frame',
  'franc',
  'france',
  'frank',
  'free',
  'freed',
  'freely',
  'freer',
  'freeze',
  'french',
  'frenzy',
  'fresh',
  'friar',
  'friday',
  'fridge',
  'fried',
  'friend',
  'fright',
  'fringe',
  'frock',
  'frog',
  'from',
  'front',
  'frost',
  'frosty',
  'frown',
  'frozen',
  'frugal',
  'fruit',
  'fruity',
  'fudge',
  'fuel',
  'fulfil',
  'full',
  'fully',
  'fun',
  'fund',
  'funny',
  'fur',
  'furry',
  'fury',
  'fuse',
  'fusion',
  'fuss',
  'fussy',
  'futile',
  'future',
  'fuzzy',
  'gadget',
  'gag',
  'gain',
  'gala',
  'galaxy',
  'gale',
  'gall',
  'galley',
  'gallon',
  'gallop',
  'gamble',
  'game',
  'gamma',
  'gandhi',
  'gap',
  'garage',
  'garden',
  'garlic',
  'gas',
  'gasp',
  'gate',
  'gather',
  'gaucho',
  'gauge',
  'gaul',
  'gaunt',
  'gave',
  'gaze',
  'gear',
  'geese',
  'gemini',
  'gender',
  'gene',
  'geneva',
  'genial',
  'genius',
  'genre',
  'gentle',
  'gently',
  'gentry',
  'genus',
  'george',
  'get',
  'ghetto',
  'ghost',
  'giant',
  'gift',
  'giggle',
  'gill',
  'gilt',
  'ginger',
  'girl',
  'give',
  'given',
  'glad',
  'glade',
  'glance',
  'gland',
  'glare',
  'glass',
  'glassy',
  'gleam',
  'glee',
  'glib',
  'glide',
  'global',
  'globe',
  'gloom',
  'gloomy',
  'gloria',
  'glory',
  'gloss',
  'glossy',
  'glove',
  'glow',
  'glue',
  'goal',
  'goat',
  'gold',
  'golden',
  'golf',
  'gone',
  'gong',
  'good',
  'goose',
  'gorge',
  'gory',
  'gosh',
  'gospel',
  'gossip',
  'got',
  'gothic',
  'govern',
  'gown',
  'grab',
  'grace',
  'grade',
  'grain',
  'grand',
  'grant',
  'grape',
  'graph',
  'grasp',
  'grass',
  'grassy',
  'grate',
  'grave',
  'gravel',
  'gravy',
  'gray',
  'grease',
  'greasy',
  'great',
  'greece',
  'greed',
  'greedy',
  'greek',
  'green',
  'greet',
  'grew',
  'grey',
  'grid',
  'grief',
  'grill',
  'grim',
  'grin',
  'grind',
  'grip',
  'grit',
  'gritty',
  'groan',
  'groin',
  'groom',
  'groove',
  'ground',
  'group',
  'grove',
  'grow',
  'grown',
  'growth',
  'grudge',
  'grunt',
  'guard',
  'guess',
  'guest',
  'guide',
  'guild',
  'guilt',
  'guilty',
  'guise',
  'guitar',
  'gulf',
  'gully',
  'gunman',
  'guru',
  'gut',
  'guy',
  'gypsy',
  'habit',
  'hack',
  'had',
  'hague',
  'hail',
  'hair',
  'hairy',
  'haiti',
  'hale',
  'half',
  'hall',
  'halt',
  'hamlet',
  'hammer',
  'hand',
  'handle',
  'handy',
  'hang',
  'hangar',
  'hanoi',
  'happen',
  'happy',
  'hard',
  'hardly',
  'hare',
  'harm',
  'harp',
  'harry',
  'harsh',
  'has',
  'hash',
  'hassle',
  'hasta',
  'haste',
  'hasten',
  'hasty',
  'hat',
  'hatch',
  'hate',
  'haul',
  'haunt',
  'havana',
  'have',
  'haven',
  'havoc',
  'hawaii',
  'hawk',
  'hawse',
  'hazard',
  'haze',
  'hazel',
  'hazy',
  'heal',
  'health',
  'heap',
  'hear',
  'heard',
  'heart',
  'hearth',
  'hearty',
  'heat',
  'heater',
  'heaven',
  'heavy',
  'hebrew',
  'heck',
  'hectic',
  'hedge',
  'heel',
  'hefty',
  'height',
  'heil',
  'heir',
  'held',
  'helium',
  'helix',
  'hello',
  'helm',
  'helmet',
  'help',
  'hemp',
  'hence',
  'henry',
  'her',
  'herald',
  'herb',
  'herd',
  'here',
  'hereby',
  'hermes',
  'hernia',
  'hero',
  'heroic',
  'hest',
  'hey',
  'heyday',
  'hick',
  'hidden',
  'hide',
  'high',
  'higher',
  'highly',
  'hill',
  'him',
  'hind',
  'hindu',
  'hint',
  'hippy',
  'hire',
  'his',
  'hiss',
  'hit',
  'hive',
  'hoard',
  'hoarse',
  'hobby',
  'hockey',
  'hold',
  'holder',
  'hollow',
  'holly',
  'holy',
  'home',
  'honest',
  'honey',
  'hood',
  'hope',
  'hopple',
  'horrid',
  'horror',
  'horse',
  'hose',
  'host',
  'hotbox',
  'hotel',
  'hound',
  'hour',
  'house',
  'hover',
  'how',
  'huck',
  'huge',
  'hull',
  'human',
  'humane',
  'humble',
  'humid',
  'hung',
  'hunger',
  'hungry',
  'hunt',
  'hurdle',
  'hurl',
  'hurry',
  'hurt',
  'hush',
  'hut',
  'hybrid',
  'hymn',
  'hyphen',
  'ice',
  'icing',
  'icon',
  'idaho',
  'idea',
  'ideal',
  'idiom',
  'idle',
  'idly',
  'idol',
  'ignite',
  'ignore',
  'ill',
  'image',
  'immune',
  'impact',
  'imply',
  'import',
  'impose',
  'inca',
  'inch',
  'income',
  'incur',
  'indeed',
  'index',
  'india',
  'indian',
  'indoor',
  'induce',
  'inept',
  'inert',
  'infant',
  'infect',
  'infer',
  'influx',
  'inform',
  'inhere',
  'inject',
  'injure',
  'injury',
  'ink',
  'inlaid',
  'inland',
  'inlet',
  'inmate',
  'inn',
  'innate',
  'inner',
  'input',
  'insane',
  'insect',
  'insert',
  'inset',
  'inside',
  'insist',
  'insult',
  'insure',
  'intact',
  'intake',
  'intend',
  'inter',
  'into',
  'invade',
  'invent',
  'invest',
  'invite',
  'invoke',
  'inward',
  'iowa',
  'iran',
  'iraq',
  'irish',
  'iron',
  'ironic',
  'irony',
  'isaac',
  'isabel',
  'islam',
  'island',
  'isle',
  'issue',
  'italy',
  'item',
  'itself',
  'ivan',
  'ivory',
  'ivy',
  'jacket',
  'jacob',
  'jaguar',
  'jail',
  'james',
  'japan',
  'jargon',
  'java',
  'jaw',
  'jazz',
  'jeep',
  'jelly',
  'jerky',
  'jersey',
  'jest',
  'jet',
  'jewel',
  'jim',
  'jive',
  'job',
  'jock',
  'jockey',
  'john',
  'join',
  'joke',
  'jolly',
  'jolt',
  'jordan',
  'joseph',
  'joy',
  'joyful',
  'joyous',
  'judas',
  'judge',
  'judy',
  'juice',
  'juicy',
  'july',
  'jumble',
  'jumbo',
  'jump',
  'june',
  'jungle',
  'junior',
  'junk',
  'junta',
  'jury',
  'just',
  'kami',
  'kansas',
  'karate',
  'karl',
  'karma',
  'kedge',
  'keel',
  'keen',
  'keep',
  'keeper',
  'kenya',
  'kept',
  'kernel',
  'kettle',
  'key',
  'khaki',
  'khaya',
  'khowar',
  'kick',
  'kidnap',
  'kidney',
  'kin',
  'kind',
  'kindly',
  'king',
  'kiss',
  'kite',
  'kitten',
  'knack',
  'knaggy',
  'knee',
  'knew',
  'knight',
  'knit',
  'knock',
  'knot',
  'know',
  'known',
  'koran',
  'korea',
  'kusan',
  'kuwait',
  'label',
  'lace',
  'lack',
  'lad',
  'ladder',
  'laden',
  'lady',
  'lagoon',
  'laity',
  'lake',
  'lamb',
  'lame',
  'lamp',
  'lance',
  'land',
  'lane',
  'laos',
  'lap',
  'lapse',
  'large',
  'larval',
  'laser',
  'last',
  'latch',
  'late',
  'lately',
  'latent',
  'later',
  'latest',
  'latter',
  'laugh',
  'launch',
  'lava',
  'lavish',
  'law',
  'lawful',
  'lawn',
  'laws',
  'lawyer',
  'lay',
  'layer',
  'layman',
  'lazy',
  'lead',
  'leader',
  'leaf',
  'leafy',
  'league',
  'leak',
  'leaky',
  'lean',
  'leap',
  'learn',
  'lease',
  'leash',
  'least',
  'leave',
  'led',
  'ledge',
  'left',
  'leg',
  'legacy',
  'legal',
  'legend',
  'legion',
  'lemon',
  'lend',
  'length',
  'lens',
  'lent',
  'leo',
  'leper',
  'lese',
  'lesion',
  'less',
  'lessen',
  'lesser',
  'lesson',
  'lest',
  'let',
  'lethal',
  'letter',
  'letup',
  'level',
  'lever',
  'levy',
  'lewis',
  'liable',
  'liar',
  'libel',
  'libya',
  'lice',
  'lick',
  'lid',
  'lie',
  'lied',
  'life',
  'lift',
  'light',
  'like',
  'likely',
  'lima',
  'limb',
  'lime',
  'limit',
  'limp',
  'line',
  'linear',
  'linen',
  'lineup',
  'linger',
  'link',
  'lion',
  'lip',
  'liquid',
  'lisbon',
  'list',
  'listen',
  'lit',
  'live',
  'lively',
  'liver',
  'livy',
  'liz',
  'lizard',
  'load',
  'loaf',
  'loan',
  'lobby',
  'lobe',
  'local',
  'locate',
  'lock',
  'locus',
  'lodge',
  'loft',
  'lofty',
  'log',
  'logic',
  'logo',
  'london',
  'lone',
  'lonely',
  'long',
  'longer',
  'look',
  'loop',
  'loose',
  'loosen',
  'loot',
  'lord',
  'lorry',
  'lose',
  'loss',
  'lost',
  'lot',
  'lotus',
  'loud',
  'loudly',
  'lounge',
  'lousy',
  'louvre',
  'love',
  'lovely',
  'lover',
  'low',
  'lower',
  'lowest',
  'loyal',
  'lucid',
  'luck',
  'lucky',
  'lucy',
  'lukes',
  'lull',
  'lump',
  'lumpy',
  'lunacy',
  'lunar',
  'lunch',
  'lung',
  'lure',
  'lurid',
  'lush',
  'lusory',
  'lute',
  'luther',
  'luxury',
  'lying',
  'lymph',
  'lyric',
  'macho',
  'macro',
  'macte',
  'madam',
  'madame',
  'made',
  'madrid',
  'magic',
  'magma',
  'magnet',
  'magnum',
  'maid',
  'maiden',
  'mail',
  'main',
  'mainly',
  'major',
  'make',
  'maker',
  'male',
  'malice',
  'mall',
  'malt',
  'malta',
  'mammal',
  'manage',
  'mane',
  'mania',
  'manic',
  'manila',
  'manner',
  'manor',
  'mantle',
  'manual',
  'manure',
  'many',
  'map',
  'maple',
  'marble',
  'march',
  'mare',
  'margin',
  'maria',
  'marina',
  'mark',
  'market',
  'marry',
  'mars',
  'marsh',
  'martin',
  'martyr',
  'mary',
  'mask',
  'mason',
  'mass',
  'mast',
  'match',
  'mate',
  'matrix',
  'matter',
  'mature',
  'maxim',
  'may',
  'maya',
  'maybe',
  'mayor',
  'maze',
  'mead',
  'meadow',
  'meal',
  'mean',
  'meant',
  'meat',
  'mecca',
  'medal',
  'media',
  'median',
  'medic',
  'medium',
  'meet',
  'mellow',
  'melody',
  'melon',
  'melt',
  'member',
  'memo',
  'memory',
  'menace',
  'mend',
  'mental',
  'mentor',
  'menu',
  'mercy',
  'mere',
  'merely',
  'merge',
  'merger',
  'merit',
  'merry',
  'mesh',
  'mess',
  'messy',
  'met',
  'metal',
  'meter',
  'method',
  'methyl',
  'metric',
  'metro',
  'mexico',
  'miami',
  'mickey',
  'mid',
  'midas',
  'midday',
  'middle',
  'midst',
  'midway',
  'might',
  'mighty',
  'milan',
  'mild',
  'mildew',
  'mile',
  'milk',
  'milky',
  'mill',
  'mimic',
  'mince',
  'mind',
  'mine',
  'mini',
  'mink',
  'minor',
  'mint',
  'minus',
  'minute',
  'mirror',
  'mirth',
  'misery',
  'miss',
  'mist',
  'misty',
  'mite',
  'mix',
  'mizzle',
  'moan',
  'moat',
  'mobile',
  'mock',
  'mode',
  'model',
  'modem',
  'modern',
  'modest',
  'modify',
  'module',
  'moist',
  'molar',
  'mole',
  'molten',
  'moment',
  'monaco',
  'monday',
  'money',
  'monies',
  'monk',
  'monkey',
  'month',
  'mood',
  'moody',
  'moon',
  'moor',
  'moral',
  'morale',
  'morbid',
  'more',
  'morgue',
  'mortal',
  'mortar',
  'mosaic',
  'moscow',
  'moses',
  'mosque',
  'moss',
  'most',
  'mostly',
  'moth',
  'mother',
  'motion',
  'motive',
  'motor',
  'mould',
  'mount',
  'mourn',
  'mouse',
  'mouth',
  'move',
  'movie',
  'mrs',
  'much',
  'muck',
  'mucky',
  'mucus',
  'mud',
  'muddle',
  'muddy',
  'mule',
  'mummy',
  'munich',
  'murky',
  'murmur',
  'muscle',
  'museum',
  'music',
  'mussel',
  'must',
  'mutant',
  'mute',
  'mutiny',
  'mutter',
  'mutton',
  'mutual',
  'muzzle',
  'myopic',
  'myriad',
  'myself',
  'mystic',
  'myth',
  'nadir',
  'nail',
  'name',
  'namely',
  'nape',
  'napkin',
  'naples',
  'narrow',
  'nasal',
  'nation',
  'native',
  'nature',
  'nausea',
  'naval',
  'nave',
  'navy',
  'near',
  'nearer',
  'nearly',
  'neat',
  'neatly',
  'neck',
  'need',
  'needle',
  'needy',
  'negate',
  'nemo',
  'neon',
  'nepal',
  'nephew',
  'nerve',
  'nest',
  'neural',
  'never',
  'newark',
  'newly',
  'next',
  'nice',
  'nicely',
  'niche',
  'nickel',
  'nidor',
  'niece',
  'night',
  'nile',
  'nimble',
  'nine',
  'ninety',
  'ninth',
  'nobel',
  'noble',
  'nobody',
  'node',
  'noise',
  'noisy',
  'non',
  'none',
  'noon',
  'nor',
  'norm',
  'normal',
  'north',
  'norway',
  'nose',
  'nostoc',
  'nosy',
  'not',
  'note',
  'notice',
  'notify',
  'notion',
  'nought',
  'noun',
  'novel',
  'novice',
  'now',
  'nozzle',
  'nubere',
  'null',
  'numb',
  'number',
  'nurse',
  'nylon',
  'oak',
  'oasis',
  'oath',
  'obese',
  'obey',
  'object',
  'oblige',
  'oboe',
  'obtain',
  'occult',
  'occupy',
  'occur',
  'ocean',
  'octave',
  'odd',
  'off',
  'offend',
  'offer',
  'office',
  'offset',
  'often',
  'ohio',
  'oil',
  'oily',
  'okay',
  'old',
  'older',
  'oldest',
  'olive',
  'omega',
  'omen',
  'omit',
  'once',
  'one',
  'onion',
  'only',
  'onset',
  'onto',
  'onus',
  'onward',
  'opaque',
  'open',
  'openly',
  'opera',
  'opium',
  'oppose',
  'optic',
  'option',
  'oracle',
  'orange',
  'orbit',
  'orchid',
  'orchil',
  'ordeal',
  'order',
  'organ',
  'orient',
  'origin',
  'ornate',
  'orphan',
  'oscar',
  'oslo',
  'other',
  'otter',
  'ought',
  'ounce',
  'our',
  'out',
  'outer',
  'output',
  'outset',
  'oval',
  'oven',
  'over',
  'overt',
  'owe',
  'owing',
  'owl',
  'own',
  'owner',
  'oxford',
  'oxide',
  'oxygen',
  'oyster',
  'ozone',
  'pace',
  'pack',
  'packet',
  'pact',
  'paddle',
  'paddy',
  'pagan',
  'page',
  'paid',
  'pain',
  'paint',
  'pair',
  'palace',
  'pale',
  'palm',
  'panama',
  'panel',
  'panic',
  'papa',
  'papal',
  'paper',
  'parade',
  'parcel',
  'pardon',
  'parent',
  'paris',
  'parish',
  'park',
  'parody',
  'parrot',
  'part',
  'partly',
  'party',
  'pascal',
  'pass',
  'past',
  'paste',
  'pastel',
  'pastor',
  'pastry',
  'pat',
  'patch',
  'patent',
  'path',
  'patio',
  'patrol',
  'patron',
  'paul',
  'pause',
  'pave',
  'pay',
  'peace',
  'peach',
  'peak',
  'pear',
  'pearl',
  'pedal',
  'peel',
  'peer',
  'peking',
  'pelvic',
  'pelvis',
  'pen',
  'penal',
  'pence',
  'pencil',
  'pennon',
  'penny',
  'people',
  'pepper',
  'per',
  'perch',
  'peril',
  'perish',
  'permit',
  'person',
  'peru',
  'pest',
  'peter',
  'petrol',
  'petty',
  'phage',
  'phase',
  'philip',
  'phone',
  'photo',
  'phrase',
  'piano',
  'pick',
  'picket',
  'picnic',
  'pie',
  'piece',
  'pier',
  'pierce',
  'piety',
  'pig',
  'pigeon',
  'piggy',
  'pigsty',
  'pike',
  'pile',
  'pill',
  'pillar',
  'pillow',
  'pilot',
  'pin',
  'pinch',
  'pine',
  'pink',
  'pint',
  'pious',
  'pipe',
  'pirate',
  'piston',
  'pit',
  'pitch',
  'pity',
  'pivot',
  'pixel',
  'pizza',
  'place',
  'placid',
  'plague',
  'plaguy',
  'plain',
  'plan',
  'plane',
  'planet',
  'plank',
  'plant',
  'plasma',
  'plate',
  'play',
  'playa',
  'player',
  'plea',
  'plead',
  'please',
  'pledge',
  'plenty',
  'plenum',
  'plight',
  'plot',
  'ploy',
  'plum',
  'plump',
  'plunge',
  'plural',
  'plus',
  'plush',
  'pocket',
  'pod',
  'poem',
  'poet',
  'poetic',
  'poetry',
  'point',
  'poison',
  'poland',
  'polar',
  'pole',
  'police',
  'policy',
  'polish',
  'polite',
  'poll',
  'pollen',
  'polo',
  'pond',
  'ponder',
  'pony',
  'pool',
  'poor',
  'poorly',
  'pop',
  'pope',
  'popery',
  'poppy',
  'pore',
  'pork',
  'port',
  'portal',
  'pose',
  'posh',
  'post',
  'postal',
  'potato',
  'potent',
  'pouch',
  'pound',
  'pour',
  'powder',
  'power',
  'prague',
  'praise',
  'prate',
  'pray',
  'prayer',
  'preach',
  'prefer',
  'prefix',
  'press',
  'pretty',
  'price',
  'pride',
  'priest',
  'primal',
  'prime',
  'prince',
  'print',
  'prior',
  'prism',
  'prison',
  'privy',
  'prize',
  'probe',
  'profit',
  'prompt',
  'prone',
  'proof',
  'propel',
  'proper',
  'prose',
  'proton',
  'proud',
  'prove',
  'proven',
  'proxy',
  'prune',
  'psalm',
  'pseudo',
  'psyche',
  'pub',
  'public',
  'puff',
  'pull',
  'pulp',
  'pulpit',
  'pulsar',
  'pulse',
  'pump',
  'punch',
  'pung',
  'punish',
  'punk',
  'pupil',
  'puppet',
  'puppy',
  'pure',
  'purely',
  'purge',
  'purify',
  'purple',
  'purse',
  'pursue',
  'push',
  'pushy',
  'put',
  'putt',
  'puzzle',
  'quaint',
  'quake',
  'quarry',
  'quartz',
  'quay',
  'quebec',
  'queen',
  'query',
  'quest',
  'queue',
  'quick',
  'quid',
  'quiet',
  'quilt',
  'quirk',
  'quit',
  'quite',
  'quiver',
  'quiz',
  'quota',
  'quote',
  'rabato',
  'rabbit',
  'race',
  'racism',
  'rack',
  'racket',
  'radar',
  'radio',
  'radish',
  'radius',
  'raffle',
  'raft',
  'rage',
  'raid',
  'rail',
  'rain',
  'rainy',
  'raise',
  'rally',
  'ramp',
  'random',
  'range',
  'rank',
  'ransom',
  'rapid',
  'rare',
  'rarely',
  'rarity',
  'rash',
  'rat',
  'rate',
  'rather',
  'ratify',
  'ratio',
  'rattle',
  'rave',
  'raven',
  'raw',
  'ray',
  'razor',
  'reach',
  'react',
  'read',
  'reader',
  'ready',
  'real',
  'really',
  'realm',
  'reap',
  'rear',
  'reason',
  'rebel',
  'recall',
  'recent',
  'recess',
  'recipe',
  'reckon',
  'record',
  'recoup',
  'rector',
  'red',
  'redeem',
  'reduce',
  'reed',
  'reef',
  'reefy',
  'refer',
  'reform',
  'refuge',
  'refuse',
  'regal',
  'regard',
  'regent',
  'regime',
  'region',
  'regret',
  'reign',
  'relate',
  'relax',
  'relay',
  'relic',
  'relief',
  'relish',
  'rely',
  'remain',
  'remark',
  'remedy',
  'remind',
  'remit',
  'remote',
  'remove',
  'renal',
  'render',
  'rent',
  'rental',
  'repair',
  'repeal',
  'repeat',
  'repent',
  'repine',
  'reply',
  'report',
  'rescue',
  'resent',
  'reside',
  'resign',
  'resin',
  'resist',
  'resort',
  'rest',
  'result',
  'resume',
  'retail',
  'retain',
  'retina',
  'retire',
  'return',
  'reveal',
  'revest',
  'review',
  'revise',
  'revive',
  'revolt',
  'reward',
  'rex',
  'rhexia',
  'rhine',
  'rhino',
  'rho',
  'rhyme',
  'rhythm',
  'ribbon',
  'rice',
  'rich',
  'rick',
  'rid',
  'ride',
  'rider',
  'ridge',
  'rife',
  'rifle',
  'rift',
  'right',
  'rigid',
  'ring',
  'rinse',
  'riot',
  'ripe',
  'ripen',
  'ripple',
  'rise',
  'risk',
  'risky',
  'rite',
  'ritual',
  'ritz',
  'rival',
  'river',
  'road',
  'roar',
  'roast',
  'rob',
  'robe',
  'robert',
  'robin',
  'robot',
  'robust',
  'rock',
  'rocket',
  'rocks',
  'rocky',
  'rod',
  'rode',
  'rodent',
  'rogue',
  'role',
  'roll',
  'roman',
  'rome',
  'roof',
  'room',
  'root',
  'rope',
  'rosa',
  'rose',
  'roseau',
  'rosy',
  'rotate',
  'rotor',
  'rotten',
  'rouge',
  'rough',
  'round',
  'route',
  'rover',
  'row',
  'royal',
  'rubble',
  'ruby',
  'rudder',
  'rude',
  'rugby',
  'ruin',
  'rule',
  'ruler',
  'rumble',
  'run',
  'rune',
  'rung',
  'runway',
  'rural',
  'rush',
  'russia',
  'rust',
  'rustic',
  'rusty',
  'ruta',
  'sabe',
  'saber',
  'sack',
  'sacred',
  'sad',
  'saddle',
  'sadism',
  'sadly',
  'safari',
  'safe',
  'safely',
  'safer',
  'safety',
  'saga',
  'sage',
  'sahara',
  'said',
  'sail',
  'sailor',
  'saint',
  'sake',
  'salad',
  'salary',
  'sale',
  'saline',
  'saliva',
  'salmon',
  'saloon',
  'salt',
  'salty',
  'salute',
  'sam',
  'same',
  'sample',
  'sand',
  'sandy',
  'sane',
  'sarong',
  'sash',
  'satin',
  'satire',
  'saturn',
  'sauce',
  'saudi',
  'sauna',
  'savage',
  'save',
  'saxon',
  'say',
  'scale',
  'scalp',
  'scan',
  'scant',
  'scar',
  'scarce',
  'scare',
  'scarf',
  'scary',
  'scene',
  'scenic',
  'scent',
  'school',
  'scope',
  'score',
  'scorn',
  'scot',
  'scotch',
  'scout',
  'scrap',
  'scream',
  'screen',
  'script',
  'scroll',
  'scrub',
  'scute',
  'sea',
  'seal',
  'seam',
  'seaman',
  'search',
  'season',
  'seat',
  'second',
  'secret',
  'sect',
  'sector',
  'secure',
  'see',
  'seed',
  'seeing',
  'seek',
  'seem',
  'seize',
  'seldom',
  'select',
  'self',
  'sell',
  'seller',
  'semi',
  'senate',
  'send',
  'senile',
  'senior',
  'sense',
  'sensor',
  'sent',
  'sentry',
  'seoul',
  'sequel',
  'serene',
  'serial',
  'series',
  'sermon',
  'serum',
  'serve',
  'server',
  'set',
  'settle',
  'seven',
  'severe',
  'sewage',
  'shabby',
  'shade',
  'shadow',
  'shady',
  'shaft',
  'shaggy',
  'shah',
  'shake',
  'shaky',
  'shall',
  'sham',
  'shame',
  'shanks',
  'shape',
  'share',
  'shark',
  'sharp',
  'shawl',
  'she',
  'shear',
  'sheen',
  'sheep',
  'sheer',
  'sheet',
  'shelf',
  'shell',
  'sherry',
  'shield',
  'shift',
  'shine',
  'shiny',
  'ship',
  'shire',
  'shirt',
  'shiver',
  'shock',
  'shoe',
  'shook',
  'shop',
  'shore',
  'short',
  'shot',
  'should',
  'shout',
  'show',
  'shower',
  'shrank',
  'shrewd',
  'shrill',
  'shrimp',
  'shrine',
  'shrink',
  'shrub',
  'shrug',
  'shuha',
  'shut',
  'shy',
  'shyly',
  'side',
  'sided',
  'siege',
  'sigh',
  'sight',
  'sigma',
  'sign',
  'signal',
  'silent',
  'silk',
  'silken',
  'silky',
  'sill',
  'silly',
  'silver',
  'simian',
  'simple',
  'simply',
  'since',
  'sinful',
  'sing',
  'singer',
  'single',
  'sink',
  'sir',
  'siren',
  'sirius',
  'sister',
  'sit',
  'site',
  'six',
  'sixth',
  'sixty',
  'size',
  'sketch',
  'skill',
  'skin',
  'skinny',
  'skip',
  'skirt',
  'skull',
  'sky',
  'slab',
  'slabby',
  'slack',
  'slain',
  'slam',
  'slang',
  'slap',
  'slate',
  'slater',
  'sleek',
  'sleep',
  'sleepy',
  'sleeve',
  'slice',
  'slick',
  'slid',
  'slide',
  'slight',
  'slim',
  'slimy',
  'sling',
  'slip',
  'slit',
  'slogan',
  'slope',
  'sloppy',
  'slot',
  'slow',
  'slowly',
  'slug',
  'slum',
  'slump',
  'small',
  'smart',
  'smash',
  'smear',
  'smell',
  'smelly',
  'smelt',
  'smile',
  'smite',
  'smoke',
  'smoky',
  'smooth',
  'smug',
  'snack',
  'snail',
  'snake',
  'snap',
  'sneak',
  'snow',
  'snowy',
  'snug',
  'soak',
  'soap',
  'sober',
  'soccer',
  'social',
  'sock',
  'socket',
  'soda',
  'sodden',
  'sodium',
  'sofa',
  'soft',
  'soften',
  'softly',
  'soggy',
  'soil',
  'solar',
  'sold',
  'sole',
  'solely',
  'solemn',
  'solid',
  'solo',
  'solve',
  'somali',
  'some',
  'son',
  'sonar',
  'sonata',
  'song',
  'sonic',
  'sony',
  'soon',
  'sooner',
  'soot',
  'soothe',
  'sordid',
  'sore',
  'sorrow',
  'sorry',
  'sort',
  'soul',
  'sound',
  'soup',
  'sour',
  'source',
  'space',
  'spade',
  'spain',
  'span',
  'spare',
  'spark',
  'sparse',
  'spasm',
  'spat',
  'spate',
  'speak',
  'spear',
  'speech',
  'speed',
  'speedy',
  'spell',
  'spend',
  'sphere',
  'spice',
  'spicy',
  'spider',
  'spiky',
  'spill',
  'spin',
  'spinal',
  'spine',
  'spinus',
  'spiral',
  'spirit',
  'spite',
  'splash',
  'split',
  'spoil',
  'spoke',
  'sponge',
  'spoon',
  'sport',
  'spot',
  'spouse',
  'spout',
  'spray',
  'spread',
  'spree',
  'spring',
  'sprint',
  'spur',
  'squad',
  'square',
  'squash',
  'squat',
  'squid',
  'stab',
  'stable',
  'stack',
  'staff',
  'stage',
  'stain',
  'stair',
  'stake',
  'stale',
  'stalin',
  'stall',
  'stamp',
  'stance',
  'stand',
  'staple',
  'star',
  'starch',
  'stare',
  'stark',
  'start',
  'starve',
  'state',
  'static',
  'statue',
  'status',
  'stay',
  'stead',
  'steady',
  'steak',
  'steal',
  'steam',
  'steel',
  'steep',
  'steer',
  'stem',
  'stench',
  'step',
  'steppe',
  'stereo',
  'stern',
  'stew',
  'stick',
  'sticky',
  'stiff',
  'stifle',
  'stigma',
  'still',
  'sting',
  'stint',
  'stir',
  'stitch',
  'stock',
  'stocky',
  'stone',
  'stony',
  'stool',
  'stop',
  'store',
  'storm',
  'stormy',
  'story',
  'stot',
  'stout',
  'stove',
  'strain',
  'strait',
  'strand',
  'strap',
  'strata',
  'straw',
  'stray',
  'streak',
  'stream',
  'street',
  'stress',
  'strict',
  'stride',
  'strife',
  'strike',
  'string',
  'strip',
  'strive',
  'stroll',
  'strong',
  'stud',
  'studio',
  'study',
  'stuff',
  'stuffy',
  'stunt',
  'sturdy',
  'style',
  'submit',
  'subset',
  'subtle',
  'subtly',
  'suburb',
  'such',
  'sudan',
  'sudden',
  'sue',
  'suez',
  'suffer',
  'sugar',
  'suit',
  'suite',
  'suitor',
  'sullen',
  'sultan',
  'sum',
  'summer',
  'summit',
  'summon',
  'sun',
  'sunday',
  'sunny',
  'sunset',
  'super',
  'superb',
  'supper',
  'supple',
  'supply',
  'sure',
  'surely',
  'surf',
  'surge',
  'survey',
  'suture',
  'swamp',
  'swan',
  'swap',
  'swarm',
  'sway',
  'swear',
  'sweat',
  'sweaty',
  'sweden',
  'sweep',
  'sweet',
  'swell',
  'swift',
  'swim',
  'swine',
  'swing',
  'swirl',
  'swiss',
  'switch',
  'sword',
  'swore',
  'sydney',
  'symbol',
  'synod',
  'syntax',
  'syria',
  'syrup',
  'system',
  'table',
  'tablet',
  'tace',
  'tacit',
  'tackle',
  'tact',
  'tactic',
  'tail',
  'tailor',
  'taiwan',
  'take',
  'tale',
  'talent',
  'talk',
  'tall',
  'tally',
  'tame',
  'tandem',
  'tangle',
  'tank',
  'tap',
  'tape',
  'target',
  'tariff',
  'tart',
  'tarzan',
  'task',
  'tasset',
  'taste',
  'tasty',
  'tattoo',
  'taurus',
  'taut',
  'tavern',
  'tax',
  'taxi',
  'tea',
  'teach',
  'teak',
  'team',
  'tear',
  'tease',
  'tech',
  'tecum',
  'teeth',
  'tehran',
  'tel',
  'tell',
  'temper',
  'temple',
  'tempo',
  'tempt',
  'ten',
  'tenant',
  'tend',
  'tender',
  'tendon',
  'tenet',
  'tennis',
  'tenor',
  'tense',
  'tensor',
  'tent',
  'tenth',
  'tenure',
  'tera',
  'teresa',
  'term',
  'test',
  'texas',
  'text',
  'than',
  'thank',
  'that',
  'the',
  'their',
  'them',
  'theme',
  'then',
  'thence',
  'theory',
  'there',
  'these',
  'thesis',
  'they',
  'thick',
  'thief',
  'thigh',
  'thin',
  'thing',
  'think',
  'third',
  'thirst',
  'thirty',
  'this',
  'thomas',
  'thorn',
  'those',
  'though',
  'thread',
  'threat',
  'three',
  'thrill',
  'thrive',
  'throat',
  'throne',
  'throng',
  'throw',
  'thrust',
  'thud',
  'thug',
  'thumb',
  'thump',
  'thus',
  'thyme',
  'tibet',
  'tick',
  'ticket',
  'tidal',
  'tide',
  'tidy',
  'tie',
  'tier',
  'tiger',
  'tight',
  'tile',
  'tiling',
  'till',
  'tilt',
  'timber',
  'time',
  'timid',
  'tin',
  'tiny',
  'tip',
  'tissue',
  'title',
  'toad',
  'toast',
  'today',
  'token',
  'tokyo',
  'told',
  'toll',
  'tom',
  'tomato',
  'tomb',
  'tonal',
  'tone',
  'tonic',
  'too',
  'took',
  'tool',
  'tooth',
  'top',
  'topaz',
  'tophet',
  'topic',
  'torch',
  'torque',
  'torso',
  'tort',
  'toss',
  'total',
  'totem',
  'touch',
  'tough',
  'tour',
  'toward',
  'towel',
  'tower',
  'town',
  'toxic',
  'toxin',
  'trace',
  'track',
  'tract',
  'trade',
  'tragic',
  'trail',
  'train',
  'trait',
  'tram',
  'trance',
  'trap',
  'trauma',
  'travel',
  'tray',
  'tread',
  'treat',
  'treaty',
  'treble',
  'tree',
  'trek',
  'tremor',
  'trench',
  'trend',
  'trendy',
  'trial',
  'tribal',
  'tribe',
  'trick',
  'tricky',
  'tried',
  'trifle',
  'trim',
  'trio',
  'trip',
  'triple',
  'troop',
  'trophy',
  'trot',
  'trough',
  'trout',
  'truce',
  'truck',
  'true',
  'truly',
  'trunk',
  'trust',
  'truth',
  'try',
  'tsar',
  'tube',
  'tulle',
  'tumble',
  'tuna',
  'tundra',
  'tune',
  'tung',
  'tunic',
  'tunis',
  'tunnel',
  'turban',
  'turf',
  'turk',
  'turkey',
  'turn',
  'turtle',
  'tutor',
  'tweed',
  'twelve',
  'twenty',
  'twice',
  'twin',
  'twist',
  'two',
  'tycoon',
  'tying',
  'type',
  'tyrant',
  'uganda',
  'ugly',
  'ulcer',
  'ultra',
  'umpire',
  'unable',
  'uncle',
  'under',
  'uneasy',
  'unfair',
  'unify',
  'union',
  'unique',
  'unit',
  'unite',
  'unity',
  'unkind',
  'unlike',
  'unrest',
  'unruly',
  'unship',
  'until',
  'unwary',
  'update',
  'upheld',
  'uphill',
  'uphold',
  'upon',
  'uproar',
  'upset',
  'upshot',
  'uptake',
  'upturn',
  'upward',
  'urban',
  'urge',
  'urgent',
  'urging',
  'usable',
  'usage',
  'use',
  'useful',
  'user',
  'usual',
  'utmost',
  'utter',
  'vacant',
  'vacuum',
  'vague',
  'vain',
  'valet',
  'valid',
  'valley',
  'value',
  'valve',
  'van',
  'vanish',
  'vanity',
  'vary',
  'vase',
  'vast',
  'vat',
  'vault',
  'vector',
  'vedic',
  'veil',
  'vein',
  'velvet',
  'vendor',
  'veneer',
  'venice',
  'venom',
  'vent',
  'venue',
  'venus',
  'verb',
  'verbal',
  'verge',
  'verify',
  'verity',
  'verse',
  'versus',
  'very',
  'vessel',
  'vest',
  'veto',
  'vex',
  'via',
  'viable',
  'vicar',
  'vice',
  'victim',
  'victor',
  'video',
  'vienna',
  'view',
  'vigil',
  'vigor',
  'viking',
  'vile',
  'villa',
  'vine',
  'vinyl',
  'viola',
  'violet',
  'violin',
  'viral',
  'virgo',
  'virtue',
  'virus',
  'visa',
  'vision',
  'visit',
  'visual',
  'vitae',
  'vital',
  'vivid',
  'vocal',
  'vodka',
  'vogue',
  'voice',
  'void',
  'volley',
  'volume',
  'vote',
  'vowel',
  'voyage',
  'vulgar',
  'wade',
  'wage',
  'waist',
  'wait',
  'waiter',
  'wake',
  'walk',
  'walker',
  'wall',
  'wallet',
  'walnut',
  'wander',
  'want',
  'war',
  'warden',
  'warm',
  'warmth',
  'warn',
  'warp',
  'warsaw',
  'wary',
  'was',
  'wash',
  'wasp',
  'waste',
  'watch',
  'water',
  'watery',
  'wave',
  'way',
  'weak',
  'weaken',
  'wealth',
  'wear',
  'weary',
  'wedge',
  'wee',
  'weed',
  'week',
  'weekly',
  'weep',
  'weight',
  'weird',
  'well',
  'were',
  'west',
  'wet',
  'whale',
  'wharf',
  'what',
  'wheat',
  'wheel',
  'wheeze',
  'wheezy',
  'when',
  'whence',
  'where',
  'which',
  'whiff',
  'whig',
  'while',
  'whim',
  'whip',
  'whisky',
  'white',
  'who',
  'whole',
  'wholly',
  'whom',
  'whose',
  'why',
  'wide',
  'widely',
  'widen',
  'wider',
  'widow',
  'width',
  'wife',
  'wild',
  'wildly',
  'wilful',
  'will',
  'willow',
  'win',
  'wind',
  'window',
  'windy',
  'wine',
  'winery',
  'wing',
  'wink',
  'winner',
  'winter',
  'wipe',
  'wire',
  'wisdom',
  'wise',
  'wish',
  'wit',
  'witch',
  'with',
  'within',
  'witty',
  'wizard',
  'woke',
  'wolf',
  'wolves',
  'woman',
  'womb',
  'won',
  'wonder',
  'wood',
  'wooden',
  'woods',
  'woody',
  'wool',
  'word',
  'work',
  'worker',
  'world',
  'worm',
  'worry',
  'worse',
  'worst',
  'worth',
  'worthy',
  'would',
  'wound',
  'wrap',
  'wrath',
  'wreath',
  'wreck',
  'wren',
  'wright',
  'wrist',
  'writ',
  'write',
  'writer',
  'wrong',
  'xerox',
  'yacht',
  'yager',
  'yale',
  'yard',
  'yarn',
  'yeah',
  'year',
  'yeast',
  'yellow',
  'yemen',
  'yet',
  'yield',
  'yogurt',
  'yokel',
  'yolk',
  'york',
  'you',
  'young',
  'your',
  'youth',
  'zaire',
  'zeal',
  'zebra',
  'zenith',
  'zero',
  'zigzag',
  'zinc',
  'zing',
  'zipper',
  'zombie',
  'zone',
  'zurich',
];

/**
 * Minimal mnemonic adapters.
 * @module wallet/misc/mnemonic
 */


const WORD_LOOKUP = WordList.reduce((acc, word, i) => {
  acc[word] = i;
  return acc;
}, Object.create(null));

/**
 * Encode bytes to a spaced hex mnemonic string.
 * @param {Uint8Array} input
 * @returns {string}
 */
function binToMnemonic(input) {
  if (!(input instanceof Uint8Array)) {
    // Without this check a string (or array) input whose length happens to
    // be a multiple of 3 would silently encode to a garbage mnemonic —
    // character indexing coerces to NaN, which maps every word to index 0.
    throw new Error('input must be a Uint8Array');
  }
  if (input.length % 3 !== 0) {
    throw new Error('byte count needs to be a multiple of 3');
  }

  const words = [];
  for (let nibble = 0; nibble < input.length * 2; nibble += 3) {
    const p = nibble >> 1;
    const b1 = input[p];
    /* c8 ignore next -- fallback unreachable for valid (multiple of 3) input */
    const b2 = p + 1 < input.length ? input[p + 1] : 0;
    const idx = nibble % 2 === 0 ? (b1 << 4) + (b2 >> 4) : ((b1 & 0x0f) << 8) + b2;

    words.push(WordList[idx]);
  }

  return words.join(' ');
}

/**
 * Decode spaced hex mnemonic to bytes.
 * @param {string} mnemonic
 * @returns {Uint8Array}
 *
 * Note: Mnemonic words are normalized to lowercase for user convenience.
 * This is by design to reduce errors from capitalization differences.
 */
function mnemonicToBin(mnemonic) {
  // Normalize to lowercase for user-friendly input (case-insensitive matching)
  const mnemonicWords = mnemonic.trim().toLowerCase().split(/\s+/);
  if (mnemonicWords.length % 2 !== 0) throw new Error('word count must be even');

  const result = new Uint8Array((mnemonicWords.length * 15) / 10);
  let current = 0;
  let buffering = 0;
  let resultIndex = 0;

  for (let i = 0; i < mnemonicWords.length; i += 1) {
    const w = mnemonicWords[i];
    const value = WORD_LOOKUP[w];
    if (value === undefined) throw new Error('invalid word in mnemonic');

    buffering += 3;
    current = (current << 12) + value;
    for (; buffering > 2; ) {
      const shift = 4 * (buffering - 2);
      const mask = (1 << shift) - 1;
      const tmp = current >> shift;
      buffering -= 2;
      current &= mask;
      result[resultIndex++] = tmp;
    }
  }

  if (buffering > 0) {
    result[resultIndex] = current & 0xff;
  }

  return result;
}

/**
 * @module wallet/ml_dsa_87/crypto
 */


/** @typedef {import('../common/seed.js').Seed} Seed */

/**
 * Generate a keypair.
 *
 * Note: ML-DSA-87 (FIPS 204) requires a 32-byte seed for key generation.
 * QRL uses a 48-byte seed for mnemonic compatibility across wallet types.
 * SHA-256 hashing reduces the 48-byte seed to the required 32 bytes per spec.
 * This matches go-qrllib behavior for cross-implementation compatibility.
 *
 * @param {Seed} seed - 48-byte QRL seed (hashed to 32 bytes internally)
 * @returns {{ pk: Uint8Array, sk: Uint8Array }}
 */
function keygen(seed) {
  const pk = new Uint8Array(CryptoPublicKeyBytes);
  const sk = new Uint8Array(CryptoSecretKeyBytes);
  // FIPS 204 requires 32-byte seed; hash 48-byte QRL seed to derive it
  const seedBytes = new Uint8Array(seed.hashSHA256());
  try {
    cryptoSignKeypair(seedBytes, pk, sk);
    return { pk, sk };
  } finally {
    seedBytes.fill(0);
  }
}

/**
 * Check if input is a valid byte array (Uint8Array or Buffer).
 * @param {unknown} input
 * @returns {input is Uint8Array}
 */
function isBytes(input) {
  return input instanceof Uint8Array;
}

/**
 * Build a validation Error carrying a stable, machine-readable `code`.
 * Callers (e.g. `Wallet.verifyWithReason`) classify failures by `code`;
 * the human-readable message text is informational and may evolve.
 *
 * Codes: `ERR_SK_TYPE`, `ERR_SK_LENGTH`, `ERR_MESSAGE_TYPE`,
 * `ERR_CTX_TYPE`, `ERR_RANDOMIZED_TYPE`, `ERR_SIGNATURE_TYPE`,
 * `ERR_SIGNATURE_LENGTH`, `ERR_PK_TYPE`, `ERR_PK_LENGTH`.
 *
 * @param {string} code
 * @param {string} message
 * @returns {Error & {code: string}}
 */
function typedError(code, message) {
  const err = /** @type {Error & {code: string}} */ (new Error(message));
  err.code = code;
  return err;
}

/**
 * Sign a message.
 *
 * Signing mode (TOB-QRLLIB-6 — port from the `go-qrllib` Trail of Bits
 * engagement). The `randomized` flag selects between FIPS 204 §3.4
 * (hedged) and §3.5 (deterministic) ML-DSA signing:
 *
 * - `randomized: true` — **hedged, recommended.** Per FIPS 204 §3.4 the
 *   per-signature nonce is mixed with fresh randomness from the system
 *   RNG on every call. Two signs over the same `(sk, ctx, message)`
 *   produce **distinct** signature bytes; both verify under the same
 *   public key. Hedged signing frustrates the fault-injection attack
 *   class against deterministic ML-DSA where an adversary who can flip
 *   a single bit during the `z` computation can differentiate two
 *   signatures of the same message and recover `s1`/`s2` by lattice
 *   differential analysis. This is the wallet's default.
 *
 * - `randomized: false` — **deterministic, opt-in.** Use only when the
 *   deterministic property is itself a security or protocol requirement
 *   — e.g. RANDAO-style verifiable beacon contributions where every
 *   validator must produce the same signature for the same input, or
 *   KAT / ACVP vector reproduction. Prefer the `signDeterministic`
 *   helper to signal intent at the call site rather than passing a
 *   positional boolean.
 *
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes bytes)
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} ctx - FIPS 204 context bytes (wallet layer passes the
 *   domain-separated `"ZOND" || version || descriptor` context)
 * @param {boolean} [randomized=true] - `true` for hedged (recommended),
 *   `false` for deterministic.
 * @returns {Uint8Array} signature
 * @throws {Error} If sk, message, or ctx is invalid
 */
function sign(sk, message, ctx, randomized = true) {
  if (!isBytes(sk)) {
    throw typedError('ERR_SK_TYPE', 'sk must be Uint8Array or Buffer');
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    throw typedError('ERR_SK_LENGTH', `sk must be ${CryptoSecretKeyBytes} bytes, got ${sk.length}`);
  }
  if (!isBytes(message)) {
    throw typedError('ERR_MESSAGE_TYPE', 'message must be Uint8Array or Buffer');
  }
  if (!isBytes(ctx)) {
    throw typedError('ERR_CTX_TYPE', 'ctx must be Uint8Array or Buffer');
  }
  if (typeof randomized !== 'boolean') {
    throw typedError('ERR_RANDOMIZED_TYPE', 'randomized must be a boolean');
  }

  const sm = cryptoSign(message, sk, randomized, ctx);
  const signature = sm.slice(0, CryptoBytes);
  return signature;
}

/**
 * Deterministic signing helper. Thin wrapper around {@link sign} with
 * `randomized: false` that signals caller intent at the API surface
 * rather than via a positional boolean. Use only when determinism is
 * itself a protocol requirement (see {@link sign} JSDoc). For all
 * other cases prefer {@link sign}, which defaults to hedged signing
 * per FIPS 204 §3.4 and TOB-QRLLIB-6.
 *
 * @param {Uint8Array} sk - Secret key
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} ctx - FIPS 204 context bytes
 * @returns {Uint8Array} signature
 */
function signDeterministic(sk, message, ctx) {
  return sign(sk, message, ctx, false);
}

/**
 * Verify a signature.
 * @param {Uint8Array} signature - Signature to verify (must be CryptoBytes bytes)
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes bytes)
 * @param {Uint8Array} ctx - FIPS 204 context bytes (wallet layer passes the
 *   domain-separated `"ZOND" || version || descriptor` context)
 * @returns {boolean}
 * @throws {Error} If signature, message, pk, or ctx is invalid
 */
function verify(signature, message, pk, ctx) {
  if (!isBytes(signature)) {
    throw typedError('ERR_SIGNATURE_TYPE', 'signature must be Uint8Array or Buffer');
  }
  if (signature.length !== CryptoBytes) {
    throw typedError('ERR_SIGNATURE_LENGTH', `signature must be ${CryptoBytes} bytes, got ${signature.length}`);
  }
  if (!isBytes(message)) {
    throw typedError('ERR_MESSAGE_TYPE', 'message must be Uint8Array or Buffer');
  }
  if (!isBytes(pk)) {
    throw typedError('ERR_PK_TYPE', 'pk must be Uint8Array or Buffer');
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    throw typedError('ERR_PK_LENGTH', `pk must be ${CryptoPublicKeyBytes} bytes, got ${pk.length}`);
  }
  if (!isBytes(ctx)) {
    throw typedError('ERR_CTX_TYPE', 'ctx must be Uint8Array or Buffer');
  }

  const sigBytes = new Uint8Array(signature);
  const msgBytes = new Uint8Array(message);
  const pkBytes = new Uint8Array(pk);
  return cryptoSignVerify(sigBytes, msgBytes, pkBytes, ctx);
}

/**
 * ML-DSA-87 Wallet object encapsulating descriptor, seeds and keypair.
 * @module wallet/ml_dsa_87/wallet
 */


/**
 * Property names that carry secret material. Kept non-enumerable so that
 * `Object.keys`, `JSON.stringify`, `{...wallet}`, and default `util.inspect`
 * do not surface them — defense-in-depth against accidental leakage through
 * logs, crash reporters, serializers, etc. Direct access (e.g. `w.sk`)
 * still works for legitimate callers; see `toJSON()` for the redacted
 * public shape.
 */
const SECRET_FIELDS = ['seed', 'sk', 'extendedSeed', '_zeroized'];

class Wallet {
  /**
   * @param {{descriptor: Descriptor, seed: Seed, pk: Uint8Array, sk: Uint8Array}} opts
   *
   * Ownership contract: the constructor takes ownership of every object and
   * buffer passed in. Callers constructing a Wallet directly must not
   * retain, mutate, or zeroize `descriptor`, `seed`, `pk`, or `sk` after
   * construction — `zeroize()` assumes the wallet is their sole owner.
   * The static factories uphold this internally; `newWalletFromSeed`
   * defensively copies the caller's Seed so external code never shares
   * secret-bearing state with a Wallet.
   */
  constructor({ descriptor, seed, pk, sk }) {
    if (!(descriptor instanceof Descriptor)) {
      throw new Error('descriptor must be a Descriptor instance');
    }
    if (!(seed instanceof Seed)) {
      throw new Error('seed must be a Seed instance');
    }
    if (!(pk instanceof Uint8Array)) {
      throw new Error('pk must be a Uint8Array');
    }
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`pk must be ${CryptoPublicKeyBytes} bytes, got ${pk.length}`);
    }
    if (!(sk instanceof Uint8Array)) {
      throw new Error('sk must be a Uint8Array');
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`sk must be ${CryptoSecretKeyBytes} bytes, got ${sk.length}`);
    }
    this.descriptor = descriptor;
    this.seed = seed;
    this.pk = pk;
    this.sk = sk;
    this.extendedSeed = ExtendedSeed.newExtendedSeed(descriptor, seed);
    /** @private */
    this._zeroized = false;
    for (const name of SECRET_FIELDS) {
      Object.defineProperty(this, name, { enumerable: false });
    }
  }

  /**
   * Create a new random wallet (non-deterministic).
   * @param {[number, number]} [metadata=[0,0]]
   * @returns {Wallet}
   */
  static newWallet(metadata = [0, 0]) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const seedBytes = randomBytes(48);
    try {
      const seed = new Seed(seedBytes);
      const { pk, sk } = keygen(seed);
      return new Wallet({ descriptor, seed, pk, sk });
    } finally {
      seedBytes.fill(0);
    }
  }

  /**
   * Create a wallet deterministically from an existing seed.
   *
   * The caller's `Seed` instance is **defensively copied**: the wallet and
   * the caller's object have independent lifecycles. Zeroizing the input
   * Seed afterwards does not affect the wallet, and `wallet.zeroize()`
   * does not reach the caller's instance — the caller stays responsible
   * for zeroizing their own copy.
   *
   * @param {Seed} seed
   * @param {[number, number]} [metadata=[0,0]]
   * @returns {Wallet}
   */
  static newWalletFromSeed(seed, metadata = [0, 0]) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const { pk, sk } = keygen(seed);
    // Copy the caller's Seed so no secret-bearing state is shared across
    // the API boundary; zeroize the transient byte buffer once wrapped.
    const seedBytes = seed.toBytes();
    try {
      return new Wallet({ descriptor, seed: new Seed(seedBytes), pk, sk });
    } finally {
      seedBytes.fill(0);
    }
  }

  /**
   * @param {ExtendedSeed} extendedSeed
   * @returns {Wallet}
   */
  static newWalletFromExtendedSeed(extendedSeed) {
    const descriptor = extendedSeed.getDescriptor();
    const seed = extendedSeed.getSeed();
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk });
  }

  /**
   * @param {string} mnemonic
   * @returns {Wallet}
   */
  static newWalletFromMnemonic(mnemonic) {
    const bin = mnemonicToBin(mnemonic);
    try {
      const extendedSeed = new ExtendedSeed(bin);
      return this.newWalletFromExtendedSeed(extendedSeed);
    } finally {
      bin.fill(0);
    }
  }

  /** @returns {Uint8Array} */
  getAddress() {
    return getAddressFromPKAndDescriptor(this.pk, this.descriptor);
  }

  /**
   * @returns {string} Address with `Q` prefix and lowercase hex body. Pass
   *   through `toChecksumAddress` to obtain the EIP-55-style mixed-case
   *   checksummed form.
   */
  getAddressStr() {
    return addressToString(this.getAddress());
  }

  /** @returns {Descriptor} */
  getDescriptor() {
    return new Descriptor(this.descriptor.toBytes());
  }

  /**
   * @private
   * @throws {Error} If the wallet has been zeroized.
   */
  _requireLive() {
    if (this._zeroized) {
      throw new Error('Wallet has been zeroized');
    }
  }

  /** @returns {ExtendedSeed} */
  getExtendedSeed() {
    this._requireLive();
    return ExtendedSeed.from(this.extendedSeed.toBytes());
  }

  /** @returns {Seed} */
  getSeed() {
    this._requireLive();
    return new Seed(this.seed.toBytes());
  }

  /** @returns {string} hex(ExtendedSeed) */
  getHexExtendedSeed() {
    this._requireLive();
    return `0x${bytesToHex(this.getExtendedSeed().toBytes())}`;
  }

  /** @returns {string} */
  getMnemonic() {
    this._requireLive();
    return binToMnemonic(this.getExtendedSeed().toBytes());
  }

  /** @returns {Uint8Array} */
  getPK() {
    return this.pk.slice();
  }

  /**
   * Returns a copy of the secret key.
   * @returns {Uint8Array}
   * @warning Caller is responsible for zeroing the returned buffer when done
   * (e.g. `sk.fill(0)`). The Wallet's `zeroize()` method cannot reach copies
   * returned by this method.
   */
  getSK() {
    this._requireLive();
    return this.sk.slice();
  }

  /**
   * Sign a message. The wallet binds the signature to its descriptor via
   * the domain-separated signing context; callers do not need to pass it
   * explicitly.
   *
   * Signing is **hedged** by default (FIPS 204 §3.4, recommended per
   * TOB-QRLLIB-6) — two signs over the same `(wallet, message)` pair
   * produce distinct signature bytes that both verify under the same
   * public key. For protocols that require deterministic signatures
   * (RANDAO-style verifiable beacon contributions, KAT / ACVP vector
   * reproduction), use {@link Wallet#signDeterministic} instead.
   *
   * @param {Uint8Array} message
   * @returns {Uint8Array} Signature bytes.
   */
  sign(message) {
    this._requireLive();
    return sign(this.sk, message, signingContext(this.descriptor));
  }

  /**
   * Sign a message deterministically (FIPS 204 §3.5). The same
   * `(wallet, message)` pair always yields byte-identical signatures.
   * Use only when determinism is itself a protocol requirement (see
   * {@link Wallet#sign} for the recommended hedged default and the
   * TOB-QRLLIB-6 rationale).
   *
   * @param {Uint8Array} message
   * @returns {Uint8Array} Signature bytes.
   */
  signDeterministic(message) {
    this._requireLive();
    return signDeterministic(this.sk, message, signingContext(this.descriptor));
  }

  /**
   * Verify a signature. The descriptor is required so verification uses
   * the same domain-separated context that signing did.
   *
   * **Total over malformed inputs**: wrong-typed or wrong-length
   * signature/message/pk and a non-Descriptor descriptor all return
   * `false` — this boundary never throws. Use
   * {@link Wallet.verifyWithReason} when you need to distinguish *why*
   * verification failed.
   *
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} pk
   * @param {Descriptor} descriptor
   * @returns {boolean}
   */
  static verify(signature, message, pk, descriptor) {
    return Wallet.verifyWithReason(signature, message, pk, descriptor).ok;
  }

  /**
   * Verify a signature with a discriminated failure reason (TOB-QRLLIB-14
   * — port from the `go-qrllib` Trail of Bits engagement). Returns
   * `{ ok: true }` on success, or `{ ok: false, reason }` with a typed
   * reason on failure. This is a non-destructive companion to
   * {@link Wallet.verify} — the boolean form is unchanged.
   *
   * Failure-reason taxonomy:
   *  - `'invalid-descriptor'` — `descriptor` is not a `Descriptor` instance
   *  - `'invalid-signature-type'` — `signature` is not a `Uint8Array`
   *  - `'invalid-signature-length'` — `signature` is the wrong byte length
   *  - `'invalid-message-type'` — `message` is not a `Uint8Array`
   *  - `'invalid-pk-type'` — `pk` is not a `Uint8Array`
   *  - `'invalid-pk-length'` — `pk` is the wrong byte length
   *  - `'verification-failed'` — well-formed inputs, signature does not verify
   *
   * The boolean {@link Wallet.verify} collapses all of these into `false`
   * to preserve constant-time semantics at the verification boundary;
   * `verifyWithReason` exposes them only for diagnostic / error-reporting
   * use cases (e.g. wallet UI telling the user the descriptor is wrong vs.
   * the signature is forged). Do not branch program logic on the reason
   * in security-sensitive paths.
   *
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} pk
   * @param {Descriptor} descriptor
   * @returns {{ok: true} | {ok: false, reason: string}}
   */
  static verifyWithReason(signature, message, pk, descriptor) {
    if (!(descriptor instanceof Descriptor)) {
      return { ok: false, reason: 'invalid-descriptor' };
    }
    if (!(signature instanceof Uint8Array)) {
      return { ok: false, reason: 'invalid-signature-type' };
    }
    if (!(message instanceof Uint8Array)) {
      return { ok: false, reason: 'invalid-message-type' };
    }
    if (!(pk instanceof Uint8Array)) {
      return { ok: false, reason: 'invalid-pk-type' };
    }
    // Length checks delegate to the lower layer, whose validation errors
    // carry stable machine-readable `code`s (see crypto.js `typedError`);
    // we classify by code, never by message text. The final `throw e` in
    // the catch block below is a defensive safety net — given the type
    // pre-checks above, the only lower-layer failures reachable here are
    // the two length codes. If a future lower-layer change introduces an
    // unclassified error, we want the surprise to propagate rather than
    // be silently collapsed into 'verification-failed'. The re-raise is
    // therefore unreachable from any current public-API call site;
    // covered by inspection rather than by a test that would have to
    // monkey-patch the lower layer.
    try {
      const ok = verify(signature, message, pk, signingContext(descriptor));
      return ok ? { ok: true } : { ok: false, reason: 'verification-failed' };
    } catch (e) {
      const { code } = /** @type {Error & {code?: string}} */ (e);
      if (code === 'ERR_SIGNATURE_LENGTH') {
        return { ok: false, reason: 'invalid-signature-length' };
      }
      if (code === 'ERR_PK_LENGTH') {
        return { ok: false, reason: 'invalid-pk-length' };
      }
      /* c8 ignore next 2 */
      throw e;
    }
  }

  /**
   * Redacted JSON shape used by `JSON.stringify`. Returns only public
   * information — address and public key. Secret material (sk, seed,
   * extendedSeed) is intentionally excluded so that accidental
   * serialization through logs, crash reporters, telemetry, structured
   * clone, or object spreading cannot leak secrets.
   *
   * Callers who need the raw material must ask for it explicitly via
   * `getSK()`, `getSeed()`, `getExtendedSeed()`, or `getMnemonic()`.
   *
   * @returns {{address: string, pk: string}}
   */
  toJSON() {
    return {
      address: this.getAddressStr(),
      pk: `0x${bytesToHex(this.pk)}`,
    };
  }

  /**
   * Safe representation for Node's `util.inspect` / `console.log`.
   * Never includes secret material.
   * @returns {string}
   */
  [Symbol.for('nodejs.util.inspect.custom')]() {
    const state = this._zeroized ? 'zeroized' : 'live';
    const addr = this._zeroized ? '<zeroized>' : this.getAddressStr();
    return `Wallet { address: '${addr}', state: '${state}', <secret material redacted> }`;
  }

  /**
   * Securely zeroize sensitive key material.
   * Call this when the wallet is no longer needed to minimize
   * the window where secrets exist in memory.
   *
   * Note: JavaScript garbage collection may retain copies;
   * this provides best-effort zeroization.
   */
  zeroize() {
    if (this.sk) {
      this.sk.fill(0);
      this.sk = null;
    }
    if (this.seed) {
      this.seed.zeroize();
      this.seed = null;
    }
    if (this.extendedSeed) {
      this.extendedSeed.zeroize();
      this.extendedSeed = null;
    }
    this._zeroized = true;
  }
}

/**
 * Auto-select wallet implementation based on the ExtendedSeed descriptor.
 * @module wallet/factory
 */


/**
 * Construct a wallet from an ExtendedSeed by auto-selecting the correct implementation.
 *
 * @param {ExtendedSeed|Uint8Array|string} extendedSeed - ExtendedSeed instance, 51 bytes or hex string.
 * @returns {MLDSA87} Wallet instance
 * @throws {Error} If wallet type is unsupported
 */
function newWalletFromExtendedSeed(extendedSeed) {
  let ext;
  if (extendedSeed instanceof Uint8Array || isHexLike(extendedSeed)) {
    ext = ExtendedSeed.from(extendedSeed);
  } else if (extendedSeed instanceof ExtendedSeed) {
    ext = extendedSeed;
  } else {
    throw new Error('Unsupported extendedSeed input');
  }

  const desc = ext.getDescriptor();
  switch (desc.type()) {
    case WalletType.ML_DSA_87:
      return Wallet.newWalletFromExtendedSeed(ext);
    // case WalletType.SPHINCSPLUS_256S:
    //   Not yet implemented - reserved for future use
    /* c8 ignore next 2 */
    default:
      throw new Error(`Unsupported wallet type: ${desc.type()}`);
  }
}

export { ADDRESS_SIZE, DESCRIPTOR_SIZE, Descriptor, EXTENDED_SEED_SIZE, ExtendedSeed, Wallet as MLDSA87, SEED_SIZE, SIGNING_CONTEXT_PREFIX, SIGNING_CONTEXT_SIZE, SIGNING_CONTEXT_VERSION, Seed, WalletType, addressToString, getAddressFromPKAndDescriptor, isValidAddress, isValidChecksumAddress, newMLDSA87Descriptor, newWalletFromExtendedSeed, signingContext, stringToAddress, toChecksumAddress };
