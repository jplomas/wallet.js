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

/** @typedef {import('./descriptor.js').Descriptor} Descriptor */
import { shake256 } from '@noble/hashes/sha3.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { ADDRESS_SIZE } from './constants.js';

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

export {
  addressToString,
  stringToAddress,
  isValidAddress,
  toChecksumAddress,
  isValidChecksumAddress,
  getAddressFromPKAndDescriptor,
};
