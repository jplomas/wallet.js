/**
 * Address helpers.
 * @module wallet/common/address
 *
 * Address Format:
 *   - Byte form: `ADDRESS_SIZE`-byte SHAKE-256 hash of (descriptor || public key).
 *   - String form: "Q" prefix followed by `2 × ADDRESS_SIZE` lowercase hex
 *     characters. At the canonical 64-byte size this is a 129-character string.
 *   - Output is always lowercase hex; input parsing is case-insensitive for both
 *     the "Q"/"q" prefix and hex characters.
 *   - Unlike EIP-55, no checksum encoding is used in the address itself.
 *   - All helpers (`addressToString`, `stringToAddress`, `isValidAddress`,
 *     `getAddressFromPKAndDescriptor`) operate at the single canonical
 *     {@link ADDRESS_SIZE}; addresses of other sizes are rejected. This
 *     matches go-qrllib (`AddressSize`) and rust-qrllib (`ADDRESS_SIZE`).
 */

/** @typedef {import('./descriptor.js').Descriptor} Descriptor */
import { shake256 } from '@noble/hashes/sha3.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { ADDRESS_SIZE } from './constants.js';

/**
 * Convert address bytes to string form.
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
  const hex = [...addrBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `Q${hex}`;
}

/**
 * Convert address string to bytes.
 * @param {string} addrStr - Address string: 'Q' followed by exactly
 *   `2 × ADDRESS_SIZE` (= 128) hex characters.
 * @returns {Uint8Array} Decoded ADDRESS_SIZE-byte address.
 * @throws {Error} If address format is invalid.
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
  const expectedHexLen = ADDRESS_SIZE * 2;
  if (hex.length !== expectedHexLen) {
    throw new Error(`address must be Q + exactly ${expectedHexLen} hex characters, got ${hex.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('address contains invalid characters');
  }
  const bytes = new Uint8Array(ADDRESS_SIZE);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Check if a string is a valid QRL address format. Requires exactly
 * `Q` + `2 × ADDRESS_SIZE` hex characters. QRL addresses contain no
 * checksum; applications should add their own confirmation or checksum
 * layer.
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if valid address format.
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

export { addressToString, stringToAddress, isValidAddress, getAddressFromPKAndDescriptor };
