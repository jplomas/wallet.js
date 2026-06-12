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

import { DESCRIPTOR_SIZE } from './constants.js';
import { isValidWalletType } from './wallettype.js';
import { toFixedU8 } from '../../utils/bytes.js';

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

export { Descriptor, getDescriptorBytes };
