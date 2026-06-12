/**
 * Seed(48 bytes) and ExtendedSeed(51 bytes) with constructors.
 * @module wallet/common/seed
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { SEED_SIZE, EXTENDED_SEED_SIZE, DESCRIPTOR_SIZE } from './constants.js';
import { toFixedU8 } from '../../utils/bytes.js';
import { Descriptor } from './descriptor.js';
import { isValidWalletType } from './wallettype.js';

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

export { Seed, ExtendedSeed };
