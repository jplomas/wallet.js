/**
 * ML-DSA-87 Wallet object encapsulating descriptor, seeds and keypair.
 * @module wallet/ml_dsa_87/wallet
 */

import { bytesToHex } from '@noble/hashes/utils.js';
import { randomBytes } from '../../utils/random.js';
import { mnemonicToBin, binToMnemonic } from '../misc/mnemonic.js';
import { getAddressFromPKAndDescriptor, addressToString } from '../common/address.js';
import { DEFAULT_ADDRESS_SIZE } from '../common/constants.js';
import { signingContext } from '../common/context.js';
import { Descriptor } from '../common/descriptor.js';
import { Seed, ExtendedSeed } from '../common/seed.js';
import { newMLDSA87Descriptor } from './descriptor.js';
import { keygen, sign, signDeterministic, verify } from './crypto.js';

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
   * @param {{descriptor: Descriptor, seed: Seed, pk: Uint8Array, sk: Uint8Array, addressSize?: number}} opts
   */
  constructor({ descriptor, seed, pk, sk, addressSize = DEFAULT_ADDRESS_SIZE }) {
    if (!Number.isInteger(addressSize) || addressSize <= 0) {
      throw new Error('addressSize must be a positive integer');
    }
    this.descriptor = descriptor;
    this.seed = seed;
    this.pk = pk;
    this.sk = sk;
    /**
     * Address length in bytes this wallet derives. Defaults to
     * {@link DEFAULT_ADDRESS_SIZE} (20, NIST Category 1 — v2.x contract);
     * pass `addressSize: ADDRESS_SIZE_CATEGORY_5` (48) on construction to
     * get NIST Category 5 post-quantum collision resistance.
     * @type {number}
     */
    this.addressSize = addressSize;
    this.extendedSeed = ExtendedSeed.newExtendedSeed(descriptor, seed);
    /** @private */
    this._zeroized = false;
    for (const name of SECRET_FIELDS) {
      Object.defineProperty(this, name, { enumerable: false });
    }
  }

  /**
   * Create a new random wallet(non-deterministic).
   * @param {[number, number]} [metadata=[0,0] ]
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWallet(metadata = [0, 0], addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const seedBytes = randomBytes(48);
    try {
      const seed = new Seed(seedBytes);
      const { pk, sk } = keygen(seed);
      return new Wallet({ descriptor, seed, pk, sk, addressSize });
    } finally {
      seedBytes.fill(0);
    }
  }

  /**
   * @param {Seed} seed
   * @param {[number, number]} [metadata=[0,0]]
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromSeed(seed, metadata = [0, 0], addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk, addressSize });
  }

  /**
   * @param {ExtendedSeed} extendedSeed
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromExtendedSeed(extendedSeed, addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = extendedSeed.getDescriptor();
    const seed = extendedSeed.getSeed();
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk, addressSize });
  }

  /**
   * @param {string} mnemonic
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromMnemonic(mnemonic, addressSize = DEFAULT_ADDRESS_SIZE) {
    const bin = mnemonicToBin(mnemonic);
    try {
      const extendedSeed = new ExtendedSeed(bin);
      return this.newWalletFromExtendedSeed(extendedSeed, addressSize);
    } finally {
      bin.fill(0);
    }
  }

  /** @returns {Uint8Array} */
  getAddress() {
    return getAddressFromPKAndDescriptor(this.pk, this.descriptor, this.addressSize);
  }

  /** @returns {string} */
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
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} pk
   * @param {Descriptor} descriptor
   * @returns {boolean}
   */
  static verify(signature, message, pk, descriptor) {
    return verify(signature, message, pk, signingContext(descriptor));
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
    // Length checks delegate to the lower layer; we re-classify the
    // lower layer's typed errors into our reason taxonomy here. The
    // final `throw e` in the catch block below is a defensive safety
    // net — the lower-layer `verify`'s complete error taxonomy
    // ({sk,signature,message,pk,ctx} × {type,length}) is fully
    // classified into the `if` branches above. If a future lower-layer
    // change introduces an error message we haven't classified yet,
    // we want the surprise to propagate rather than be silently
    // collapsed into 'verification-failed'. The re-raise is therefore
    // unreachable from any current public-API call site; covered by
    // inspection rather than by a test that would have to monkey-patch
    // the lower layer.
    try {
      const ok = verify(signature, message, pk, signingContext(descriptor));
      return ok ? { ok: true } : { ok: false, reason: 'verification-failed' };
    } catch (e) {
      // `e && e.message || e` is defensive against a `throw null`,
      // `throw undefined`, or `throw { message: '' }` from the lower
      // layer; under the current lower-layer contract `e` is always an
      // `Error` instance with a non-empty message, so the short-circuit
      // fallback branches are unreachable today.
      /* c8 ignore next */
      const msg = String((e && e.message) || e);
      if (msg.includes('signature must be')) {
        return { ok: false, reason: 'invalid-signature-length' };
      }
      if (msg.includes('pk must be')) {
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

export { Wallet };
