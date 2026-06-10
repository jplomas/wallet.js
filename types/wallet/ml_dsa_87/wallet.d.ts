export class Wallet {
    /**
     * Create a new random wallet (non-deterministic).
     * @param {[number, number]} [metadata=[0,0]]
     * @returns {Wallet}
     */
    static newWallet(metadata?: [number, number]): Wallet;
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
    static newWalletFromSeed(seed: Seed, metadata?: [number, number]): Wallet;
    /**
     * @param {ExtendedSeed} extendedSeed
     * @returns {Wallet}
     */
    static newWalletFromExtendedSeed(extendedSeed: ExtendedSeed): Wallet;
    /**
     * @param {string} mnemonic
     * @returns {Wallet}
     */
    static newWalletFromMnemonic(mnemonic: string): Wallet;
    /**
     * Verify a signature. The descriptor is required so verification uses
     * the same domain-separated context that signing did.
     * @param {Uint8Array} signature
     * @param {Uint8Array} message
     * @param {Uint8Array} pk
     * @param {Descriptor} descriptor
     * @returns {boolean}
     */
    static verify(signature: Uint8Array, message: Uint8Array, pk: Uint8Array, descriptor: Descriptor): boolean;
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
    static verifyWithReason(signature: Uint8Array, message: Uint8Array, pk: Uint8Array, descriptor: Descriptor): {
        ok: true;
    } | {
        ok: false;
        reason: string;
    };
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
    constructor({ descriptor, seed, pk, sk }: {
        descriptor: Descriptor;
        seed: Seed;
        pk: Uint8Array;
        sk: Uint8Array;
    });
    descriptor: Descriptor;
    seed: Seed;
    pk: Uint8Array<ArrayBufferLike>;
    sk: Uint8Array<ArrayBufferLike>;
    extendedSeed: ExtendedSeed;
    /** @private */
    private _zeroized;
    /** @returns {Uint8Array} */
    getAddress(): Uint8Array;
    /**
     * @returns {string} Address with `Q` prefix and lowercase hex body. Pass
     *   through `toChecksumAddress` to obtain the EIP-55-style mixed-case
     *   checksummed form.
     */
    getAddressStr(): string;
    /** @returns {Descriptor} */
    getDescriptor(): Descriptor;
    /**
     * @private
     * @throws {Error} If the wallet has been zeroized.
     */
    private _requireLive;
    /** @returns {ExtendedSeed} */
    getExtendedSeed(): ExtendedSeed;
    /** @returns {Seed} */
    getSeed(): Seed;
    /** @returns {string} hex(ExtendedSeed) */
    getHexExtendedSeed(): string;
    /** @returns {string} */
    getMnemonic(): string;
    /** @returns {Uint8Array} */
    getPK(): Uint8Array;
    /**
     * Returns a copy of the secret key.
     * @returns {Uint8Array}
     * @warning Caller is responsible for zeroing the returned buffer when done
     * (e.g. `sk.fill(0)`). The Wallet's `zeroize()` method cannot reach copies
     * returned by this method.
     */
    getSK(): Uint8Array;
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
    sign(message: Uint8Array): Uint8Array;
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
    signDeterministic(message: Uint8Array): Uint8Array;
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
    toJSON(): {
        address: string;
        pk: string;
    };
    /**
     * Securely zeroize sensitive key material.
     * Call this when the wallet is no longer needed to minimize
     * the window where secrets exist in memory.
     *
     * Note: JavaScript garbage collection may retain copies;
     * this provides best-effort zeroization.
     */
    zeroize(): void;
}
import { Descriptor } from '../common/descriptor.js';
import { Seed } from '../common/seed.js';
import { ExtendedSeed } from '../common/seed.js';
//# sourceMappingURL=wallet.d.ts.map