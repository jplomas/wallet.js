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
export function keygen(seed: Seed): {
    pk: Uint8Array;
    sk: Uint8Array;
};
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
export function sign(sk: Uint8Array, message: Uint8Array, ctx: Uint8Array, randomized?: boolean): Uint8Array;
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
export function signDeterministic(sk: Uint8Array, message: Uint8Array, ctx: Uint8Array): Uint8Array;
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
export function verify(signature: Uint8Array, message: Uint8Array, pk: Uint8Array, ctx: Uint8Array): boolean;
//# sourceMappingURL=crypto.d.ts.map