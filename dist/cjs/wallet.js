'use strict';

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

const U32_MASK64$1 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n$1 = /* @__PURE__ */ BigInt(32);
// Split bigint into two 32-bit halves. With `le=true`, returned fields become `{ h: low, l: high
// }` to match little-endian word order rather than the property names.
function fromBig$1(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64$1), l: Number((n >> _32n$1) & U32_MASK64$1) };
    return { h: Number((n >> _32n$1) & U32_MASK64$1) | 0, l: Number(n & U32_MASK64$1) | 0 };
}
// Split bigint list into `[highWords, lowWords]` when `le=false`; with `le=true`, the first array
// holds the low halves because `fromBig(...)` swaps the semantic meaning of `h` and `l`.
function split$1(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
        const { h, l } = fromBig$1(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
// High 32-bit half of a 64-bit left rotate, valid for `s` in `1..31`.
const rotlSH$1 = (h, l, s) => (h << s) | (l >>> (32 - s));
// Low 32-bit half of a 64-bit left rotate, valid for `s` in `1..31`.
const rotlSL$1 = (h, l, s) => (l << s) | (h >>> (32 - s));
// High 32-bit half of a 64-bit left rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotlBH$1 = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
// Low 32-bit half of a 64-bit left rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotlBL$1 = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));

/**
 * Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
 * @param a - value to test
 * @returns `true` when the value is a Uint8Array-compatible view.
 * @example
 * Check whether a value is a Uint8Array-compatible view.
 * ```ts
 * isBytes(new Uint8Array([1, 2, 3]));
 * ```
 */
function isBytes$2(a) {
    // Plain `instanceof Uint8Array` is too strict for some Buffer / proxy / cross-realm cases.
    // The fallback still requires a real ArrayBuffer view, so plain
    // JSON-deserialized `{ constructor: ... }` spoofing is rejected, and
    // `BYTES_PER_ELEMENT === 1` keeps the fallback on byte-oriented views.
    return (a instanceof Uint8Array ||
        (ArrayBuffer.isView(a) &&
            a.constructor.name === 'Uint8Array' &&
            'BYTES_PER_ELEMENT' in a &&
            a.BYTES_PER_ELEMENT === 1));
}
/**
 * Asserts something is a non-negative integer.
 * @param n - number to validate
 * @param title - label included in thrown errors
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate a non-negative integer option.
 * ```ts
 * anumber(32, 'length');
 * ```
 */
function anumber$1(n, title = '') {
    if (typeof n !== 'number') {
        const prefix = title && `"${title}" `;
        throw new TypeError(`${prefix}expected number, got ${typeof n}`);
    }
    if (!Number.isSafeInteger(n) || n < 0) {
        const prefix = title && `"${title}" `;
        throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
    }
}
/**
 * Asserts something is Uint8Array.
 * @param value - value to validate
 * @param length - optional exact length constraint
 * @param title - label included in thrown errors
 * @returns The validated byte array.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate that a value is a byte array.
 * ```ts
 * abytes(new Uint8Array([1, 2, 3]));
 * ```
 */
function abytes$1(value, length, title = '') {
    const bytes = isBytes$2(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || (needsLen)) {
        const prefix = title && `"${title}" `;
        const ofLen = '';
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        const message = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
        if (!bytes)
            throw new TypeError(message);
        throw new RangeError(message);
    }
    return value;
}
/**
 * Asserts a hash instance has not been destroyed or finished.
 * @param instance - hash instance to validate
 * @param checkFinished - whether to reject finalized instances
 * @throws If the hash instance has already been destroyed or finalized. {@link Error}
 * @example
 * Validate that a hash instance is still usable.
 * ```ts
 * import { aexists } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const hash = sha256.create();
 * aexists(hash);
 * ```
 */
function aexists$1(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/**
 * Asserts output is a sufficiently-sized byte array.
 * @param out - destination buffer
 * @param instance - hash instance providing output length
 * Oversized buffers are allowed; downstream code only promises to fill the first `outputLen` bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate a caller-provided digest buffer.
 * ```ts
 * import { aoutput } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const hash = sha256.create();
 * aoutput(new Uint8Array(hash.outputLen), hash);
 * ```
 */
function aoutput$1(out, instance) {
    abytes$1(out, undefined, 'digestInto() output');
    const min = instance.outputLen;
    if (out.length < min) {
        throw new RangeError('"digestInto() output" expected to be of length >=' + min);
    }
}
/**
 * Casts a typed array view to Uint32Array.
 * `arr.byteOffset` must already be 4-byte aligned or the platform
 * Uint32Array constructor will throw.
 * @param arr - source typed array
 * @returns Uint32Array view over the same buffer.
 * @example
 * Reinterpret a byte array as 32-bit words.
 * ```ts
 * u32(new Uint8Array(8));
 * ```
 */
function u32$1(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/**
 * Zeroizes typed arrays in place. Warning: JS provides no guarantees.
 * @param arrays - arrays to overwrite with zeros
 * @example
 * Zeroize sensitive buffers in place.
 * ```ts
 * clean(new Uint8Array([1, 2, 3]));
 * ```
 */
function clean$1(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/**
 * Creates a DataView for byte-level manipulation.
 * @param arr - source typed array
 * @returns DataView over the same buffer region.
 * @example
 * Create a DataView over an existing buffer.
 * ```ts
 * createView(new Uint8Array(4));
 * ```
 */
function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/**
 * Rotate-right operation for uint32 values.
 * @param word - source word
 * @param shift - shift amount in bits
 * @returns Rotated word.
 * @example
 * Rotate a 32-bit word to the right.
 * ```ts
 * rotr(0x12345678, 8);
 * ```
 */
function rotr(word, shift) {
    return (word << (32 - shift)) | (word >>> shift);
}
/** Whether the current platform is little-endian. */
const isLE$1 = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
/**
 * Byte-swap operation for uint32 values.
 * @param word - source word
 * @returns Word with reversed byte order.
 * @example
 * Reverse the byte order of a 32-bit word.
 * ```ts
 * byteSwap(0x11223344);
 * ```
 */
function byteSwap$1(word) {
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/**
 * Byte-swaps every word of a Uint32Array in place.
 * @param arr - array to mutate
 * @returns The same array after mutation; callers pass live state arrays here.
 * @example
 * Reverse the byte order of every word in place.
 * ```ts
 * byteSwap32(new Uint32Array([0x11223344]));
 * ```
 */
function byteSwap32$1(arr) {
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap$1(arr[i]);
    }
    return arr;
}
/**
 * Conditionally byte-swaps a Uint32Array on big-endian platforms.
 * @param u - array to normalize for host endianness
 * @returns Original or byte-swapped array depending on platform endianness.
 *   On big-endian runtimes this mutates `u` in place via `byteSwap32(...)`.
 * @example
 * Normalize a word array for host endianness.
 * ```ts
 * swap32IfBE(new Uint32Array([0x11223344]));
 * ```
 */
const swap32IfBE$1 = isLE$1
    ? (u) => u
    : byteSwap32$1;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin$1 = /* @__PURE__ */ (() => 
// @ts-ignore
typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * Convert byte array to hex string.
 * Uses the built-in function when available and assumes it matches the tested
 * fallback semantics.
 * @param bytes - bytes to encode
 * @returns Lowercase hexadecimal string.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Convert bytes to lowercase hexadecimal.
 * ```ts
 * bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])); // 'cafe0123'
 * ```
 */
function bytesToHex(bytes) {
    abytes$1(bytes);
    // @ts-ignore
    if (hasHexBuiltin$1)
        return bytes.toHex();
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
// We use optimized technique to convert hex string to byte array
const asciis$1 = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16$1(ch) {
    if (ch >= asciis$1._0 && ch <= asciis$1._9)
        return ch - asciis$1._0; // '2' => 50-48
    if (ch >= asciis$1.A && ch <= asciis$1.F)
        return ch - (asciis$1.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis$1.a && ch <= asciis$1.f)
        return ch - (asciis$1.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @param hex - hexadecimal string to decode
 * @returns Decoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Decode lowercase hexadecimal into bytes.
 * ```ts
 * hexToBytes('cafe0123'); // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 * ```
 */
function hexToBytes$2(hex) {
    if (typeof hex !== 'string')
        throw new TypeError('hex string expected, got ' + typeof hex);
    if (hasHexBuiltin$1) {
        try {
            return Uint8Array.fromHex(hex);
        }
        catch (error) {
            if (error instanceof SyntaxError)
                throw new RangeError(error.message);
            throw error;
        }
    }
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new RangeError('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16$1(hex.charCodeAt(hi));
        const n2 = asciiToBase16$1(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
/**
 * Creates a callable hash function from a stateful class constructor.
 * @param hashCons - hash constructor or factory
 * @param info - optional metadata such as DER OID
 * @returns Frozen callable hash wrapper with `.create()`.
 *   Wrapper construction eagerly calls `hashCons(undefined)` once to read
 *   `outputLen` / `blockLen`, so constructor side effects happen at module
 *   init time.
 * @example
 * Wrap a stateful hash constructor into a callable helper.
 * ```ts
 * import { createHasher } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const wrapped = createHasher(sha256.create, { oid: sha256.oid });
 * wrapped(new Uint8Array([1]));
 * ```
 */
function createHasher$1(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts)
        .update(msg)
        .digest();
    const tmp = hashCons(undefined);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
}
/**
 * Creates OID metadata for NIST hashes with prefix `06 09 60 86 48 01 65 03 04 02`.
 * @param suffix - final OID byte for the selected hash.
 *   The helper accepts any byte even though only the documented NIST hash
 *   suffixes are meaningful downstream.
 * @returns Object containing the DER-encoded OID.
 * @example
 * Build OID metadata for a NIST hash.
 * ```ts
 * oidNist(0x01);
 * ```
 */
const oidNist$1 = (suffix) => ({
    // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
    // Larger suffix values would need base-128 OID encoding and a different length byte.
    oid: Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix]),
});

/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out
 * {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf | FIPS-202},
 * {@link https://keccak.team/keccak.html | Website}, and
 * {@link https://crypto.stackexchange.com/q/15727 | the differences between
 * SHA-3 and Keccak}.
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */
// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n$1 = BigInt(0);
const _1n$1 = BigInt(1);
const _2n$1 = BigInt(2);
const _7n$1 = BigInt(7);
const _256n$1 = BigInt(256);
// FIPS 202 Algorithm 5 rc(): when the outgoing bit is 1, the 8-bit LFSR xors
// taps 0, 4, 5, and 6, which compresses to the feedback mask `0x71`.
const _0x71n$1 = BigInt(0x71);
const SHA3_PI$1 = [];
const SHA3_ROTL$1 = [];
const _SHA3_IOTA$1 = []; // no pure annotation: var is always used
for (let round = 0, R = _1n$1, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI$1.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL$1.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n$1;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n$1) ^ ((R >> _7n$1) * _0x71n$1)) % _256n$1;
        if (R & _2n$1)
            t ^= _1n$1 << ((_1n$1 << BigInt(j)) - _1n$1);
    }
    _SHA3_IOTA$1.push(t);
}
const IOTAS$1 = split$1(_SHA3_IOTA$1, true);
// `split(..., true)` keeps the local little-endian lane-word layout used by
// `state32`, so these `H` / `L` tables follow the file's first-word /
// second-word lane slots rather than `_u64.ts`'s usual high/low naming.
const SHA3_IOTA_H$1 = IOTAS$1[0];
const SHA3_IOTA_L$1 = IOTAS$1[1];
// Left rotation (without 0, 32, 64)
const rotlH$1 = (h, l, s) => (s > 32 ? rotlBH$1(h, l, s) : rotlSH$1(h, l, s));
const rotlL$1 = (h, l, s) => (s > 32 ? rotlBL$1(h, l, s) : rotlSL$1(h, l, s));
/**
 * `keccakf1600` internal permutation, additionally allows adjusting the round count.
 * @param s - 5x5 Keccak state encoded as 25 lanes split into 50 uint32 words
 *   in this file's local little-endian lane-word order
 * @param rounds - number of rounds to execute
 * @throws If `rounds` is outside the supported `1..24` range. {@link Error}
 * @example
 * Permute a Keccak state with the default 24 rounds.
 * ```ts
 * keccakP(new Uint32Array(50));
 * ```
 */
function keccakP$1(s, rounds = 24) {
    anumber$1(rounds, 'rounds');
    // This implementation precomputes only the standard Keccak-f[1600] 24-round Iota table.
    if (rounds < 1 || rounds > 24)
        throw new Error('"rounds" expected integer 1..24');
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++)
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH$1(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL$1(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL$1[t];
            const Th = rotlH$1(curH, curL, shift);
            const Tl = rotlL$1(curH, curL, shift);
            const PI = SHA3_PI$1[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        // Same as:
        // for (let x = 0; x < 10; x++) B[x] = s[y + x];
        // for (let x = 0; x < 10; x++) s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        for (let y = 0; y < 50; y += 10) {
            const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
            s[y] ^= ~s[y + 2] & s[y + 4];
            s[y + 1] ^= ~s[y + 3] & s[y + 5];
            s[y + 2] ^= ~s[y + 4] & s[y + 6];
            s[y + 3] ^= ~s[y + 5] & s[y + 7];
            s[y + 4] ^= ~s[y + 6] & s[y + 8];
            s[y + 5] ^= ~s[y + 7] & s[y + 9];
            s[y + 6] ^= ~s[y + 8] & b0;
            s[y + 7] ^= ~s[y + 9] & b1;
            s[y + 8] ^= ~b0 & b2;
            s[y + 9] ^= ~b1 & b3;
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H$1[round];
        s[1] ^= SHA3_IOTA_L$1[round];
    }
    clean$1(B);
}
/**
 * Keccak sponge function.
 * @param blockLen - absorb/squeeze rate in bytes
 * @param suffix - domain separation suffix byte
 * @param outputLen - default digest length in bytes. This base sponge only
 *   requires a non-negative integer; wrappers that need positive output
 *   lengths must enforce that themselves.
 * @param enableXOF - whether XOF output is allowed
 * @param rounds - number of Keccak-f rounds
 * @example
 * Build a sponge state, absorb bytes, then finalize a digest.
 * ```ts
 * const hash = new Keccak(136, 0x06, 32);
 * hash.update(new Uint8Array([1, 2, 3]));
 * hash.digest();
 * ```
 */
let Keccak$1 = class Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    canXOF;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.canXOF = enableXOF;
        this.rounds = rounds;
        // Can be passed from user as dkLen
        anumber$1(outputLen, 'outputLen');
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        // 0 < blockLen < 200
        if (!(0 < blockLen && blockLen < 200))
            throw new Error('only keccak-f1600 function is supported');
        this.state = new Uint8Array(200);
        this.state32 = u32$1(this.state);
    }
    clone() {
        return this._cloneInto();
    }
    keccak() {
        swap32IfBE$1(this.state32);
        keccakP$1(this.state32, this.rounds);
        swap32IfBE$1(this.state32);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        aexists$1(this);
        abytes$1(data);
        const { blockLen, state } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // FIPS 202 appends the SHA3/SHAKE domain-separation suffix before pad10*1.
        // These byte values already include the first padding bit, while the
        // final `0x80` below supplies the closing `1` bit in the last rate byte.
        state[pos] ^= suffix;
        // If that combined suffix lands in the last rate byte and already sets
        // bit 7, absorb it first so the final pad10*1 bit can be xored into a
        // fresh block.
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        aexists$1(this, false);
        abytes$1(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Plain SHA3/Keccak usage with XOF is probably a mistake, but this base
        // class is also reused by SHAKE/cSHAKE/KMAC/TupleHash/ParallelHash/
        // TurboSHAKE/KangarooTwelve wrappers that intentionally enable XOF.
        if (!this.enableXOF)
            throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        anumber$1(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        aoutput$1(out, this);
        if (this.finished)
            throw new Error('digest() was already called');
        // `aoutput(...)` allows oversized buffers; digestInto() must fill only the advertised digest.
        this.writeInto(out.subarray(0, this.outputLen));
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);
        return out;
    }
    destroy() {
        this.destroyed = true;
        clean$1(this.state);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        // Reused destinations can come from a different rate/capacity variant, so clone must rewrite
        // the sponge geometry as well as the state words.
        to.blockLen = blockLen;
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        // Clones must preserve the public capability bit too; `_KMAC` reuses this path and deep clone
        // tests compare instance fields directly, so leaving `canXOF` behind makes the clone lie.
        to.canXOF = this.canXOF;
        to.destroyed = this.destroyed;
        return to;
    }
};
const genShake$1 = (suffix, blockLen, outputLen, info = {}) => createHasher$1((opts = {}) => new Keccak$1(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true), info);
/**
 * SHAKE256 XOF with 256-bit security and a 32-byte default output.
 * @param msg - message bytes to hash
 * @param opts - Optional output-length override. See {@link ShakeOpts}.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHAKE256.
 * ```ts
 * shake256(new Uint8Array([97, 98, 99]), { dkLen: 64 });
 * ```
 */
const shake256$1 = 
/* @__PURE__ */
genShake$1(0x1f, 136, 32, /* @__PURE__ */ oidNist$1(0x0c));

/**
 * Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
 * @todo re-check https://issues.chromium.org/issues/42212588
 * @module
 */
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));

/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes$1(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is positive integer. */
function anumber(n, title = '') {
    if (!Number.isSafeInteger(n) || n < 0) {
        const prefix = title && `"${title}" `;
        throw new Error(`${prefix}expected integer >= 0, got ${n}`);
    }
}
/** Asserts something is Uint8Array. */
function abytes(value, length, title = '') {
    const bytes = isBytes$1(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || (needsLen)) {
        const prefix = title && `"${title}" `;
        const ofLen = '';
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        throw new Error(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
    abytes(out, undefined, 'digestInto() output');
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
}
/** Cast u8 / u16 / u32 to u32. */
function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
const isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
/** The byte swap operation for uint32 */
function byteSwap(word) {
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/** In place byte swap for Uint32Array */
function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
const swap32IfBE = isLE
    ? (u) => u
    : byteSwap32;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin = /* @__PURE__ */ (() => 
// @ts-ignore
typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes$1(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // @ts-ignore
    if (hasHexBuiltin)
        return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
/** Creates function with outputLen, blockLen, create properties from a class constructor. */
function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(undefined);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
}
/** Creates OID opts for NIST hashes, with prefix 06 09 60 86 48 01 65 03 04 02. */
const oidNist = (suffix) => ({
    oid: Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix]),
});

/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */
// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
const SHA3_PI = [];
const SHA3_ROTL = [];
const _SHA3_IOTA = []; // no pure annotation: var is always used
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
        if (R & _2n)
            t ^= _1n << ((_1n << BigInt(j)) - _1n);
    }
    _SHA3_IOTA.push(t);
}
const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (h, l, s) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));
/** `keccakf1600` internal function, additionally allows to adjust round count. */
function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++)
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        for (let y = 0; y < 50; y += 10) {
            for (let x = 0; x < 10; x++)
                B[x] = s[y + x];
            for (let x = 0; x < 10; x++)
                s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
}
/** Keccak sponge function. */
class Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        // Can be passed from user as dkLen
        anumber(outputLen, 'outputLen');
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        // 0 < blockLen < 200
        if (!(0 < blockLen && blockLen < 200))
            throw new Error('only keccak-f1600 function is supported');
        this.state = new Uint8Array(200);
        this.state32 = u32(this.state);
    }
    clone() {
        return this._cloneInto();
    }
    keccak() {
        swap32IfBE(this.state32);
        keccakP(this.state32, this.rounds);
        swap32IfBE(this.state32);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        aexists(this);
        abytes(data);
        const { blockLen, state } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // Do the padding
        state[pos] ^= suffix;
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        aexists(this, false);
        abytes(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
        if (!this.enableXOF)
            throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        anumber(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        aoutput(out, this);
        if (this.finished)
            throw new Error('digest() was already called');
        this.writeInto(out);
        this.destroy();
        return out;
    }
    digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
        this.destroyed = true;
        clean(this.state);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
const genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true), info);
/** SHAKE128 XOF with 128-bit security. */
const shake128 = 
/* @__PURE__ */
genShake(0x1f, 168, 16, /* @__PURE__ */ oidNist(0x0b));
/** SHAKE256 XOF with 256-bit security. */
const shake256 = 
/* @__PURE__ */
genShake(0x1f, 136, 32, /* @__PURE__ */ oidNist(0x0c));

const Shake128Rate = 168;
const Shake256Rate = 136;
const Stream128BlockBytes = Shake128Rate;
const Stream256BlockBytes = Shake256Rate;

const SeedBytes = 32;
const CRHBytes = 64;
const TRBytes = 64;
const RNDBytes = 32;
const N = 256;
const Q = 8380417;
const QInv = 58728449;
const D = 13;

const K = 8;
const L = 7;
const ETA = 2;
const TAU = 60;
const BETA = 120;
const GAMMA1 = 1 << 19;
const GAMMA2 = Math.floor((Q - 1) / 32);
const OMEGA = 75;
const CTILDEBytes = 64;

const PolyT1PackedBytes = 320;
const PolyT0PackedBytes = 416;
const PolyETAPackedBytes = 96;
const PolyZPackedBytes = 640;
const PolyVecHPackedBytes = OMEGA + K;
const PolyW1PackedBytes = 128;

const CryptoPublicKeyBytes = SeedBytes + K * PolyT1PackedBytes;
const CryptoSecretKeyBytes =
  2 * SeedBytes + TRBytes + L * PolyETAPackedBytes + K * PolyETAPackedBytes + K * PolyT0PackedBytes;
const CryptoBytes = CTILDEBytes + L * PolyZPackedBytes + PolyVecHPackedBytes;

const PolyUniformNBlocks = Math.floor((768 + Stream128BlockBytes - 1) / Stream128BlockBytes);
const PolyUniformETANBlocks = Math.floor((136 + Stream256BlockBytes - 1) / Stream256BlockBytes);
const PolyUniformGamma1NBlocks = Math.floor((PolyZPackedBytes + Stream256BlockBytes - 1) / Stream256BlockBytes);

const zetas = [
  0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251, -2091905, 3119733, -2884855,
  3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186, -3859737,
  -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516,
  3915439, -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
  -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598, -1000202,
  -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
  -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992, 44288,
  -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548, -3553272,
  3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669, -1584928, -812732, -1439742, -3019102, -3881060,
  -3628969, 3839961, 2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439,
  -1235728, 3513181, -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
  -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297, 286988, -2437823, 4108315,
  3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016,
  1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100,
  1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
  -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455, -164721, 1957272,
  3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916, 3523897,
  3866901, 269760, 2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646,
  -3833893, -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
  -1362209, 3937738, 1400424, -846154, 1976782,
];

/**
 * FIPS 202 SHAKE functions using @noble/hashes
 * Provides streaming XOF (extendable output function) interface
 */


/**
 * Keccak state wrapper for @noble/hashes
 * Maintains hasher instance for streaming operations
 */
class KeccakState {
  constructor() {
    this.hasher = null;
    this.finalized = false;
  }
}

// SHAKE-128 functions

function shake128Init(state) {
  state.hasher = shake128.create({});
  state.finalized = false;
}

function shake128Absorb(state, input) {
  state.hasher.update(input);
}

function shake128Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

function shake128SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake128Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

// SHAKE-256 functions

function shake256Init(state) {
  state.hasher = shake256.create({});
  state.finalized = false;
}

function shake256Absorb(state, input) {
  state.hasher.update(input);
}

function shake256Finalize(state) {
  // Mark as finalized - actual finalization happens on first xofInto call
  state.finalized = true;
}

function shake256SqueezeBlocks(out, outputOffset, nBlocks, state) {
  const len = nBlocks * Shake256Rate;
  const output = out.subarray(outputOffset, outputOffset + len);
  state.hasher.xofInto(output);
}

function mldsaShake128StreamInit(state, seed, nonce) {
  if (seed.length !== SeedBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${SeedBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake128Init(state);
  shake128Absorb(state, seed);
  shake128Absorb(state, t);
  shake128Finalize(state);
}

function mldsaShake256StreamInit(state, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | expected ${CRHBytes}`);
  }
  const t = new Uint8Array(2);
  t[0] = nonce & 0xff;
  t[1] = nonce >> 8;

  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Absorb(state, t);
  shake256Finalize(state);
}

function montgomeryReduce(a) {
  let t = BigInt.asIntN(32, BigInt.asIntN(64, BigInt.asIntN(32, a)) * BigInt(QInv));
  t = BigInt.asIntN(32, (a - t * BigInt(Q)) >> 32n);
  return t;
}

// Partial reduction modulo Q. Input must satisfy |a| < 2^31 - 2^22.
// Output is in (-Q, Q). Mirrors the reference C implementation.
function reduce32(a) {
  let t = (a + (1 << 22)) >> 23;
  t = a - t * Q;
  return t;
}

// Conditional add Q: if a is negative, add Q. Input must satisfy -Q < a < 2^31.
// Output is in [0, Q). Mirrors the reference C implementation.
function cAddQ(a) {
  let ar = a;
  ar += (ar >> 31) & Q;
  return ar;
}

function ntt(a) {
  let k = 0;
  let j;

  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = zetas[++k];
      for (j = start; j < start + len; ++j) {
        const t = Number(montgomeryReduce(BigInt.asIntN(64, BigInt(zeta) * BigInt(a[j + len]))));
        a[j + len] = a[j] - t;
        a[j] += t;
      }
    }
  }
}

function invNTTToMont(a) {
  const f = 41978n; // mont^2/256
  let j;
  let k = 256;

  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start = j + len) {
      const zeta = BigInt.asIntN(32, BigInt(-zetas[--k]));
      for (j = start; j < start + len; ++j) {
        const t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = Number(montgomeryReduce(BigInt.asIntN(64, zeta * BigInt(a[j + len]))));
      }
    }
  }
  for (let j = 0; j < N; ++j) {
    a[j] = Number(montgomeryReduce(BigInt.asIntN(64, f * BigInt(a[j]))));
  }
}

function power2round(a0p, i, a) {
  const a0 = a0p;
  const a1 = (a + (1 << (D - 1)) - 1) >> D;
  a0[i] = a - (a1 << D);
  return a1;
}

function decompose(a0p, i, a) {
  const a0 = a0p;
  let a1 = (a + 127) >> 7;
  a1 = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;

  a0[i] = a - a1 * 2 * GAMMA2;
  a0[i] -= (((Q - 1) / 2 - a0[i]) >> 31) & Q;
  return a1;
}

function makeHint(a0, a1) {
  if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 === -GAMMA2 && a1 !== 0)) return 1;

  return 0;
}

function useHint(a, hint) {
  const a0 = new Int32Array(1);
  const a1 = decompose(a0, 0, a);

  if (hint === 0) return a1;

  if (a0[0] > 0) return (a1 + 1) & 15;
  return (a1 - 1) & 15;
}

class Poly {
  constructor() {
    this.coeffs = new Int32Array(N);
  }

  copy(poly) {
    for (let i = N - 1; i >= 0; i--) {
      this.coeffs[i] = poly.coeffs[i];
    }
  }
}

function polyReduce(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = reduce32(a.coeffs[i]);
}

function polyCAddQ(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] = cAddQ(a.coeffs[i]);
}

function polyAdd(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
}

function polySub(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
}

function polyShiftL(aP) {
  const a = aP;
  for (let i = 0; i < N; ++i) a.coeffs[i] <<= D;
}

function polyNTT(a) {
  ntt(a.coeffs);
}

function polyInvNTTToMont(a) {
  invNTTToMont(a.coeffs);
}

function polyPointWiseMontgomery(cP, a, b) {
  const c = cP;
  for (let i = 0; i < N; ++i) c.coeffs[i] = Number(montgomeryReduce(BigInt(a.coeffs[i]) * BigInt(b.coeffs[i])));
}

function polyPower2round(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = power2round(a0.coeffs, i, a.coeffs[i]);
}

function polyDecompose(a1p, a0, a) {
  const a1 = a1p;
  for (let i = 0; i < N; ++i) a1.coeffs[i] = decompose(a0.coeffs, i, a.coeffs[i]);
}

function polyMakeHint(hp, a0, a1) {
  let s = 0;
  const h = hp;
  for (let i = 0; i < N; ++i) {
    h.coeffs[i] = makeHint(a0.coeffs[i], a1.coeffs[i]);
    s += h.coeffs[i];
  }

  return s;
}

function polyUseHint(bp, a, h) {
  const b = bp;
  for (let i = 0; i < N; ++i) {
    b.coeffs[i] = useHint(a.coeffs[i], h.coeffs[i]);
  }
}

function polyChkNorm(a, b) {
  if (b > Math.floor((Q - 1) / 8)) {
    return 1;
  }

  for (let i = 0; i < N; i++) {
    if (Math.abs(a.coeffs[i]) >= b) {
      return 1;
    }
  }

  return 0;
}

function rejUniform(ap, aOffset, len, buf, bufLen) {
  let ctr = 0;
  let pos = 0;
  const a = ap;
  while (ctr < len && pos + 3 <= bufLen) {
    let t = buf[pos++];
    t |= buf[pos++] << 8;
    t |= buf[pos++] << 16;
    t &= 0x7fffff;

    if (t < Q) {
      a[aOffset + ctr++] = t;
    }
  }

  return ctr;
}

function polyUniform(a, seed, nonce) {
  let off = 0;
  let bufLen = PolyUniformNBlocks * Stream128BlockBytes;
  const buf = new Uint8Array(PolyUniformNBlocks * Stream128BlockBytes + 2);

  const state = new KeccakState();
  mldsaShake128StreamInit(state, seed, nonce);
  shake128SqueezeBlocks(buf, off, PolyUniformNBlocks, state);

  let ctr = rejUniform(a.coeffs, 0, N, buf, bufLen);

  // Note: With current parameters, needing extra blocks is vanishingly unlikely.
  /* c8 ignore start */
  while (ctr < N) {
    off = bufLen % 3;
    for (let i = 0; i < off; ++i) buf[i] = buf[bufLen - off + i];

    shake128SqueezeBlocks(buf, off, 1, state);
    bufLen = Stream128BlockBytes + off;
    ctr += rejUniform(a.coeffs, ctr, N - ctr, buf, bufLen);
  }
  /* c8 ignore stop */
}

function rejEta(aP, aOffset, len, buf, bufLen) {
  let ctr;
  let pos;
  let t0;
  let t1;
  const a = aP;
  ctr = 0;
  pos = 0;
  while (ctr < len && pos < bufLen) {
    t0 = buf[pos] & 0x0f;
    t1 = buf[pos++] >> 4;

    if (t0 < 15) {
      t0 -= ((205 * t0) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t0;
    }
    if (t1 < 15 && ctr < len) {
      t1 -= ((205 * t1) >> 10) * 5;
      a[aOffset + ctr++] = 2 - t1;
    }
  }

  return ctr;
}

function polyUniformEta(a, seed, nonce) {
  let ctr;
  const bufLen = PolyUniformETANBlocks * Stream256BlockBytes;
  const buf = new Uint8Array(bufLen);

  const state = new KeccakState();
  mldsaShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformETANBlocks, state);

  ctr = rejEta(a.coeffs, 0, N, buf, bufLen);
  while (ctr < N) {
    shake256SqueezeBlocks(buf, 0, 1, state);
    ctr += rejEta(a.coeffs, ctr, N - ctr, buf, Stream256BlockBytes);
  }
}

function polyZUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r.coeffs[2 * i] = a[aOffset + 5 * i];
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 1] << 8;
    r.coeffs[2 * i] |= a[aOffset + 5 * i + 2] << 16;
    r.coeffs[2 * i] &= 0xfffff;

    r.coeffs[2 * i + 1] = a[aOffset + 5 * i + 2] >> 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 3] << 4;
    r.coeffs[2 * i + 1] |= a[aOffset + 5 * i + 4] << 12;
    r.coeffs[2 * i + 1] &= 0xfffff;

    r.coeffs[2 * i] = GAMMA1 - r.coeffs[2 * i];
    r.coeffs[2 * i + 1] = GAMMA1 - r.coeffs[2 * i + 1];
  }
}

function polyUniformGamma1(a, seed, nonce) {
  const buf = new Uint8Array(PolyUniformGamma1NBlocks * Stream256BlockBytes);

  const state = new KeccakState();
  mldsaShake256StreamInit(state, seed, nonce);
  shake256SqueezeBlocks(buf, 0, PolyUniformGamma1NBlocks, state);
  polyZUnpack(a, buf, 0);
}

function polyChallenge(cP, seed) {
  if (seed.length !== CTILDEBytes) throw new Error('invalid ctilde length');

  let b;
  let pos;
  const c = cP;
  const buf = new Uint8Array(Shake256Rate);

  const state = new KeccakState();
  shake256Init(state);
  shake256Absorb(state, seed);
  shake256Finalize(state);
  shake256SqueezeBlocks(buf, 0, 1, state);

  let signs = 0n;
  for (let i = 0; i < 8; ++i) {
    signs = BigInt.asUintN(64, signs | (BigInt(buf[i]) << BigInt(8 * i)));
  }
  pos = 8;

  for (let i = 0; i < N; ++i) {
    c.coeffs[i] = 0;
  }
  for (let i = N - TAU; i < N; ++i) {
    do {
      // Note: Re-squeezing here is extremely unlikely with TAU=60.
      /* c8 ignore start */
      if (pos >= Shake256Rate) {
        shake256SqueezeBlocks(buf, 0, 1, state);
        pos = 0;
      }
      /* c8 ignore stop */

      b = buf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = Number(1n - 2n * (signs & 1n));
    signs >>= 1n;
  }
}

function polyEtaPack(rP, rOffset, a) {
  const t = new Uint8Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = ETA - a.coeffs[8 * i];
    t[1] = ETA - a.coeffs[8 * i + 1];
    t[2] = ETA - a.coeffs[8 * i + 2];
    t[3] = ETA - a.coeffs[8 * i + 3];
    t[4] = ETA - a.coeffs[8 * i + 4];
    t[5] = ETA - a.coeffs[8 * i + 5];
    t[6] = ETA - a.coeffs[8 * i + 6];
    t[7] = ETA - a.coeffs[8 * i + 7];

    r[rOffset + 3 * i] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[rOffset + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[rOffset + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
}

function polyEtaUnpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = (a[aOffset + 3 * i] >> 0) & 7;
    r.coeffs[8 * i + 1] = (a[aOffset + 3 * i] >> 3) & 7;
    r.coeffs[8 * i + 2] = ((a[aOffset + 3 * i] >> 6) | (a[aOffset + 3 * i + 1] << 2)) & 7;
    r.coeffs[8 * i + 3] = (a[aOffset + 3 * i + 1] >> 1) & 7;
    r.coeffs[8 * i + 4] = (a[aOffset + 3 * i + 1] >> 4) & 7;
    r.coeffs[8 * i + 5] = ((a[aOffset + 3 * i + 1] >> 7) | (a[aOffset + 3 * i + 2] << 1)) & 7;
    r.coeffs[8 * i + 6] = (a[aOffset + 3 * i + 2] >> 2) & 7;
    r.coeffs[8 * i + 7] = (a[aOffset + 3 * i + 2] >> 5) & 7;

    r.coeffs[8 * i] = ETA - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = ETA - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = ETA - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = ETA - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = ETA - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = ETA - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = ETA - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = ETA - r.coeffs[8 * i + 7];
  }
}

function polyT1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r[rOffset + 5 * i] = a.coeffs[4 * i] >> 0;
    r[rOffset + 5 * i + 1] = (a.coeffs[4 * i] >> 8) | (a.coeffs[4 * i + 1] << 2);
    r[rOffset + 5 * i + 2] = (a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4);
    r[rOffset + 5 * i + 3] = (a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6);
    r[rOffset + 5 * i + 4] = a.coeffs[4 * i + 3] >> 2;
  }
}

function polyT1Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 4; ++i) {
    r.coeffs[4 * i] = ((a[aOffset + 5 * i] >> 0) | (a[aOffset + 5 * i + 1] << 8)) & 0x3ff;
    r.coeffs[4 * i + 1] = ((a[aOffset + 5 * i + 1] >> 2) | (a[aOffset + 5 * i + 2] << 6)) & 0x3ff;
    r.coeffs[4 * i + 2] = ((a[aOffset + 5 * i + 2] >> 4) | (a[aOffset + 5 * i + 3] << 4)) & 0x3ff;
    r.coeffs[4 * i + 3] = ((a[aOffset + 5 * i + 3] >> 6) | (a[aOffset + 5 * i + 4] << 2)) & 0x3ff;
  }
}

function polyT0Pack(rP, rOffset, a) {
  const t = new Uint32Array(8);
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    t[0] = (1 << (D - 1)) - a.coeffs[8 * i];
    t[1] = (1 << (D - 1)) - a.coeffs[8 * i + 1];
    t[2] = (1 << (D - 1)) - a.coeffs[8 * i + 2];
    t[3] = (1 << (D - 1)) - a.coeffs[8 * i + 3];
    t[4] = (1 << (D - 1)) - a.coeffs[8 * i + 4];
    t[5] = (1 << (D - 1)) - a.coeffs[8 * i + 5];
    t[6] = (1 << (D - 1)) - a.coeffs[8 * i + 6];
    t[7] = (1 << (D - 1)) - a.coeffs[8 * i + 7];

    r[rOffset + 13 * i] = t[0];
    r[rOffset + 13 * i + 1] = t[0] >> 8;
    r[rOffset + 13 * i + 1] |= t[1] << 5;
    r[rOffset + 13 * i + 2] = t[1] >> 3;
    r[rOffset + 13 * i + 3] = t[1] >> 11;
    r[rOffset + 13 * i + 3] |= t[2] << 2;
    r[rOffset + 13 * i + 4] = t[2] >> 6;
    r[rOffset + 13 * i + 4] |= t[3] << 7;
    r[rOffset + 13 * i + 5] = t[3] >> 1;
    r[rOffset + 13 * i + 6] = t[3] >> 9;
    r[rOffset + 13 * i + 6] |= t[4] << 4;
    r[rOffset + 13 * i + 7] = t[4] >> 4;
    r[rOffset + 13 * i + 8] = t[4] >> 12;
    r[rOffset + 13 * i + 8] |= t[5] << 1;
    r[rOffset + 13 * i + 9] = t[5] >> 7;
    r[rOffset + 13 * i + 9] |= t[6] << 6;
    r[rOffset + 13 * i + 10] = t[6] >> 2;
    r[rOffset + 13 * i + 11] = t[6] >> 10;
    r[rOffset + 13 * i + 11] |= t[7] << 3;
    r[rOffset + 13 * i + 12] = t[7] >> 5;
  }
}

function polyT0Unpack(rP, a, aOffset) {
  const r = rP;
  for (let i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i] = a[aOffset + 13 * i];
    r.coeffs[8 * i] |= a[aOffset + 13 * i + 1] << 8;
    r.coeffs[8 * i] &= 0x1fff;

    r.coeffs[8 * i + 1] = a[aOffset + 13 * i + 1] >> 5;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 2] << 3;
    r.coeffs[8 * i + 1] |= a[aOffset + 13 * i + 3] << 11;
    r.coeffs[8 * i + 1] &= 0x1fff;

    r.coeffs[8 * i + 2] = a[aOffset + 13 * i + 3] >> 2;
    r.coeffs[8 * i + 2] |= a[aOffset + 13 * i + 4] << 6;
    r.coeffs[8 * i + 2] &= 0x1fff;

    r.coeffs[8 * i + 3] = a[aOffset + 13 * i + 4] >> 7;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 5] << 1;
    r.coeffs[8 * i + 3] |= a[aOffset + 13 * i + 6] << 9;
    r.coeffs[8 * i + 3] &= 0x1fff;

    r.coeffs[8 * i + 4] = a[aOffset + 13 * i + 6] >> 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 7] << 4;
    r.coeffs[8 * i + 4] |= a[aOffset + 13 * i + 8] << 12;
    r.coeffs[8 * i + 4] &= 0x1fff;

    r.coeffs[8 * i + 5] = a[aOffset + 13 * i + 8] >> 1;
    r.coeffs[8 * i + 5] |= a[aOffset + 13 * i + 9] << 7;
    r.coeffs[8 * i + 5] &= 0x1fff;

    r.coeffs[8 * i + 6] = a[aOffset + 13 * i + 9] >> 6;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 10] << 2;
    r.coeffs[8 * i + 6] |= a[aOffset + 13 * i + 11] << 10;
    r.coeffs[8 * i + 6] &= 0x1fff;

    r.coeffs[8 * i + 7] = a[aOffset + 13 * i + 11] >> 3;
    r.coeffs[8 * i + 7] |= a[aOffset + 13 * i + 12] << 5;
    r.coeffs[8 * i + 7] &= 0x1fff;

    r.coeffs[8 * i] = (1 << (D - 1)) - r.coeffs[8 * i];
    r.coeffs[8 * i + 1] = (1 << (D - 1)) - r.coeffs[8 * i + 1];
    r.coeffs[8 * i + 2] = (1 << (D - 1)) - r.coeffs[8 * i + 2];
    r.coeffs[8 * i + 3] = (1 << (D - 1)) - r.coeffs[8 * i + 3];
    r.coeffs[8 * i + 4] = (1 << (D - 1)) - r.coeffs[8 * i + 4];
    r.coeffs[8 * i + 5] = (1 << (D - 1)) - r.coeffs[8 * i + 5];
    r.coeffs[8 * i + 6] = (1 << (D - 1)) - r.coeffs[8 * i + 6];
    r.coeffs[8 * i + 7] = (1 << (D - 1)) - r.coeffs[8 * i + 7];
  }
}

function polyZPack(rP, rOffset, a) {
  const t = new Uint32Array(4);
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    t[0] = GAMMA1 - a.coeffs[2 * i];
    t[1] = GAMMA1 - a.coeffs[2 * i + 1];

    r[rOffset + 5 * i] = t[0];
    r[rOffset + 5 * i + 1] = t[0] >> 8;
    r[rOffset + 5 * i + 2] = t[0] >> 16;
    r[rOffset + 5 * i + 2] |= t[1] << 4;
    r[rOffset + 5 * i + 3] = t[1] >> 4;
    r[rOffset + 5 * i + 4] = t[1] >> 12;
  }
}

function polyW1Pack(rP, rOffset, a) {
  const r = rP;
  for (let i = 0; i < N / 2; ++i) {
    r[rOffset + i] = a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4);
  }
}

class PolyVecK {
  constructor() {
    this.vec = new Array(K).fill().map(() => new Poly());
  }
}

class PolyVecL {
  constructor() {
    this.vec = new Array(L).fill().map(() => new Poly());
  }

  copy(polyVecL) {
    for (let i = L - 1; i >= 0; i--) {
      this.vec[i].copy(polyVecL.vec[i]);
    }
  }
}

function polyVecMatrixExpand(mat, rho) {
  if (rho.length !== SeedBytes) {
    throw new Error(`invalid rho length ${rho.length} | Expected length ${SeedBytes}`);
  }
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < L; ++j) {
      polyUniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

function polyVecMatrixPointWiseMontgomery(t, mat, v) {
  for (let i = 0; i < K; ++i) {
    polyVecLPointWiseAccMontgomery(t.vec[i], mat[i], v);
  }
}

function polyVecLUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecLUniformGamma1(v, seed, nonce) {
  if (seed.length !== CRHBytes) {
    throw new Error(`invalid seed length ${seed.length} | Expected length ${CRHBytes}`);
  }
  for (let i = 0; i < L; i++) {
    polyUniformGamma1(v.vec[i], seed, L * nonce + i);
  }
}

function polyVecLReduce(v) {
  for (let i = 0; i < L; i++) {
    polyReduce(v.vec[i]);
  }
}

function polyVecLAdd(w, u, v) {
  for (let i = 0; i < L; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecLNTT(v) {
  for (let i = 0; i < L; ++i) {
    polyNTT(v.vec[i]);
  }
}

function polyVecLInvNTTToMont(v) {
  for (let i = 0; i < L; ++i) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecLPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < L; ++i) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecLPointWiseAccMontgomery(w, u, v) {
  const t = new Poly();
  polyPointWiseMontgomery(w, u.vec[0], v.vec[0]);
  for (let i = 1; i < L; i++) {
    polyPointWiseMontgomery(t, u.vec[i], v.vec[i]);
    polyAdd(w, w, t);
  }
}

function polyVecLChkNorm(v, bound) {
  for (let i = 0; i < L; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKUniformEta(v, seed, nonceP) {
  let nonce = nonceP;
  for (let i = 0; i < K; ++i) {
    polyUniformEta(v.vec[i], seed, nonce++);
  }
}

function polyVecKReduce(v) {
  for (let i = 0; i < K; ++i) {
    polyReduce(v.vec[i]);
  }
}

function polyVecKCAddQ(v) {
  for (let i = 0; i < K; ++i) {
    polyCAddQ(v.vec[i]);
  }
}

function polyVecKAdd(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polyAdd(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKSub(w, u, v) {
  for (let i = 0; i < K; ++i) {
    polySub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyVecKShiftL(v) {
  for (let i = 0; i < K; ++i) {
    polyShiftL(v.vec[i]);
  }
}

function polyVecKNTT(v) {
  for (let i = 0; i < K; i++) {
    polyNTT(v.vec[i]);
  }
}

function polyVecKInvNTTToMont(v) {
  for (let i = 0; i < K; i++) {
    polyInvNTTToMont(v.vec[i]);
  }
}

function polyVecKPointWisePolyMontgomery(r, a, v) {
  for (let i = 0; i < K; i++) {
    polyPointWiseMontgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyVecKChkNorm(v, bound) {
  for (let i = 0; i < K; i++) {
    if (polyChkNorm(v.vec[i], bound) !== 0) {
      return 1;
    }
  }
  return 0;
}

function polyVecKPower2round(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyPower2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKDecompose(v1, v0, v) {
  for (let i = 0; i < K; i++) {
    polyDecompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyVecKMakeHint(h, v0, v1) {
  let s = 0;
  for (let i = 0; i < K; i++) {
    s += polyMakeHint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

function polyVecKUseHint(w, u, h) {
  for (let i = 0; i < K; ++i) {
    polyUseHint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

function polyVecKPackW1(r, w1) {
  for (let i = 0; i < K; ++i) {
    polyW1Pack(r, i * PolyW1PackedBytes, w1.vec[i]);
  }
}

function packPk(pkp, rho, t1) {
  const pk = pkp;
  for (let i = 0; i < SeedBytes; ++i) {
    pk[i] = rho[i];
  }
  for (let i = 0; i < K; ++i) {
    polyT1Pack(pk, SeedBytes + i * PolyT1PackedBytes, t1.vec[i]);
  }
}

function unpackPk(rhop, t1, pk) {
  if (!(pk instanceof Uint8Array) || pk.length !== CryptoPublicKeyBytes) {
    throw new Error(`pk must be a Uint8Array of ${CryptoPublicKeyBytes} bytes`);
  }
  const rho = rhop;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = pk[i];
  }

  for (let i = 0; i < K; ++i) {
    polyT1Unpack(t1.vec[i], pk, SeedBytes + i * PolyT1PackedBytes);
  }
}

function packSk(skp, rho, tr, key, t0, s1, s2) {
  let skOffset = 0;
  const sk = skp;
  for (let i = 0; i < SeedBytes; ++i) {
    sk[i] = rho[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    sk[skOffset + i] = key[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < TRBytes; ++i) {
    sk[skOffset + i] = tr[i];
  }
  skOffset += TRBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s1.vec[i]);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaPack(sk, skOffset + i * PolyETAPackedBytes, s2.vec[i]);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Pack(sk, skOffset + i * PolyT0PackedBytes, t0.vec[i]);
  }
}

function unpackSk(rhoP, trP, keyP, t0, s1, s2, sk) {
  if (!(sk instanceof Uint8Array) || sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`sk must be a Uint8Array of ${CryptoSecretKeyBytes} bytes`);
  }
  let skOffset = 0;
  const rho = rhoP;
  const tr = trP;
  const key = keyP;
  for (let i = 0; i < SeedBytes; ++i) {
    rho[i] = sk[i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < SeedBytes; ++i) {
    key[i] = sk[skOffset + i];
  }
  skOffset += SeedBytes;

  for (let i = 0; i < TRBytes; ++i) {
    tr[i] = sk[skOffset + i];
  }
  skOffset += TRBytes;

  for (let i = 0; i < L; ++i) {
    polyEtaUnpack(s1.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += L * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyEtaUnpack(s2.vec[i], sk, skOffset + i * PolyETAPackedBytes);
  }
  skOffset += K * PolyETAPackedBytes;

  for (let i = 0; i < K; ++i) {
    polyT0Unpack(t0.vec[i], sk, skOffset + i * PolyT0PackedBytes);
  }
}

function packSig(sigP, ctilde, z, h) {
  let sigOffset = 0;
  const sig = sigP;
  for (let i = 0; i < CTILDEBytes; ++i) {
    sig[i] = ctilde[i];
  }
  sigOffset += CTILDEBytes;

  for (let i = 0; i < L; ++i) {
    polyZPack(sig, sigOffset + i * PolyZPackedBytes, z.vec[i]);
  }
  sigOffset += L * PolyZPackedBytes;

  for (let i = 0; i < OMEGA + K; ++i) {
    sig[sigOffset + i] = 0;
  }

  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      if (h.vec[i].coeffs[j] !== 0) {
        if (h.vec[i].coeffs[j] !== 1) {
          throw new Error('hint coefficients must be binary (0 or 1)');
        }
        if (k >= OMEGA) {
          throw new Error(`hint count exceeds OMEGA (${OMEGA})`);
        }
        sig[sigOffset + k++] = j;
      }
    }

    sig[sigOffset + OMEGA + i] = k;
  }
}

// Returns 0 on success, 1 on failure. On failure, output buffers (c, z, h)
// may contain partial data and must not be used.
function unpackSig(cP, z, hP, sig) {
  if (!(sig instanceof Uint8Array) || sig.length !== CryptoBytes) {
    throw new Error(`sig must be a Uint8Array of ${CryptoBytes} bytes`);
  }
  let sigOffset = 0;
  const c = cP; // ctilde
  const h = hP;
  for (let i = 0; i < CTILDEBytes; ++i) {
    c[i] = sig[i];
  }
  sigOffset += CTILDEBytes;

  for (let i = 0; i < L; ++i) {
    polyZUnpack(z.vec[i], sig, sigOffset + i * PolyZPackedBytes);
  }
  sigOffset += L * PolyZPackedBytes;

  /* Decode h */
  let k = 0;
  for (let i = 0; i < K; ++i) {
    for (let j = 0; j < N; ++j) {
      h.vec[i].coeffs[j] = 0;
    }

    if (sig[sigOffset + OMEGA + i] < k || sig[sigOffset + OMEGA + i] > OMEGA) {
      return 1;
    }

    for (let j = k; j < sig[sigOffset + OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if (j > k && sig[sigOffset + j] <= sig[sigOffset + j - 1]) {
        return 1;
      }
      h.vec[i].coeffs[sig[sigOffset + j]] = 1;
    }

    k = sig[sigOffset + OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for (let j = k; j < OMEGA; ++j) {
    if (sig[sigOffset + j]) {
      return 1;
    }
  }

  return 0;
}

const MAX_BYTES$1 = 65536;

function getWebCrypto$1() {
  if (typeof globalThis === 'object' && globalThis.crypto) return globalThis.crypto;
  return null;
}

function randomBytes$1(size) {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError('size must be a non-negative integer');
  }

  const cryptoObj = getWebCrypto$1();
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i += MAX_BYTES$1) {
      cryptoObj.getRandomValues(out.subarray(i, Math.min(size, i + MAX_BYTES$1)));
    }
    {
      let acc = 0;
      for (let i = 0; i < 16; i++) acc |= out[i];
      if (acc === 0) throw new Error('getRandomValues returned all zeros');
    }
    return out;
  }

  throw new Error('Secure random number generation is not supported by this environment');
}

/**
 * Security utilities for post-quantum signature schemes
 *
 * IMPORTANT: JavaScript cannot guarantee secure memory zeroization.
 * See SECURITY.md for details on limitations.
 */

/**
 * Attempts to zero out a Uint8Array buffer.
 *
 * WARNING: This is a BEST-EFFORT operation. Due to JavaScript/JIT limitations:
 * - The write may be optimized away if the buffer is unused afterward
 * - Copies may exist in garbage collector memory
 * - Data may have been swapped to disk
 *
 * For high-security applications, consider native implementations (go-qrllib)
 * or hardware security modules.
 *
 * @param {Uint8Array} buffer - The buffer to zero
 * @returns {void}
 * @throws {TypeError} If buffer is not a Uint8Array
 * @throws {Error} If zeroization verification fails
 */
function zeroize(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('zeroize requires a Uint8Array');
  }
  // Use fill(0) for zeroing - best effort
  buffer.fill(0);
  // Accumulator-OR over all bytes to discourage dead-store elimination
  // (Reading every byte makes it harder for JIT to prove fill is dead)
  let check = 0;
  for (let i = 0; i < buffer.length; i++) check |= buffer[i];
  if (check !== 0) {
    throw new Error('zeroize failed');
  }
}

/**
 * Convert hex string to Uint8Array with strict validation.
 *
 * Accepts an optional 0x/0X prefix. Leading/trailing whitespace is rejected.
 * Empty strings and whitespace-only strings are rejected.
 *
 * @param {string} hex - Hex string (optional 0x prefix, even length, no whitespace).
 * @returns {Uint8Array} Decoded bytes.
 * @throws {Error} If input is not a valid hex string
 * @private
 */
function hexToBytes(hex) {
  /* c8 ignore start */
  if (typeof hex !== 'string') {
    throw new Error('message must be a hex string');
  }
  /* c8 ignore stop */
  if (hex !== hex.trim()) {
    throw new Error('hex string must not have leading or trailing whitespace');
  }
  let clean = hex;
  if (clean.startsWith('0x') || clean.startsWith('0X')) {
    clean = clean.slice(2);
  }
  if (clean.length === 0) {
    throw new Error('hex string must not be empty');
  }
  if (clean.length % 2 !== 0) {
    throw new Error('hex string must have an even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('hex string contains non-hex characters');
  }
  return hexToBytes$1(clean);
}

/**
 * Convert a message to Uint8Array.
 *
 * @param {string|Uint8Array} message - Message as hex string (optional 0x prefix) or Uint8Array.
 * @returns {Uint8Array} Message bytes.
 * @throws {Error} If message is not a Uint8Array or valid hex string
 * @private
 */
function messageToBytes(message) {
  if (typeof message === 'string') {
    return hexToBytes(message);
  }
  if (message instanceof Uint8Array) {
    return message;
  }
  throw new Error('message must be Uint8Array or hex string');
}

/**
 * Generate an ML-DSA-87 key pair.
 *
 * Key generation follows FIPS 204, using domain separator [K, L] during
 * seed expansion to ensure algorithm binding.
 *
 * @param {Uint8Array|null} [passedSeed=null] - Optional 32-byte seed for deterministic key generation.
 *   Pass null or undefined for random key generation.
 * @param {Uint8Array} pk - Output buffer for public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} sk - Output buffer for secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @returns {Uint8Array} The seed used for key generation (useful when passedSeed is null)
 * @throws {Error} If pk/sk buffers are null or wrong size, or if seed is wrong size
 *
 * @example
 * const pk = new Uint8Array(CryptoPublicKeyBytes);
 * const sk = new Uint8Array(CryptoSecretKeyBytes);
 * const seed = cryptoSignKeypair(null, pk, sk);
 */
function cryptoSignKeypair(passedSeed, pk, sk) {
  try {
    if (pk.length !== CryptoPublicKeyBytes) {
      throw new Error(`invalid pk length ${pk.length} | Expected length ${CryptoPublicKeyBytes}`);
    }
    if (sk.length !== CryptoSecretKeyBytes) {
      throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(`pk/sk cannot be null`, { cause: e });
    } else {
      throw new Error(`${e.message}`, { cause: e });
    }
  }

  // Validate seed length if provided
  if (passedSeed !== null && passedSeed !== undefined) {
    if (passedSeed.length !== SeedBytes) {
      throw new Error(`invalid seed length ${passedSeed.length} | Expected length ${SeedBytes}`);
    }
  }

  const mat = new Array(K).fill().map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const s2 = new PolyVecK();
  const t1 = new PolyVecK();
  const t0 = new PolyVecK();

  // Expand seed -> rho(32), rhoPrime(64), key(32) with domain sep [K, L]
  const seed = passedSeed || randomBytes$1(SeedBytes);

  const outputLength = 2 * SeedBytes + CRHBytes;
  const domainSep = new Uint8Array([K, L]);
  const seedBuf = shake256.create({}).update(seed).update(domainSep).xof(outputLength);
  const rho = seedBuf.slice(0, SeedBytes);
  const rhoPrime = seedBuf.slice(SeedBytes, SeedBytes + CRHBytes);
  const key = seedBuf.slice(SeedBytes + CRHBytes);

  let s1hat;
  try {
    // Expand matrix
    polyVecMatrixExpand(mat, rho);

    // Sample short vectors s1 and s2
    polyVecLUniformEta(s1, rhoPrime, 0);
    polyVecKUniformEta(s2, rhoPrime, L);

    // Matrix-vector multiplication
    s1hat = new PolyVecL();
    s1hat.copy(s1);
    polyVecLNTT(s1hat);
    polyVecMatrixPointWiseMontgomery(t1, mat, s1hat);
    polyVecKReduce(t1);
    polyVecKInvNTTToMont(t1);

    // Add error vector s2
    polyVecKAdd(t1, t1, s2);

    // Extract t1 and write public key
    polyVecKCAddQ(t1);
    polyVecKPower2round(t1, t0, t1);
    packPk(pk, rho, t1);

    // Compute tr = SHAKE256(pk) (64 bytes) and write secret key
    const tr = shake256.create({}).update(pk).xof(TRBytes);
    packSk(sk, rho, tr, key, t0, s1, s2);

    return seed;
  } finally {
    zeroize(seedBuf);
    zeroize(rhoPrime);
    zeroize(key);
    for (let i = 0; i < L; i++) s1.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) s2.vec[i].coeffs.fill(0);
    if (s1hat) for (let i = 0; i < L; i++) s1hat.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) t0.vec[i].coeffs.fill(0);
  }
}

/**
 * Create a detached signature for a message with context.
 *
 * Uses the ML-DSA-87 (FIPS 204) signing algorithm with rejection sampling.
 * The context parameter provides domain separation as required by FIPS 204.
 *
 * # Signing-mode recommendation (TOB-QRLLIB-6)
 *
 * **Hedged signing (`randomizedSigning = true`) is the recommended mode**
 * per FIPS 204 §3.4: the per-signature nonce mixes fresh `crypto.getRandomValues`
 * randomness, which frustrates the fault-injection attack class against
 * deterministic signing where an adversary who can flip a single bit during
 * the `z` computation can differentiate two same-message signatures and
 * recover `s1`/`s2` by lattice differential analysis. Verification is
 * unchanged — hedged and deterministic signatures verify under the same
 * public key.
 *
 * **Use deterministic signing (`randomizedSigning = false`) only when the
 * deterministic property is itself a security or protocol requirement** —
 * e.g. RANDAO-style verifiable beacon contributions where each validator
 * must produce the same signature for the same input, or test-vector
 * reproduction. Consider the [cryptoSignDeterministic] convenience wrapper
 * for those cases.
 *
 * @param {Uint8Array} sig - Output buffer for signature (must be at least CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - **Recommended: `true` (hedged, FIPS 204 §3.4).**
 *   If true, mix fresh `crypto.getRandomValues` randomness into the
 *   per-signature nonce. If false, use a deterministic nonce derived from
 *   message and key (FIPS 204 §3.5).
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes).
 *   Pass an empty Uint8Array for no context.
 * @returns {number} 0 on success
 * @throws {TypeError} If sig is not a Uint8Array or is smaller than CryptoBytes
 * @throws {TypeError} If sk is not a Uint8Array
 * @throws {TypeError} If ctx is not a Uint8Array
 * @throws {TypeError} If randomizedSigning is not a boolean
 * @throws {Error} If ctx exceeds 255 bytes
 * @throws {Error} If sk length does not equal CryptoSecretKeyBytes
 * @throws {Error} If message is not a Uint8Array or valid hex string
 *
 * @example
 * const sig = new Uint8Array(CryptoBytes);
 * const ctx = new Uint8Array([0x01, 0x02]);
 * cryptoSignSignature(sig, message, sk, false, ctx);
 */
function cryptoSignSignature(sig, m, sk, randomizedSigning, ctx) {
  if (!(sig instanceof Uint8Array) || sig.length < CryptoBytes) {
    throw new TypeError(`sig must be at least ${CryptoBytes} bytes and a Uint8Array`);
  }
  if (!(sk instanceof Uint8Array)) {
    throw new TypeError('sk must be a Uint8Array');
  }
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  if (ctx.length > 255) throw new Error(`invalid context length: ${ctx.length} (max 255)`);
  if (typeof randomizedSigning !== 'boolean') {
    throw new TypeError('randomizedSigning must be a boolean');
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`invalid sk length ${sk.length} | Expected length ${CryptoSecretKeyBytes}`);
  }

  const rho = new Uint8Array(SeedBytes);
  const tr = new Uint8Array(TRBytes);
  const key = new Uint8Array(SeedBytes);
  let rhoPrime = new Uint8Array(CRHBytes);
  let nonce = 0;
  const mat = Array(K)
    .fill()
    .map(() => new PolyVecL());
  const s1 = new PolyVecL();
  const y = new PolyVecL();
  const z = new PolyVecL();
  const t0 = new PolyVecK();
  const s2 = new PolyVecK();
  const w1 = new PolyVecK();
  const w0 = new PolyVecK();
  const h = new PolyVecK();
  const cp = new Poly();

  try {
    unpackSk(rho, tr, key, t0, s1, s2, sk);

    // pre = 0x00 || len(ctx) || ctx
    const pre = new Uint8Array(2 + ctx.length);
    pre[0] = 0;
    pre[1] = ctx.length;
    pre.set(ctx, 2);

    const mBytes = messageToBytes(m);

    // mu = SHAKE256(tr || pre || m)
    const mu = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);

    // rhoPrime = SHAKE256(key || rnd || mu)
    const rnd = randomizedSigning ? randomBytes$1(RNDBytes) : new Uint8Array(RNDBytes);
    rhoPrime = shake256.create({}).update(key).update(rnd).update(mu).xof(CRHBytes);
    zeroize(rnd);

    polyVecMatrixExpand(mat, rho);
    polyVecLNTT(s1);
    polyVecKNTT(s2);
    polyVecKNTT(t0);

    while (true) {
      polyVecLUniformGamma1(y, rhoPrime, nonce++);
      // Matrix-vector multiplication
      z.copy(y);
      polyVecLNTT(z);
      polyVecMatrixPointWiseMontgomery(w1, mat, z);
      polyVecKReduce(w1);
      polyVecKInvNTTToMont(w1);

      // Decompose w and call the random oracle
      polyVecKCAddQ(w1);
      polyVecKDecompose(w1, w0, w1);
      polyVecKPackW1(sig, w1);

      // ctilde = SHAKE256(mu || w1_packed) (64 bytes)
      const ctilde = shake256
        .create({})
        .update(mu)
        .update(sig.slice(0, K * PolyW1PackedBytes))
        .xof(CTILDEBytes);

      polyChallenge(cp, ctilde);
      polyNTT(cp);

      // Compute z, reject if it reveals secret
      polyVecLPointWisePolyMontgomery(z, cp, s1);
      polyVecLInvNTTToMont(z);
      polyVecLAdd(z, z, y);
      polyVecLReduce(z);
      if (polyVecLChkNorm(z, GAMMA1 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, s2);
      polyVecKInvNTTToMont(h);
      polyVecKSub(w0, w0, h);
      polyVecKReduce(w0);
      if (polyVecKChkNorm(w0, GAMMA2 - BETA) !== 0) {
        continue;
      }

      polyVecKPointWisePolyMontgomery(h, cp, t0);
      polyVecKInvNTTToMont(h);
      polyVecKReduce(h);
      /* c8 ignore start */
      if (polyVecKChkNorm(h, GAMMA2) !== 0) {
        continue;
      }
      /* c8 ignore stop */

      polyVecKAdd(w0, w0, h);
      const n = polyVecKMakeHint(h, w0, w1);
      /* c8 ignore start */
      if (n > OMEGA) {
        continue;
      }
      /* c8 ignore stop */

      packSig(sig, ctilde, z, h);
      return 0;
    }
  } finally {
    zeroize(key);
    zeroize(rhoPrime);
    for (let i = 0; i < L; i++) s1.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) s2.vec[i].coeffs.fill(0);
    for (let i = 0; i < K; i++) t0.vec[i].coeffs.fill(0);
    for (let i = 0; i < L; i++) y.vec[i].coeffs.fill(0);
  }
}

/**
 * Sign a message, returning signature concatenated with message.
 *
 * This is the combined sign operation that produces a "signed message" containing
 * both the signature and the original message (signature || message).
 *
 * @param {string|Uint8Array} msg - Message to sign (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} sk - Secret key (must be CryptoSecretKeyBytes = 4896 bytes)
 * @param {boolean} randomizedSigning - If true, use random nonce; if false, deterministic
 * @param {Uint8Array} ctx - Context string for domain separation (required, max 255 bytes).
 * @returns {Uint8Array} Signed message (CryptoBytes + msg.length bytes)
 * @throws {TypeError} If ctx is not a Uint8Array
 * @throws {TypeError} If sk or randomizedSigning fail type validation (see cryptoSignSignature)
 * @throws {Error} If signing fails or message/sk/ctx are invalid
 *
 * @example
 * const signedMsg = cryptoSign(message, sk, false, ctx);
 * // signedMsg contains: signature (4627 bytes) || message
 */
function cryptoSign(msg, sk, randomizedSigning, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  const msgBytes = messageToBytes(msg);

  const sm = new Uint8Array(CryptoBytes + msgBytes.length);
  const mLen = msgBytes.length;
  for (let i = 0; i < mLen; ++i) {
    sm[CryptoBytes + mLen - 1 - i] = msgBytes[mLen - 1 - i];
  }
  const result = cryptoSignSignature(sm, msgBytes, sk, randomizedSigning, ctx);

  /* c8 ignore start */
  if (result !== 0) {
    throw new Error('failed to sign');
  }
  /* c8 ignore stop */
  return sm;
}

/**
 * Verify a detached signature with context.
 *
 * Performs constant-time verification to prevent timing side-channel attacks.
 * The context must match the one used during signing.
 *
 * @param {Uint8Array} sig - Signature to verify (must be CryptoBytes = 4627 bytes)
 * @param {string|Uint8Array} m - Message that was signed (hex string, optional 0x prefix, or Uint8Array)
 * @param {Uint8Array} pk - Public key (must be CryptoPublicKeyBytes = 2592 bytes)
 * @param {Uint8Array} ctx - Context string used during signing (required, max 255 bytes).
 * @returns {boolean} true if signature is valid, false otherwise
 * @throws {TypeError} If ctx is not a Uint8Array
 *
 * @example
 * const isValid = cryptoSignVerify(signature, message, pk, ctx);
 * if (!isValid) {
 *   throw new Error('Invalid signature');
 * }
 */
function cryptoSignVerify(sig, m, pk, ctx) {
  if (!(ctx instanceof Uint8Array)) {
    throw new TypeError('ctx is required and must be a Uint8Array');
  }
  if (ctx.length > 255) return false;
  let i;
  const buf = new Uint8Array(K * PolyW1PackedBytes);
  const rho = new Uint8Array(SeedBytes);
  const mu = new Uint8Array(CRHBytes);
  const c = new Uint8Array(CTILDEBytes);
  const c2 = new Uint8Array(CTILDEBytes);
  const cp = new Poly();
  const mat = new Array(K).fill().map(() => new PolyVecL());
  const z = new PolyVecL();
  const t1 = new PolyVecK();
  const w1 = new PolyVecK();
  const h = new PolyVecK();

  if (!(sig instanceof Uint8Array) || sig.length !== CryptoBytes) {
    return false;
  }
  if (!(pk instanceof Uint8Array) || pk.length !== CryptoPublicKeyBytes) {
    return false;
  }

  unpackPk(rho, t1, pk);
  if (unpackSig(c, z, h, sig)) {
    return false;
  }
  if (polyVecLChkNorm(z, GAMMA1 - BETA)) {
    return false;
  }

  /* Compute mu = SHAKE256(tr || pre || m) with tr = SHAKE256(pk) */
  const tr = shake256.create({}).update(pk).xof(TRBytes);

  const pre = new Uint8Array(2 + ctx.length);
  pre[0] = 0;
  pre[1] = ctx.length;
  pre.set(ctx, 2);

  let mBytes;
  try {
    mBytes = messageToBytes(m);
  } catch {
    return false;
  }
  const muFull = shake256.create({}).update(tr).update(pre).update(mBytes).xof(CRHBytes);
  mu.set(muFull);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyChallenge(cp, c);
  polyVecMatrixExpand(mat, rho);

  polyVecLNTT(z);
  polyVecMatrixPointWiseMontgomery(w1, mat, z);

  polyNTT(cp);
  polyVecKShiftL(t1);
  polyVecKNTT(t1);
  polyVecKPointWisePolyMontgomery(t1, cp, t1);

  polyVecKSub(w1, w1, t1);
  polyVecKReduce(w1);
  polyVecKInvNTTToMont(w1);

  /* Reconstruct w1 */
  polyVecKCAddQ(w1);
  polyVecKUseHint(w1, w1, h);
  polyVecKPackW1(buf, w1);

  /* Call random oracle and verify challenge */
  const c2Hash = shake256.create({}).update(mu).update(buf).xof(CTILDEBytes);
  c2.set(c2Hash);

  // Constant-time comparison to prevent timing attacks
  let diff = 0;
  for (i = 0; i < CTILDEBytes; ++i) {
    diff |= c[i] ^ c2[i];
  }
  return diff === 0;
}

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
  return shake256$1.create({ dkLen: ADDRESS_SIZE }).update(input).digest();
}

/**
 * Internal Merkle-Damgard hash utils.
 * @module
 */
/**
 * Shared 32-bit conditional boolean primitive reused by SHA-256, SHA-1, and MD5 `F`.
 * Returns bits from `b` when `a` is set, otherwise from `c`.
 * The XOR form is equivalent to MD5's `F(X,Y,Z) = XY v not(X)Z` because the masked terms never
 * set the same bit.
 * @param a - selector word
 * @param b - word chosen when selector bit is set
 * @param c - word chosen when selector bit is clear
 * @returns Mixed 32-bit word.
 * @example
 * Combine three words with the shared 32-bit choice primitive.
 * ```ts
 * Chi(0xffffffff, 0x12345678, 0x87654321);
 * ```
 */
function Chi(a, b, c) {
    return (a & b) ^ (~a & c);
}
/**
 * Shared 32-bit majority primitive reused by SHA-256 and SHA-1.
 * Returns bits shared by at least two inputs.
 * @param a - first input word
 * @param b - second input word
 * @param c - third input word
 * @returns Mixed 32-bit word.
 * @example
 * Combine three words with the shared 32-bit majority primitive.
 * ```ts
 * Maj(0xffffffff, 0x12345678, 0x87654321);
 * ```
 */
function Maj(a, b, c) {
    return (a & b) ^ (a & c) ^ (b & c);
}
/**
 * Merkle-Damgard hash construction base class.
 * Could be used to create MD5, RIPEMD, SHA1, SHA2.
 * Accepts only byte-aligned `Uint8Array` input, even when the underlying spec describes bit
 * strings with partial-byte tails.
 * @param blockLen - internal block size in bytes
 * @param outputLen - digest size in bytes
 * @param padOffset - trailing length field size in bytes
 * @param isLE - whether length and state words are encoded in little-endian
 * @example
 * Use a concrete subclass to get the shared Merkle-Damgard update/digest flow.
 * ```ts
 * import { _SHA1 } from '@noble/hashes/legacy.js';
 * const hash = new _SHA1();
 * hash.update(new Uint8Array([97, 98, 99]));
 * hash.digest();
 * ```
 */
class HashMD {
    blockLen;
    outputLen;
    canXOF = false;
    padOffset;
    isLE;
    // For partial updates less than block size
    buffer;
    view;
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    constructor(blockLen, outputLen, padOffset, isLE) {
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        aexists$1(this);
        abytes$1(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path only when there is no buffered partial block: `take === blockLen` implies
            // `this.pos === 0`, so we can process full blocks directly from the input view.
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        aexists$1(this);
        aoutput$1(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        clean$1(this.buffer.subarray(pos));
        // we have less than padOffset left in buffer, so we cannot put length in
        // current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // `padOffset` reserves the whole length field. For SHA-384/512 the high 64 bits stay zero from
        // the padding fill above, and JS will overflow before user input can make that half non-zero.
        // So we only need to write the low 64 bits here.
        view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which must be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen must be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        // Copy before destroy(): subclasses wipe `buffer` during cleanup, but `digest()` must return
        // fresh bytes to the caller.
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to ||= new this.constructor();
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        // Only partial-block bytes need copying: when `length % blockLen === 0`, `pos === 0` and
        // later `update()` / `digestInto()` overwrite `to.buffer` from the start before reading it.
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
    clone() {
        return this._cloneInto();
    }
}
/**
 * Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
 * Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
 */
/** Initial SHA256 state from RFC 6234 §6.1: the first 32 bits of the fractional parts of the
 * square roots of the first eight prime numbers. Exported as a shared table; callers must treat
 * it as read-only because constructors copy words from it by index. */
const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/**
 * SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
 * SHA256 is the fastest hash implementable in JS, even faster than Blake3.
 * Check out {@link https://www.rfc-editor.org/rfc/rfc4634 | RFC 4634} and
 * {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | FIPS 180-4}.
 * @module
 */
/**
 * SHA-224 / SHA-256 round constants from RFC 6234 §5.1: the first 32 bits
 * of the cube roots of the first 64 primes (2..311).
 */
// prettier-ignore
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
/** Reusable SHA-224 / SHA-256 message schedule buffer `W_t` from RFC 6234 §6.2 step 1. */
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
/** Internal SHA-224 / SHA-256 compression engine from RFC 6234 §6.2. */
class SHA2_32B extends HashMD {
    constructor(outputLen) {
        super(64, outputLen, 8, false);
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        clean$1(SHA256_W);
    }
    destroy() {
        // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves
        // update()/digest() callable on reused instances.
        this.destroyed = true;
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        clean$1(this.buffer);
    }
}
/** Internal SHA-256 hash class grounded in RFC 6234 §6.2. */
class _SHA256 extends SHA2_32B {
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    A = SHA256_IV[0] | 0;
    B = SHA256_IV[1] | 0;
    C = SHA256_IV[2] | 0;
    D = SHA256_IV[3] | 0;
    E = SHA256_IV[4] | 0;
    F = SHA256_IV[5] | 0;
    G = SHA256_IV[6] | 0;
    H = SHA256_IV[7] | 0;
    constructor() {
        super(32);
    }
}
/**
 * SHA2-256 hash function from RFC 4634. In JS it's the fastest: even faster than Blake3. Some info:
 *
 * - Trying 2^128 hashes would get 50% chance of collision, using birthday attack.
 * - BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
 * - Each sha256 hash is executing 2^18 bit operations.
 * - Good 2024 ASICs can do 200Th/sec with 3500 watts of power, corresponding to 2^36 hashes/joule.
 * @param msg - message bytes to hash
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-256.
 * ```ts
 * sha256(new Uint8Array([97, 98, 99]));
 * ```
 */
const sha256 = /* @__PURE__ */ createHasher$1(() => new _SHA256(), 
/* @__PURE__ */ oidNist$1(0x01));

/**
 * Shared byte/hex utils used across modules.
 * @module utils/bytes
 */


/**
 * @param {unknown} input
 * @returns {boolean}
 */
function isUint8(input) {
  return input instanceof Uint8Array;
}

/**
 * Accepts strings with optional 0x/0X prefix and separators(space, :, _, -).
 * @param {unknown} input
 * @returns {boolean}
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
    bytes = hexToBytes$2(cleanHex(input));
  } else if (Array.isArray(input)) {
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
 *  - bytes 1..2: 2 bytes metadata
 * @module wallet/common/descriptor
 */


class Descriptor {
  /**
   * @param {Uint8Array|number[]} bytes Must be exactly 3 bytes.
   * @throws {Error} If size is not 3 or wallet type is invalid.
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
 * @param {[number, number]} [metadata=[0,0]] Two metadata bytes.
 * @returns {Uint8Array} 3 bytes.
 */
function getDescriptorBytes(walletType, metadata = [0, 0]) {
  if (!isValidWalletType(walletType)) {
    throw new Error('Invalid wallet type in descriptor');
  }
  const m0 = metadata?.[0] ?? 0;
  const m1 = metadata?.[1] ?? 0;
  if (!Number.isInteger(m0) || m0 < 0 || m0 > 255 || !Number.isInteger(m1) || m1 < 0 || m1 > 255) {
    throw new Error('Descriptor metadata bytes must be in range [0, 255]');
  }
  const out = new Uint8Array(DESCRIPTOR_SIZE);
  out[0] = walletType >>> 0;
  out[1] = m0;
  out[2] = m1;
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
   * @throws {Error} If size mismatch or invalid wallet type.
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
 * @returns {boolean}
 */
function isBytes(input) {
  return input instanceof Uint8Array;
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
    throw new Error('sk must be Uint8Array or Buffer');
  }
  if (sk.length !== CryptoSecretKeyBytes) {
    throw new Error(`sk must be ${CryptoSecretKeyBytes} bytes, got ${sk.length}`);
  }
  if (!isBytes(message)) {
    throw new Error('message must be Uint8Array or Buffer');
  }
  if (!isBytes(ctx)) {
    throw new Error('ctx must be Uint8Array or Buffer');
  }
  if (typeof randomized !== 'boolean') {
    throw new Error('randomized must be a boolean');
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
    throw new Error('signature must be Uint8Array or Buffer');
  }
  if (signature.length !== CryptoBytes) {
    throw new Error(`signature must be ${CryptoBytes} bytes, got ${signature.length}`);
  }
  if (!isBytes(message)) {
    throw new Error('message must be Uint8Array or Buffer');
  }
  if (!isBytes(pk)) {
    throw new Error('pk must be Uint8Array or Buffer');
  }
  if (pk.length !== CryptoPublicKeyBytes) {
    throw new Error(`pk must be ${CryptoPublicKeyBytes} bytes, got ${pk.length}`);
  }
  if (!isBytes(ctx)) {
    throw new Error('ctx must be Uint8Array or Buffer');
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
   */
  constructor({ descriptor, seed, pk, sk }) {
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
   * @param {Seed} seed
   * @param {[number, number]} [metadata=[0,0]]
   * @returns {Wallet}
   */
  static newWalletFromSeed(seed, metadata = [0, 0]) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk });
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

exports.ADDRESS_SIZE = ADDRESS_SIZE;
exports.DESCRIPTOR_SIZE = DESCRIPTOR_SIZE;
exports.Descriptor = Descriptor;
exports.EXTENDED_SEED_SIZE = EXTENDED_SEED_SIZE;
exports.ExtendedSeed = ExtendedSeed;
exports.MLDSA87 = Wallet;
exports.SEED_SIZE = SEED_SIZE;
exports.SIGNING_CONTEXT_PREFIX = SIGNING_CONTEXT_PREFIX;
exports.SIGNING_CONTEXT_SIZE = SIGNING_CONTEXT_SIZE;
exports.SIGNING_CONTEXT_VERSION = SIGNING_CONTEXT_VERSION;
exports.Seed = Seed;
exports.WalletType = WalletType;
exports.addressToString = addressToString;
exports.getAddressFromPKAndDescriptor = getAddressFromPKAndDescriptor;
exports.isValidAddress = isValidAddress;
exports.newMLDSA87Descriptor = newMLDSA87Descriptor;
exports.newWalletFromExtendedSeed = newWalletFromExtendedSeed;
exports.signingContext = signingContext;
exports.stringToAddress = stringToAddress;
