export class Seed {
    /**
     * Constructor: accepts hex string / Uint8Array / Buffer / number[].
     * @param {string|Uint8Array|Buffer|number[]} input
     * @returns {Seed}
     */
    static from(input: string | Uint8Array | Buffer | number[]): Seed;
    /**
     * @param {Uint8Array} bytes Exactly 48 bytes.
     * @throws {Error} If size mismatch.
     */
    constructor(bytes: Uint8Array);
    bytes: Uint8Array<ArrayBuffer>;
    /** @returns {Uint8Array} */
    hashSHA256(): Uint8Array;
    /**
     * Copy of internal seed bytes.
     * @returns {Uint8Array}
     */
    toBytes(): Uint8Array;
    /**
     * Best-effort zeroize internal seed bytes.
     */
    zeroize(): void;
    /**
     * Redacted JSON shape used by `JSON.stringify`. Raw seed bytes are
     * never serialized; callers must explicitly call `toBytes()`.
     * @returns {{type: string, redacted: true}}
     */
    toJSON(): {
        type: string;
        redacted: true;
    };
}
export class ExtendedSeed {
    /**
     * Build from components.
     * @param {Descriptor} desc
     * @param {Seed} seed
     * @returns {ExtendedSeed}
     */
    static newExtendedSeed(desc: Descriptor, seed: Seed): ExtendedSeed;
    /**
     * Constructor: accepts hex string / Uint8Array / Buffer / number[].
     * @param {string|Uint8Array|Buffer|number[]} input
     * @returns {ExtendedSeed}
     */
    static from(input: string | Uint8Array | Buffer | number[]): ExtendedSeed;
    /**
     * Layout: [3 bytes descriptor] || [48 bytes seed].
     * @param {Uint8Array} bytes Exactly 51 bytes.
     * @throws {Error} If size mismatch or invalid wallet type.
     */
    constructor(bytes: Uint8Array);
    /** @private @type {Uint8Array} */
    private bytes;
    /**
     * @returns {Descriptor}
     */
    getDescriptor(): Descriptor;
    /**
     * @returns {Uint8Array} Descriptor(3 bytes).
     */
    getDescriptorBytes(): Uint8Array;
    /**
     * @returns {Uint8Array} Seed bytes(48 bytes).
     */
    getSeedBytes(): Uint8Array;
    /**
     * @returns {Seed}
     */
    getSeed(): Seed;
    /**
     * Copy of internal seed bytes.
     * @returns {Uint8Array}
     */
    toBytes(): Uint8Array;
    /**
     * Best-effort zeroize internal extended seed bytes.
     */
    zeroize(): void;
    /**
     * Redacted JSON shape used by `JSON.stringify`. Raw bytes are never
     * serialized; callers must explicitly call `toBytes()`.
     * @returns {{type: string, redacted: true}}
     */
    toJSON(): {
        type: string;
        redacted: true;
    };
}
import { Descriptor } from './descriptor.js';
//# sourceMappingURL=seed.d.ts.map