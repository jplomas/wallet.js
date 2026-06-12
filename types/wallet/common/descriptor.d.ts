export class Descriptor {
    /**
     * Constructor: accepts hex string / Uint8Array / Buffer / number[].
     * @param {string|Uint8Array|Buffer|number[]} input
     * @returns {Descriptor}
     */
    static from(input: string | Uint8Array | Buffer | number[]): Descriptor;
    /**
     * @param {Uint8Array|number[]} bytes Must be exactly 3 bytes.
     * @throws {Error} If size is not 3, wallet type is invalid, or the
     *   reserved metadata bytes (1–2) are non-zero.
     */
    constructor(bytes: Uint8Array | number[]);
    /** @private @type {Uint8Array} */
    private bytes;
    /**
     * @returns {number}
     */
    type(): number;
    /**
     * Copy of internal bytes.
     * @returns {Uint8Array}
     */
    toBytes(): Uint8Array;
}
/**
 * Build descriptor bytes from parts.
 * @param {number} walletType byte.
 * @param {[number, number]} [metadata=[0,0]] Two metadata bytes — reserved,
 *   must both be zero (the parameter is kept for API compatibility).
 * @returns {Uint8Array} 3 bytes.
 * @throws {Error} If the wallet type is invalid or metadata is non-zero.
 */
export function getDescriptorBytes(walletType: number, metadata?: [number, number]): Uint8Array;
//# sourceMappingURL=descriptor.d.ts.map