export class Descriptor {
    /**
     * Constructor: accepts hex string / Uint8Array / Buffer / number[].
     * @param {string|Uint8Array|Buffer|number[]} input
     * @returns {Descriptor}
     */
    static from(input: string | Uint8Array | Buffer | number[]): Descriptor;
    /**
     * @param {Uint8Array|number[]} bytes Must be exactly 3 bytes.
     * @throws {Error} If size is not 3 or wallet type is invalid.
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
 * @param {[number, number]} [metadata=[0,0]] Two metadata bytes.
 * @returns {Uint8Array} 3 bytes.
 */
export function getDescriptorBytes(walletType: number, metadata?: [number, number]): Uint8Array;
//# sourceMappingURL=descriptor.d.ts.map