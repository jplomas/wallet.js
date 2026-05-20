/**
 * @param {unknown} input
 * @returns {boolean}
 */
export function isUint8(input: unknown): boolean;
/**
 * Accepts strings with optional 0x/0X prefix and separators(space, :, _, -).
 * @param {unknown} input
 * @returns {boolean}
 */
export function isHexLike(input: unknown): boolean;
/**
 * Remove 0x prefix and all non-hex chars.
 * @param {string} hex
 * @returns {string}
 */
export function cleanHex(hex: string): string;
/**
 * Convert various inputs to a fixed-length byte array.
 * Supports hex string(with/without 0x), Uint8Array, Buffer, number[].
 * @param {string|Uint8Array|Buffer|number[]} input
 * @param {number} expectedLen
 * @param {string} [label='bytes']
 * @returns {Uint8Array}
 */
export function toFixedU8(input: string | Uint8Array | Buffer | number[], expectedLen: number, label?: string): Uint8Array;
//# sourceMappingURL=bytes.d.ts.map