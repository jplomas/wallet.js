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
export function randomBytes(size: number): Uint8Array;
//# sourceMappingURL=random.d.ts.map