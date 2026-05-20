/**
 * Build the domain-separated bytes that bind a signature to its
 * descriptor: `"ZOND" || SIGNING_CONTEXT_VERSION || descriptor` (8 bytes).
 *
 * @param {Descriptor} descriptor
 * @returns {Uint8Array} exactly {@link SIGNING_CONTEXT_SIZE} bytes.
 * @throws {Error} if descriptor is not a Descriptor instance.
 */
export function signingContext(descriptor: Descriptor): Uint8Array;
/** @type {number} Current signing-context format version. */
export const SIGNING_CONTEXT_VERSION: number;
/** @type {Uint8Array} Application-domain tag embedded in every context. */
export const SIGNING_CONTEXT_PREFIX: Uint8Array;
/** @type {number} Fixed on-wire length of a signing context (8 bytes). */
export const SIGNING_CONTEXT_SIZE: number;
import { Descriptor } from './descriptor.js';
//# sourceMappingURL=context.d.ts.map