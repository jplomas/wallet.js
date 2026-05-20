export type Descriptor = import("./descriptor.js").Descriptor;
/**
 * Convert address bytes to string form.
 * @param {Uint8Array} addrBytes - Exactly {@link ADDRESS_SIZE} bytes.
 * @returns {string}
 * @throws {Error} If input is not a Uint8Array of exactly ADDRESS_SIZE bytes.
 */
export function addressToString(addrBytes: Uint8Array): string;
/**
 * Convert address string to bytes.
 * @param {string} addrStr - Address string: 'Q' followed by exactly
 *   `2 × ADDRESS_SIZE` (= 128) hex characters.
 * @returns {Uint8Array} Decoded ADDRESS_SIZE-byte address.
 * @throws {Error} If address format is invalid.
 */
export function stringToAddress(addrStr: string): Uint8Array;
/**
 * Check if a string is a valid QRL address format. Requires exactly
 * `Q` + `2 × ADDRESS_SIZE` hex characters. QRL addresses contain no
 * checksum; applications should add their own confirmation or checksum
 * layer.
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if valid address format.
 */
export function isValidAddress(addrStr: string): boolean;
/**
 * Derive an address from a public key and descriptor.
 * @param {Uint8Array} pk - Public key for the wallet type encoded in the descriptor.
 * @param {Descriptor} descriptor
 * @returns {Uint8Array} {@link ADDRESS_SIZE}-byte address.
 * @throws {Error} If pk is not a Uint8Array of the expected length.
 */
export function getAddressFromPKAndDescriptor(pk: Uint8Array, descriptor: Descriptor): Uint8Array;
//# sourceMappingURL=address.d.ts.map