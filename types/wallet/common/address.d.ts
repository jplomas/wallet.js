export type Descriptor = import("./descriptor.js").Descriptor;
/**
 * Convert address bytes to string form (lowercase hex).
 * @param {Uint8Array} addrBytes - Exactly {@link ADDRESS_SIZE} bytes.
 * @returns {string}
 * @throws {Error} If input is not a Uint8Array of exactly ADDRESS_SIZE bytes.
 */
export function addressToString(addrBytes: Uint8Array): string;
/**
 * Convert address string to bytes.
 *
 * The `Q` prefix is case-insensitive. The hex body must be one of:
 *   - all lowercase (case-uniform), OR
 *   - all uppercase (case-uniform), OR
 *   - mixed-case matching the EIP-55-style checksum (see module docs).
 *
 * Mixed-case strings that do not match the checksum are rejected, mirroring
 * Ethereum tooling behavior for EIP-55 addresses.
 *
 * @param {string} addrStr - Address string: 'Q'/'q' followed by exactly
 *   `2 × ADDRESS_SIZE` (= 128) hex characters.
 * @returns {Uint8Array} Decoded ADDRESS_SIZE-byte address.
 * @throws {Error} If address format or checksum is invalid.
 */
export function stringToAddress(addrStr: string): Uint8Array;
/**
 * Check if a string is a valid QRL address. Requires exactly `Q`/`q` + `2 ×
 * ADDRESS_SIZE` hex characters. Mixed-case hex must satisfy the EIP-55-style
 * checksum; all-lowercase and all-uppercase forms are accepted unconditionally.
 *
 * This is a permissive check: it accepts un-checksummed (case-uniform) inputs.
 * Use {@link isValidChecksumAddress} to require a properly-checksummed string.
 *
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if the address parses successfully.
 */
export function isValidAddress(addrStr: string): boolean;
/**
 * Convert an address (bytes or string) to its EIP-55-style mixed-case
 * checksummed string form. The returned string always uses uppercase `Q`.
 *
 * - Uint8Array input: must be exactly {@link ADDRESS_SIZE} bytes.
 * - String input: parsed via {@link stringToAddress} first, so mixed-case
 *   inputs must already carry a valid checksum (otherwise the call throws).
 *   All-lowercase, all-uppercase, and correctly-checksummed inputs are all
 *   accepted and re-emitted in canonical checksummed form.
 *
 * @param {Uint8Array|string} addr
 * @returns {string} Checksummed address: `Q` + 128 mixed-case hex chars.
 * @throws {Error} If the input is the wrong type, wrong length, contains
 *   invalid hex, or is a mixed-case string with a bad checksum.
 */
export function toChecksumAddress(addr: Uint8Array | string): string;
/**
 * Strict check: returns true only when `addrStr` exactly matches the
 * canonical checksummed form produced by {@link toChecksumAddress}. This
 * means:
 *   - The `Q` prefix must be uppercase.
 *   - The hex body must match the EIP-55-style mixed-case checksum
 *     character-for-character.
 *
 * All-lowercase or all-uppercase addresses that contain letters return
 * `false` even though they are otherwise valid (use {@link isValidAddress}
 * for the permissive check). Digit-only hex bodies have no checksum
 * information and return `true` when the rest of the format is valid.
 *
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean}
 */
export function isValidChecksumAddress(addrStr: string): boolean;
/**
 * Derive an address from a public key and descriptor.
 * @param {Uint8Array} pk - Public key for the wallet type encoded in the descriptor.
 * @param {Descriptor} descriptor
 * @returns {Uint8Array} {@link ADDRESS_SIZE}-byte address.
 * @throws {Error} If pk is not a Uint8Array of the expected length.
 */
export function getAddressFromPKAndDescriptor(pk: Uint8Array, descriptor: Descriptor): Uint8Array;
//# sourceMappingURL=address.d.ts.map