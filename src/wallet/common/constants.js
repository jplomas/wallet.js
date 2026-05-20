/**
 * Constants used across wallet components.
 * @module wallet/common/constants
 */

/** @type {number} Size in bytes of the 3-byte descriptor */
export const DESCRIPTOR_SIZE = 3;

/**
 * @type {number} QRL address length in bytes. 64 bytes (512 bits)
 * exceeds NIST Category 5 collision targets and produces a `Q` + 128
 * hex-character address string. Matches go-qrllib's `AddressSize` and
 * rust-qrllib's `ADDRESS_SIZE` constants — one canonical size across
 * implementations.
 */
export const ADDRESS_SIZE = 64;

/** @type {number} Seed length in bytes */
export const SEED_SIZE = 48;

/** @type {number} Extended seed length in bytes */
export const EXTENDED_SEED_SIZE = DESCRIPTOR_SIZE + SEED_SIZE;
