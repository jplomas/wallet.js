/**
 * Decode spaced hex mnemonic to bytes.
 * @param {string} mnemonic
 * @returns {Uint8Array}
 *
 * Note: Mnemonic words are normalized to lowercase for user convenience.
 * This is by design to reduce errors from capitalization differences.
 */
export function mnemonicToBin(mnemonic: string): Uint8Array;
/**
 * Encode bytes to a spaced hex mnemonic string.
 * @param {Uint8Array} input
 * @returns {string}
 */
export function binToMnemonic(input: Uint8Array): string;
//# sourceMappingURL=mnemonic.d.ts.map