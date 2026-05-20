/**
 * Construct a wallet from an ExtendedSeed by auto-selecting the correct implementation.
 *
 * @param {ExtendedSeed|Uint8Array|string} extendedSeed - ExtendedSeed instance, 51 bytes or hex string.
 * @returns {MLDSA87} Wallet instance
 * @throws {Error} If wallet type is unsupported
 */
export function newWalletFromExtendedSeed(extendedSeed: ExtendedSeed | Uint8Array | string): MLDSA87;
import { ExtendedSeed } from './common/seed.js';
import { Wallet as MLDSA87 } from './ml_dsa_87/wallet.js';
//# sourceMappingURL=factory.d.ts.map