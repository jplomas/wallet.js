/**
 * Auto-select wallet implementation based on the ExtendedSeed descriptor.
 * @module wallet/factory
 */

import { isHexLike } from '../utils/bytes.js';
import { ExtendedSeed } from './common/seed.js';
import { WalletType } from './common/wallettype.js';
import { Wallet as MLDSA87 } from './ml_dsa_87/wallet.js';

/**
 * Construct a wallet from an ExtendedSeed by auto-selecting the correct implementation.
 *
 * @param {ExtendedSeed|Uint8Array|string} extendedSeed - ExtendedSeed instance, 51 bytes or hex string.
 * @returns {MLDSA87} Wallet instance
 * @throws {Error} If wallet type is unsupported
 */
function newWalletFromExtendedSeed(extendedSeed) {
  let ext;
  if (extendedSeed instanceof Uint8Array || isHexLike(extendedSeed)) {
    ext = ExtendedSeed.from(extendedSeed);
  } else if (extendedSeed instanceof ExtendedSeed) {
    ext = extendedSeed;
  } else {
    throw new Error('Unsupported extendedSeed input');
  }

  const desc = ext.getDescriptor();
  switch (desc.type()) {
    case WalletType.ML_DSA_87:
      return MLDSA87.newWalletFromExtendedSeed(ext);
    // case WalletType.SPHINCSPLUS_256S:
    //   Not yet implemented - reserved for future use
    /* c8 ignore next 2 */
    default:
      throw new Error(`Unsupported wallet type: ${desc.type()}`);
  }
}

export { newWalletFromExtendedSeed };
