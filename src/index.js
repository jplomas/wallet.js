/**
 * Package entry: re-export modules at the root for convenience.
 * @module index
 */

import { ADDRESS_SIZE, DESCRIPTOR_SIZE, EXTENDED_SEED_SIZE, SEED_SIZE } from './wallet/common/constants.js';
import {
  getAddressFromPKAndDescriptor,
  stringToAddress,
  isValidAddress,
  addressToString,
} from './wallet/common/address.js';
import { ExtendedSeed, Seed } from './wallet/common/seed.js';
import {
  SIGNING_CONTEXT_PREFIX,
  SIGNING_CONTEXT_SIZE,
  SIGNING_CONTEXT_VERSION,
  signingContext,
} from './wallet/common/context.js';
import { newMLDSA87Descriptor } from './wallet/ml_dsa_87/descriptor.js';
import { Descriptor } from './wallet/common/descriptor.js';
import { newWalletFromExtendedSeed } from './wallet/factory.js';
import { Wallet as MLDSA87 } from './wallet/ml_dsa_87/wallet.js';
import { WalletType } from './wallet/common/wallettype.js';

export {
  Seed,
  SEED_SIZE,
  ExtendedSeed,
  EXTENDED_SEED_SIZE,
  Descriptor,
  DESCRIPTOR_SIZE,
  ADDRESS_SIZE,
  SIGNING_CONTEXT_PREFIX,
  SIGNING_CONTEXT_SIZE,
  SIGNING_CONTEXT_VERSION,
  signingContext,
  newMLDSA87Descriptor,
  getAddressFromPKAndDescriptor,
  addressToString,
  stringToAddress,
  isValidAddress,
  WalletType,
  newWalletFromExtendedSeed,
  MLDSA87,
};
