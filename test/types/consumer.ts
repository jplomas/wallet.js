// TypeScript consumer compile test.
//
// Imports every value and uses every export from the public API as a real
// downstream user would. Compiled with `tsc --noEmit --strict` by
// test/unit/types-consumer.mocha.js. Any signature drift, missing export, or
// loss of generic / overload information will surface as a compile error
// before it ships to npm.

import {
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
  isValidChecksumAddress,
  toChecksumAddress,
  WalletType,
  newWalletFromExtendedSeed,
  MLDSA87,
} from '@theqrl/wallet.js';

// Numeric size constants are typed `number`.
const _seedSize: number = SEED_SIZE;
const _extSeedSize: number = EXTENDED_SEED_SIZE;
const _descSize: number = DESCRIPTOR_SIZE;
const _addrSize: number = ADDRESS_SIZE;
const _ctxSize: number = SIGNING_CONTEXT_SIZE;
const _ctxVersion: number = SIGNING_CONTEXT_VERSION;
const _ctxPrefix: Uint8Array = SIGNING_CONTEXT_PREFIX;

// WalletType enum-like value.
const _wt: number = WalletType.ML_DSA_87;

// --- Wallet creation surface ---

const wallet = MLDSA87.newWallet();
// Metadata bytes are reserved and must be zero at runtime; the parameter
// remains typed for API compatibility.
const walletWithMeta = MLDSA87.newWallet([0x00, 0x00]);
const seed = Seed.from('0x' + '00'.repeat(SEED_SIZE));
const walletFromSeed = MLDSA87.newWalletFromSeed(seed);
const walletFromSeedWithMeta = MLDSA87.newWalletFromSeed(seed, [0x00, 0x00]);
const walletFromMnemonic = MLDSA87.newWalletFromMnemonic(wallet.getMnemonic());
const walletFromExt = newWalletFromExtendedSeed(wallet.getHexExtendedSeed());

// --- Wallet instance methods ---

const addrBytes: Uint8Array = wallet.getAddress();
const addrStr: string = wallet.getAddressStr();
const mnemonic: string = wallet.getMnemonic();
const pk: Uint8Array = wallet.getPK();
const sk: Uint8Array = wallet.getSK();
const hexExt: string = wallet.getHexExtendedSeed();
const descriptor: Descriptor = wallet.getDescriptor();

const message = new TextEncoder().encode('hello');
const sig: Uint8Array = wallet.sign(message);
const detSig: Uint8Array = wallet.signDeterministic(message);
wallet.zeroize();

// --- Static verify ---
const verified: boolean = MLDSA87.verify(sig, message, pk, descriptor);

// --- Descriptor / ExtendedSeed surface ---

const newDesc: Descriptor = newMLDSA87Descriptor();
const newDescWithMeta: Descriptor = newMLDSA87Descriptor([0x00, 0x00]);
const descBytes: Uint8Array = newDesc.toBytes();
const descType: number = newDesc.type();

const extSeed: ExtendedSeed = ExtendedSeed.newExtendedSeed(newDesc, seed);
const extBytes: Uint8Array = extSeed.toBytes();
extSeed.zeroize();

const seedBytes: Uint8Array = seed.toBytes();
seed.zeroize();

// --- Signing context ---
const ctx: Uint8Array = signingContext(descriptor);

// --- Address helpers (the focus of recent work) ---

const derived: Uint8Array = getAddressFromPKAndDescriptor(pk, descriptor);
const lowerStr: string = addressToString(derived);
const checksummedFromBytes: string = toChecksumAddress(derived);
const checksummedFromStr: string = toChecksumAddress(lowerStr);
const parsed: Uint8Array = stringToAddress(checksummedFromBytes);
const permissive: boolean = isValidAddress(lowerStr);
const strict: boolean = isValidChecksumAddress(checksummedFromBytes);

// Force-use every binding so an unused-import doesn't silently mask drift.
const _used = [
  walletWithMeta, walletFromSeed, walletFromSeedWithMeta, walletFromMnemonic,
  walletFromExt, addrBytes, addrStr, mnemonic, sk, hexExt, detSig, verified,
  newDescWithMeta, descBytes, descType, extBytes, seedBytes, ctx, derived,
  lowerStr, checksummedFromBytes, checksummedFromStr, parsed, permissive,
  strict, _wt, _seedSize, _extSeedSize, _descSize, _addrSize, _ctxSize,
  _ctxVersion, _ctxPrefix,
] as const;
void _used;
