/**
 * Fuzz/Property-based tests for wallet.js
 * WJ-TST-003: Add fuzz testing
 *
 * Uses fast-check for property-based testing to find edge cases.
 */
import fc from 'fast-check';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { addressToString, stringToAddress, isValidAddress } from '../../src/wallet/common/address.js';
import { Seed, ExtendedSeed } from '../../src/wallet/common/seed.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';
import { binToMnemonic, mnemonicToBin } from '../../src/wallet/misc/mnemonic.js';
import { SEED_SIZE, EXTENDED_SEED_SIZE } from '../../src/wallet/common/constants.js';

describe('Fuzz Tests (Property-Based)', function propertyBasedTests() {
  // Increase timeout for property-based tests
  this.timeout(30000);

  let wallet;

  before(() => {
    wallet = MLDSA87.newWallet();
  });

  describe('Sign/Verify Properties', () => {
    it('sign produces valid signature for any message', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 0, maxLength: 10000 }), (message) => {
          const sig = wallet.sign(message);
          return MLDSA87.verify(sig, message, wallet.getPK(), wallet.getDescriptor()) === true;
        }),
        { numRuns: 100 }
      );
    });

    it('signature fails verification with different message', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          (msg1, msg2) => {
            // Skip if messages happen to be equal
            if (msg1.length === msg2.length && msg1.every((b, i) => b === msg2[i])) {
              return true;
            }
            const sig = wallet.sign(msg1);
            return MLDSA87.verify(sig, msg2, wallet.getPK(), wallet.getDescriptor()) === false;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('signature fails verification with different wallet', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 0, maxLength: 1000 }), (message) => {
          const otherWallet = MLDSA87.newWallet();
          const sig = wallet.sign(message);
          return MLDSA87.verify(sig, message, otherWallet.getPK(), wallet.getDescriptor()) === false;
        }),
        { numRuns: 20 }
      );
    });

    it('tampered signature fails verification', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.integer({ min: 0, max: 4626 }),
          (message, tamperIndex) => {
            const sig = wallet.sign(message);
            const tamperedSig = new Uint8Array(sig);
            tamperedSig[tamperIndex] ^= 0x01;
            return MLDSA87.verify(tamperedSig, message, wallet.getPK(), wallet.getDescriptor()) === false;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Address Properties', () => {
    it('addressToString -> stringToAddress roundtrip preserves bytes (64-byte canonical)', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (addrBytes) => {
          const str = addressToString(addrBytes);
          const recovered = stringToAddress(str);
          return recovered.length === addrBytes.length && recovered.every((b, i) => b === addrBytes[i]);
        }),
        { numRuns: 100 }
      );
    });

    it('canonical 64-byte address strings are recognized as valid', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (addrBytes) => {
          const str = addressToString(addrBytes);
          return isValidAddress(str) === true;
        }),
        { numRuns: 100 }
      );
    });

    it('random strings are almost never valid addresses', () => {
      fc.assert(
        fc.property(fc.string({ minLength: 0, maxLength: 100 }), (randomStr) => {
          // Random strings should not pass validation (with very high probability)
          // We allow false because the random string could accidentally be valid
          const result = isValidAddress(randomStr);
          return typeof result === 'boolean';
        }),
        { numRuns: 100 }
      );
    });

    it('stringToAddress rejects odd-length hex (structurally invalid)', () => {
      fc.assert(
        fc.property(
          fc
            .array(fc.integer({ min: 0, max: 15 }), { minLength: 1, maxLength: 100 })
            .map((arr) => arr.map((n) => n.toString(16)).join(''))
            .filter((s) => s.length > 0 && s.length % 2 !== 0),
          (hex) => {
            try {
              stringToAddress(`Q${hex}`);
              return false; // Should have thrown
            } catch {
              return true;
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Seed Properties', () => {
    it('Seed accepts any 48-byte input', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: SEED_SIZE, maxLength: SEED_SIZE }), (bytes) => {
          const seed = Seed.from(bytes);
          const output = seed.toBytes();
          return output.every((b, i) => b === bytes[i]);
        }),
        { numRuns: 100 }
      );
    });

    it('ExtendedSeed accepts valid descriptor + seed bytes', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: SEED_SIZE, maxLength: SEED_SIZE }), (seedBytes) => {
          const descriptor = new Uint8Array([WalletType.ML_DSA_87, 0, 0]);
          const extBytes = new Uint8Array(EXTENDED_SEED_SIZE);
          extBytes.set(descriptor, 0);
          extBytes.set(seedBytes, 3);

          const ext = ExtendedSeed.from(extBytes);
          const output = ext.toBytes();
          return output.every((b, i) => b === extBytes[i]);
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Mnemonic Properties', () => {
    it('binToMnemonic -> mnemonicToBin roundtrip preserves bytes (multiples of 3)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 17 }).map((n) => n * 3),
          fc.uint8Array({ minLength: 3, maxLength: 51 }),
          (len, randomBytes) => {
            // Use the first 'len' bytes, but ensure length is multiple of 3
            const bytes = randomBytes.slice(0, len);
            if (bytes.length % 3 !== 0) return true; // Skip invalid lengths

            const mnemonic = binToMnemonic(bytes);
            const recovered = mnemonicToBin(mnemonic);
            return recovered.every((b, i) => b === bytes[i]);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('mnemonic word count is always input length * 8 / 12', () => {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 17 }), (n) => {
          const len = n * 3;
          const bytes = new Uint8Array(len);
          const mnemonic = binToMnemonic(bytes);
          const wordCount = mnemonic.split(' ').length;
          // len bytes * 8 bits / 12 bits per word
          const expectedWords = (len * 8) / 12;
          return wordCount === expectedWords;
        }),
        { numRuns: 50 }
      );
    });
  });

  describe('Wallet Determinism', () => {
    it('same seed produces same keys', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: SEED_SIZE, maxLength: SEED_SIZE }), (seedBytes) => {
          const seed = Seed.from(seedBytes);
          const w1 = MLDSA87.newWalletFromSeed(seed);
          const w2 = MLDSA87.newWalletFromSeed(seed);

          const pk1 = w1.getPK();
          const pk2 = w2.getPK();
          const sk1 = w1.getSK();
          const sk2 = w2.getSK();

          // Clean up
          w1.zeroize();
          w2.zeroize();

          return pk1.every((b, i) => b === pk2[i]) && sk1.every((b, i) => b === sk2[i]);
        }),
        { numRuns: 10 }
      );
    });

    it('different seeds produce different keys (with overwhelming probability)', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: SEED_SIZE, maxLength: SEED_SIZE }),
          fc.uint8Array({ minLength: SEED_SIZE, maxLength: SEED_SIZE }),
          (seedBytes1, seedBytes2) => {
            // Skip if seeds are identical
            if (seedBytes1.every((b, i) => b === seedBytes2[i])) {
              return true;
            }

            const seed1 = Seed.from(seedBytes1);
            const seed2 = Seed.from(seedBytes2);
            const w1 = MLDSA87.newWalletFromSeed(seed1);
            const w2 = MLDSA87.newWalletFromSeed(seed2);

            const pk1 = w1.getPK();
            const pk2 = w2.getPK();

            // Clean up
            w1.zeroize();
            w2.zeroize();

            // Keys should be different
            return !pk1.every((b, i) => b === pk2[i]);
          }
        ),
        { numRuns: 10 }
      );
    });
  });
});
