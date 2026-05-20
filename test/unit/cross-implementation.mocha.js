/**
 * Cross-Implementation Verification Tests
 * WJ-TST-001: Cross-implementation verification tests vs go-qrllib
 *
 * These tests verify that wallet.js produces consistent results with go-qrllib.
 *
 * Verification targets:
 * 1. Address derivation (SHAKE-256 of descriptor + public key)
 * 2. Extended seed format (3-byte descriptor + 48-byte seed)
 * 3. Mnemonic encoding (12-bit words from QRL 4096-word list)
 *
 * Note: ML-DSA-87 signature verification is already covered by the underlying
 * @theqrl/mldsa87 package which is verified against go-qrllib in qrypto.js.
 *
 * Test vectors in ml_dsa_87.fixtures.js were generated to match go-qrllib.
 * This file provides explicit cross-implementation verification.
 */
import { expect } from 'chai';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';
import { ADDRESS_SIZE, DESCRIPTOR_SIZE } from '../../src/wallet/common/constants.js';

describe('Cross-Implementation Verification', () => {
  describe('Address Derivation Algorithm', () => {
    /**
     * Address derivation in wallet.js:
     *   address = SHAKE256(descriptor || public_key, ADDRESS_SIZE)
     *
     * ADDRESS_SIZE is 64 bytes (NIST Category 5), matching go-qrllib's
     * `AddressSize` and rust-qrllib's `ADDRESS_SIZE` — one canonical size.
     */
    walletTestCases.forEach((tc) => {
      it(`${tc.name}: address derivation matches fixture`, () => {
        const descriptor = hexToBytes(tc.extendedSeed.slice(0, DESCRIPTOR_SIZE * 2));
        const pk = hexToBytes(tc.wantPK);

        const input = new Uint8Array(descriptor.length + pk.length);
        input.set(descriptor, 0);
        input.set(pk, descriptor.length);
        const computedAddress = shake256.create({ dkLen: ADDRESS_SIZE }).update(input).digest();

        expect(bytesToHex(computedAddress)).to.equal(tc.wantAddress.slice(1));
      });
    });
  });

  describe('Extended Seed Format', () => {
    /**
     * Extended seed format:
     * [3-byte descriptor][48-byte seed]
     *
     * Descriptor format:
     * - Byte 0: Wallet type (1 = ML-DSA-87)
     * - Bytes 1-2: Reserved (must be 0x0000)
     */
    walletTestCases.forEach((tc) => {
      it(`${tc.name}: extended seed structure is valid`, () => {
        const ext = hexToBytes(tc.extendedSeed);

        // Total length must be 51 bytes (3 descriptor + 48 seed)
        expect(ext.length).to.equal(51);

        // Wallet type must be 1 (ML_DSA_87)
        expect(ext[0]).to.equal(1);

        // Reserved bytes must be 0
        expect(ext[1]).to.equal(0);
        expect(ext[2]).to.equal(0);
      });
    });
  });

  describe('Deterministic Key Derivation', () => {
    /**
     * Key derivation in wallet.js:
     * (pk, sk) = ML-DSA-87.KeyGen(SHA256(seed))
     *
     * This ensures the same seed always produces the same keys.
     */
    walletTestCases.forEach((tc) => {
      it(`${tc.name}: key derivation is deterministic`, () => {
        const w1 = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);
        const w2 = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);

        expect(bytesToHex(w1.getPK())).to.equal(bytesToHex(w2.getPK()));
        expect(bytesToHex(w1.getSK())).to.equal(bytesToHex(w2.getSK()));

        // Clean up
        w1.zeroize();
        w2.zeroize();
      });
    });
  });

  describe('Mnemonic Encoding', () => {
    /**
     * Mnemonic encoding in wallet.js:
     * - Uses QRL's 4096-word wordlist (12 bits per word)
     * - 51 bytes (408 bits) → 34 words
     *
     * Word selection: each 12 bits maps to wordlist[value]
     */
    walletTestCases.forEach((tc) => {
      it(`${tc.name}: mnemonic has correct word count`, () => {
        const words = tc.wantMnemonic.split(' ');

        // 51 bytes = 408 bits = 34 × 12 bits → 34 words
        expect(words.length).to.equal(34);
      });

      it(`${tc.name}: mnemonic roundtrips correctly`, () => {
        const w = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);

        expect(w.getMnemonic()).to.equal(tc.wantMnemonic);
        expect(w.getHexExtendedSeed()).to.equal(`0x${tc.extendedSeed}`);

        w.zeroize();
      });
    });
  });

  describe('Full Wallet Vector Verification', () => {
    /**
     * Verify all components of the wallet test vectors match.
     * These vectors should be consistent with go-qrllib.
     */
    walletTestCases.forEach((tc) => {
      it(`${tc.name}: all wallet components match vector`, () => {
        const w = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);

        // Extended seed
        expect(w.getHexExtendedSeed()).to.equal(`0x${tc.extendedSeed}`);

        // Public key
        expect(bytesToHex(w.getPK())).to.equal(tc.wantPK);

        // Secret key
        expect(bytesToHex(w.getSK())).to.equal(tc.wantSK);

        // Address — 64-byte canonical size (NIST Cat 5)
        expect(w.getAddressStr()).to.equal(tc.wantAddress);

        // Mnemonic
        expect(w.getMnemonic()).to.equal(tc.wantMnemonic);

        w.zeroize();
      });
    });
  });
});

/**
 * FUTURE: Automated CI cross-verification
 *
 * To add full CI cross-verification against go-qrllib:
 *
 * 1. Create .github/cross-verify/wallet_sign.js - Generate signature with wallet.js
 * 2. Create .github/cross-verify/wallet_verify.go - Verify with go-qrllib
 * 3. Create .github/cross-verify/wallet_sign_goqrllib.go - Generate with go-qrllib
 * 4. Create .github/cross-verify/wallet_verify.js - Verify with wallet.js
 * 5. Add cross-verify.yml workflow to run both directions
 *
 * Key verification points:
 * - Same seed → same public key
 * - Same seed → same address
 * - Signatures interoperate (sign in JS, verify in Go and vice versa)
 */
