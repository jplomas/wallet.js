/**
 * Edge case tests for wallet.js
 * WJ-TST-002: Missing edge case tests (empty message, max-length, boundary conditions)
 */
import { expect } from 'chai';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { CryptoBytes, CryptoPublicKeyBytes, CryptoSecretKeyBytes } from '@theqrl/mldsa87';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { sign, verify } from '../../src/wallet/ml_dsa_87/crypto.js';
import { addressToString, stringToAddress, isValidAddress } from '../../src/wallet/common/address.js';
import { signingContext } from '../../src/wallet/common/context.js';
import { newWalletFromExtendedSeed } from '../../src/wallet/factory.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

describe('Edge Cases', () => {
  let wallet;
  let ctx;

  before(() => {
    wallet = MLDSA87.newWallet();
    ctx = signingContext(wallet.getDescriptor());
  });

  describe('Message Size Edge Cases', () => {
    it('signs and verifies empty message', () => {
      const msg = new Uint8Array(0);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies single-byte message', () => {
      const msg = new Uint8Array([0x00]);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies single-byte message (0xff)', () => {
      const msg = new Uint8Array([0xff]);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies 1KB message', () => {
      const msg = new Uint8Array(1024).fill(0xab);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies 64KB message', () => {
      const msg = new Uint8Array(64 * 1024).fill(0xcd);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies 1MB message', () => {
      const msg = new Uint8Array(1024 * 1024).fill(0xef);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    }).timeout(10000);

    it('signs and verifies message with all zero bytes', () => {
      const msg = new Uint8Array(256).fill(0x00);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });

    it('signs and verifies message with all 0xff bytes', () => {
      const msg = new Uint8Array(256).fill(0xff);
      const sig = wallet.sign(msg);
      expect(MLDSA87.verify(sig, msg, wallet.getPK(), wallet.getDescriptor())).to.equal(true);
    });
  });

  describe('Sign Input Validation', () => {
    it('rejects null secret key', () => {
      expect(() => sign(null, utf8ToBytes('test'), ctx)).to.throw('sk must be Uint8Array or Buffer');
    });

    it('rejects undefined secret key', () => {
      expect(() => sign(undefined, utf8ToBytes('test'), ctx)).to.throw('sk must be Uint8Array or Buffer');
    });

    it('rejects string secret key', () => {
      expect(() => sign('not-bytes', utf8ToBytes('test'), ctx)).to.throw('sk must be Uint8Array or Buffer');
    });

    it('rejects array secret key', () => {
      expect(() => sign([1, 2, 3], utf8ToBytes('test'), ctx)).to.throw('sk must be Uint8Array or Buffer');
    });

    it('rejects wrong-length secret key', () => {
      const badSk = new Uint8Array(100);
      expect(() => sign(badSk, utf8ToBytes('test'), ctx)).to.throw(`sk must be ${CryptoSecretKeyBytes} bytes`);
    });

    it('rejects null message', () => {
      expect(() => sign(wallet.getSK(), null, ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects undefined message', () => {
      expect(() => sign(wallet.getSK(), undefined, ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects string message', () => {
      expect(() => sign(wallet.getSK(), 'string-message', ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects number message', () => {
      expect(() => sign(wallet.getSK(), 12345, ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects non-bytes ctx', () => {
      expect(() => sign(wallet.getSK(), utf8ToBytes('test'), null)).to.throw('ctx must be Uint8Array or Buffer');
    });

    // TOB-QRLLIB-6: the `randomized` boolean toggle between hedged (true,
    // default) and deterministic (false). Anything that is not a boolean
    // is a caller bug — refuse it loudly rather than silently coercing.
    it('rejects non-boolean randomized flag', () => {
      const sk = wallet.getSK();
      const msg = utf8ToBytes('test');
      expect(() => sign(sk, msg, ctx, 'true')).to.throw('randomized must be a boolean');
      expect(() => sign(sk, msg, ctx, 1)).to.throw('randomized must be a boolean');
      expect(() => sign(sk, msg, ctx, null)).to.throw('randomized must be a boolean');
    });

    it('accepts Buffer secret key', () => {
      const sk = Buffer.from(wallet.getSK());
      const msg = utf8ToBytes('test');
      const sig = sign(sk, msg, ctx);
      expect(sig).to.be.instanceOf(Uint8Array);
      expect(sig.length).to.equal(CryptoBytes);
    });

    it('accepts Buffer message', () => {
      const msg = Buffer.from('test message');
      const sig = sign(wallet.getSK(), msg, ctx);
      expect(sig).to.be.instanceOf(Uint8Array);
    });
  });

  describe('Verify Input Validation', () => {
    let validSig;
    const validMsg = utf8ToBytes('test');

    before(() => {
      validSig = wallet.sign(validMsg);
    });

    it('rejects null signature', () => {
      expect(() => verify(null, validMsg, wallet.getPK(), ctx)).to.throw('signature must be Uint8Array or Buffer');
    });

    it('rejects undefined signature', () => {
      expect(() => verify(undefined, validMsg, wallet.getPK(), ctx)).to.throw('signature must be Uint8Array or Buffer');
    });

    it('rejects string signature', () => {
      expect(() => verify('not-bytes', validMsg, wallet.getPK(), ctx)).to.throw(
        'signature must be Uint8Array or Buffer'
      );
    });

    it('rejects wrong-length signature', () => {
      const badSig = new Uint8Array(100);
      expect(() => verify(badSig, validMsg, wallet.getPK(), ctx)).to.throw(`signature must be ${CryptoBytes} bytes`);
    });

    it('rejects null message', () => {
      expect(() => verify(validSig, null, wallet.getPK(), ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects string message', () => {
      expect(() => verify(validSig, 'string', wallet.getPK(), ctx)).to.throw('message must be Uint8Array or Buffer');
    });

    it('rejects null public key', () => {
      expect(() => verify(validSig, validMsg, null, ctx)).to.throw('pk must be Uint8Array or Buffer');
    });

    it('rejects string public key', () => {
      expect(() => verify(validSig, validMsg, 'not-bytes', ctx)).to.throw('pk must be Uint8Array or Buffer');
    });

    it('rejects wrong-length public key', () => {
      const badPk = new Uint8Array(100);
      expect(() => verify(validSig, validMsg, badPk, ctx)).to.throw(`pk must be ${CryptoPublicKeyBytes} bytes`);
    });

    it('rejects non-bytes ctx', () => {
      expect(() => verify(validSig, validMsg, wallet.getPK(), null)).to.throw('ctx must be Uint8Array or Buffer');
    });

    it('accepts Buffer inputs', () => {
      const sigBuf = Buffer.from(validSig);
      const msgBuf = Buffer.from(validMsg);
      const pkBuf = Buffer.from(wallet.getPK());
      expect(verify(sigBuf, msgBuf, pkBuf, ctx)).to.equal(true);
    });

    it('returns false for wrong public key', () => {
      const otherWallet = MLDSA87.newWallet();
      expect(verify(validSig, validMsg, otherWallet.getPK(), ctx)).to.equal(false);
    });

    it('returns false for modified message', () => {
      const modifiedMsg = new Uint8Array(validMsg);
      modifiedMsg[0] ^= 0x01;
      expect(verify(validSig, modifiedMsg, wallet.getPK(), ctx)).to.equal(false);
    });

    it('returns false for modified signature', () => {
      const modifiedSig = new Uint8Array(validSig);
      modifiedSig[0] ^= 0x01;
      expect(verify(modifiedSig, validMsg, wallet.getPK(), ctx)).to.equal(false);
    });
  });

  describe('Address Validation Edge Cases', () => {
    // Address helpers are length-agnostic: 20-byte (default, NIST Cat 1) and
    // 48-byte (opt-in, NIST Cat 5) addresses must both round-trip cleanly.

    it('stringToAddress accepts lowercase q prefix (20-byte default)', () => {
      const addr = 'q' + '0'.repeat(40);
      const bytes = stringToAddress(addr);
      expect(bytes).to.be.instanceOf(Uint8Array);
      expect(bytes.length).to.equal(20);
    });

    it('stringToAddress accepts uppercase Q prefix (20-byte default)', () => {
      const addr = 'Q' + '0'.repeat(40);
      const bytes = stringToAddress(addr);
      expect(bytes).to.be.instanceOf(Uint8Array);
      expect(bytes.length).to.equal(20);
    });

    it('stringToAddress accepts 48-byte (NIST Cat 5) addresses', () => {
      const addr = 'Q' + '0'.repeat(96);
      const bytes = stringToAddress(addr);
      expect(bytes).to.be.instanceOf(Uint8Array);
      expect(bytes.length).to.equal(48);
    });

    it('stringToAddress trims whitespace', () => {
      const addr = '  Q' + '0'.repeat(40) + '  ';
      const bytes = stringToAddress(addr);
      expect(bytes).to.be.instanceOf(Uint8Array);
    });

    it('stringToAddress rejects non-string input', () => {
      expect(() => stringToAddress(123)).to.throw('address must be a string');
      expect(() => stringToAddress(null)).to.throw('address must be a string');
      expect(() => stringToAddress(undefined)).to.throw('address must be a string');
    });

    it('stringToAddress rejects missing Q prefix', () => {
      expect(() => stringToAddress('0'.repeat(40))).to.throw('address must start with Q');
    });

    it('stringToAddress rejects empty or odd-length hex', () => {
      expect(() => stringToAddress('Q')).to.throw('address must be Q + a non-empty even number of hex characters');
      expect(() => stringToAddress('Q000')).to.throw('address must be Q + a non-empty even number of hex characters');
      expect(() => stringToAddress('Q' + '0'.repeat(41))).to.throw(
        'address must be Q + a non-empty even number of hex characters'
      );
    });

    it('stringToAddress rejects invalid hex characters', () => {
      expect(() => stringToAddress('Q' + 'z'.repeat(40))).to.throw('address contains invalid characters');
      expect(() => stringToAddress('Q' + '0'.repeat(39) + 'g')).to.throw('address contains invalid characters');
    });

    it('isValidAddress returns true for valid addresses of either size', () => {
      // 20-byte (v2.x default)
      expect(isValidAddress('Q' + '0'.repeat(40))).to.equal(true);
      expect(isValidAddress('Q' + 'f'.repeat(40))).to.equal(true);
      // 48-byte (NIST Cat 5 opt-in)
      expect(isValidAddress('Q' + '0'.repeat(96))).to.equal(true);
      expect(isValidAddress('Q' + 'f'.repeat(96))).to.equal(true);
    });

    it('isValidAddress returns false for invalid address', () => {
      expect(isValidAddress('')).to.equal(false);
      expect(isValidAddress('Q')).to.equal(false);
      expect(isValidAddress('Q000')).to.equal(false); // odd hex length
      expect(isValidAddress('0'.repeat(40))).to.equal(false); // no Q prefix
      expect(isValidAddress(null)).to.equal(false);
      expect(isValidAddress(123)).to.equal(false);
    });

    it('addressToString handles all-zero 20-byte address', () => {
      const zeros = new Uint8Array(20).fill(0);
      expect(addressToString(zeros)).to.equal('Q' + '0'.repeat(40));
    });

    it('addressToString handles all-ff 20-byte address', () => {
      const ffs = new Uint8Array(20).fill(0xff);
      expect(addressToString(ffs)).to.equal('Q' + 'f'.repeat(40));
    });

    it('addressToString handles all-zero 48-byte address', () => {
      const zeros = new Uint8Array(48).fill(0);
      expect(addressToString(zeros)).to.equal('Q' + '0'.repeat(96));
    });

    it('addressToString handles all-ff 48-byte address', () => {
      const ffs = new Uint8Array(48).fill(0xff);
      expect(addressToString(ffs)).to.equal('Q' + 'f'.repeat(96));
    });

    it('roundtrip: addressToString -> stringToAddress (default 20-byte)', () => {
      const original = wallet.getAddress();
      expect(original.length).to.equal(20);
      const str = addressToString(original);
      const bytes = stringToAddress(str);
      expect(Array.from(bytes)).to.deep.equal(Array.from(original));
    });
  });

  describe('Factory Edge Cases', () => {
    it('throws on unknown wallet type in extended seed', () => {
      // Create an extended seed with an unknown wallet type (0xFF)
      const badExtSeed = new Uint8Array(51);
      badExtSeed[0] = 0xff; // Unknown wallet type
      badExtSeed[1] = 0x00;
      badExtSeed[2] = 0x00;
      expect(() => newWalletFromExtendedSeed(badExtSeed)).to.throw('Invalid wallet type');
    });

    it('throws on too-short extended seed', () => {
      const shortSeed = new Uint8Array(10);
      expect(() => newWalletFromExtendedSeed(shortSeed)).to.throw();
    });

    it('throws on empty extended seed', () => {
      expect(() => newWalletFromExtendedSeed(new Uint8Array(0))).to.throw();
    });
  });

  describe('Wallet Zeroization', () => {
    it('zeroize() nulls secret key reference', () => {
      const w = MLDSA87.newWallet();
      const skBefore = new Uint8Array(w.getSK());
      expect(skBefore.some((b) => b !== 0)).to.equal(true);

      w.zeroize();
      expect(w.sk).to.equal(null);
    });

    it('zeroize() nulls seed reference', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(w.seed).to.equal(null);
    });

    it('zeroize() nulls extendedSeed reference', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(w.extendedSeed).to.equal(null);
    });

    it('zeroize() prevents sign()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.sign(new Uint8Array([1, 2, 3]))).to.throw('Wallet has been zeroized');
    });

    it('zeroize() prevents getSK()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.getSK()).to.throw('Wallet has been zeroized');
    });

    it('zeroize() prevents getSeed()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.getSeed()).to.throw('Wallet has been zeroized');
    });

    it('zeroize() prevents getExtendedSeed()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.getExtendedSeed()).to.throw('Wallet has been zeroized');
    });

    it('zeroize() prevents getMnemonic()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.getMnemonic()).to.throw('Wallet has been zeroized');
    });

    it('zeroize() prevents getHexExtendedSeed()', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.getHexExtendedSeed()).to.throw('Wallet has been zeroized');
    });

    it('zeroize() still allows getPK() and getAddress()', () => {
      const w = MLDSA87.newWallet();
      const pkBefore = w.getPK();
      const addrBefore = w.getAddressStr();
      w.zeroize();
      expect(w.getPK()).to.deep.equal(pkBefore);
      expect(w.getAddressStr()).to.equal(addrBefore);
    });

    it('zeroize() is idempotent', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(() => w.zeroize()).to.not.throw();
    });
  });

  describe('WalletType Constants', () => {
    it('ML_DSA_87 type is 1', () => {
      expect(WalletType.ML_DSA_87).to.equal(1);
    });

    it('SPHINCSPLUS_256S type is 0 (reserved, not implemented)', () => {
      expect(WalletType.SPHINCSPLUS_256S).to.equal(0);
    });
  });
});
