// Tests for Wallet.verifyWithReason (TOB-QRLLIB-14 port from the
// go-qrllib Trail of Bits engagement). The discriminated-union variant
// of MLDSA87.verify that exposes typed failure reasons for diagnostic
// use cases. The boolean MLDSA87.verify is unchanged.

import { expect } from 'chai';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { newMLDSA87Descriptor } from '../../src/wallet/ml_dsa_87/descriptor.js';
import { sign, verify } from '../../src/wallet/ml_dsa_87/crypto.js';
import { signingContext } from '../../src/wallet/common/context.js';
import { CryptoBytes, CryptoPublicKeyBytes } from '@theqrl/mldsa87';

describe('Wallet.verifyWithReason (TOB-QRLLIB-14)', () => {
  const msg = utf8ToBytes('hello');
  let wallet;
  let sig;
  let pk;
  let desc;

  before(() => {
    wallet = MLDSA87.newWallet();
    sig = wallet.signDeterministic(msg);
    pk = wallet.getPK();
    desc = wallet.getDescriptor();
  });

  it('returns { ok: true } on valid signature', () => {
    const result = MLDSA87.verifyWithReason(sig, msg, pk, desc);
    expect(result.ok).to.equal(true);
  });

  it('distinguishes invalid-descriptor (not a Descriptor instance)', () => {
    const result = MLDSA87.verifyWithReason(sig, msg, pk, 'not-a-descriptor');
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-descriptor');
  });

  it('distinguishes invalid-signature-type (not a Uint8Array)', () => {
    const result = MLDSA87.verifyWithReason('not-bytes', msg, pk, desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-signature-type');
  });

  it('distinguishes invalid-signature-length', () => {
    const shortSig = new Uint8Array(CryptoBytes - 1);
    const result = MLDSA87.verifyWithReason(shortSig, msg, pk, desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-signature-length');
  });

  it('distinguishes invalid-message-type', () => {
    const result = MLDSA87.verifyWithReason(sig, 'not-bytes', pk, desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-message-type');
  });

  it('distinguishes invalid-pk-type', () => {
    const result = MLDSA87.verifyWithReason(sig, msg, 'not-bytes', desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-pk-type');
  });

  it('distinguishes invalid-pk-length', () => {
    const shortPk = new Uint8Array(CryptoPublicKeyBytes - 1);
    const result = MLDSA87.verifyWithReason(sig, msg, shortPk, desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('invalid-pk-length');
  });

  it('distinguishes verification-failed (well-formed inputs, bad signature)', () => {
    const tampered = new Uint8Array(sig);
    tampered[0] ^= 0x01;
    const result = MLDSA87.verifyWithReason(tampered, msg, pk, desc);
    expect(result.ok).to.equal(false);
    expect(result.reason).to.equal('verification-failed');
  });

  it('non-binding sibling descriptors are unrepresentable (TOB-QRLLIB-3 rejection)', () => {
    // Previously this asserted reason === 'verification-failed' under a
    // descriptor with different metadata. Reserved metadata is now
    // rejected at construction (go-qrllib IsValid parity), so the
    // "well-formed but wrong descriptor" scenario cannot be built via the
    // public API at all; the binding half of TOB-QRLLIB-3 is locked at
    // the crypto layer in metamorphic.mocha.js.
    expect(() => newMLDSA87Descriptor([0x42, 0x42])).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
  });

  describe('boolean Wallet.verify is total (TOB-QRLLIB-11)', () => {
    // The boolean form delegates to verifyWithReason and therefore never
    // throws on malformed inputs — wrong types, wrong lengths, and
    // non-Descriptor descriptors all collapse to `false` at this boundary
    // (go-qrllib parity: its Verify returns false instead of panicking).
    it('returns true on a valid tuple', () => {
      expect(MLDSA87.verify(sig, msg, pk, desc)).to.equal(true);
    });

    it('returns false (no throw) on malformed inputs', () => {
      expect(MLDSA87.verify('not-bytes', msg, pk, desc)).to.equal(false);
      expect(MLDSA87.verify(new Uint8Array(CryptoBytes - 1), msg, pk, desc)).to.equal(false);
      expect(MLDSA87.verify(sig, 'not-bytes', pk, desc)).to.equal(false);
      expect(MLDSA87.verify(sig, msg, 'not-bytes', desc)).to.equal(false);
      expect(MLDSA87.verify(sig, msg, new Uint8Array(CryptoPublicKeyBytes - 1), desc)).to.equal(false);
      expect(MLDSA87.verify(sig, msg, pk, 'not-a-descriptor')).to.equal(false);
      expect(MLDSA87.verify(null, null, null, null)).to.equal(false);
      expect(MLDSA87.verify(undefined, undefined, undefined, undefined)).to.equal(false);
    });

    it('returns false on a tampered signature', () => {
      const tampered = new Uint8Array(sig);
      tampered[1] ^= 0x80;
      expect(MLDSA87.verify(tampered, msg, pk, desc)).to.equal(false);
    });
  });

  describe('lower-layer validation errors carry stable codes', () => {
    // verifyWithReason classifies by error.code (never message text) —
    // these lock in the code contract for representative paths.
    function codeOf(fn) {
      try {
        fn();
      } catch (e) {
        return e.code;
      }
      throw new Error('expected function to throw');
    }

    it('verify: wrong-length signature throws ERR_SIGNATURE_LENGTH', () => {
      const ctx = signingContext(desc);
      expect(codeOf(() => verify(new Uint8Array(CryptoBytes - 1), msg, pk, ctx))).to.equal('ERR_SIGNATURE_LENGTH');
    });

    it('verify: wrong-length pk throws ERR_PK_LENGTH', () => {
      const ctx = signingContext(desc);
      expect(codeOf(() => verify(sig, msg, new Uint8Array(CryptoPublicKeyBytes - 1), ctx))).to.equal('ERR_PK_LENGTH');
    });

    it('verify: wrong types throw ERR_*_TYPE codes', () => {
      const ctx = signingContext(desc);
      expect(codeOf(() => verify('nope', msg, pk, ctx))).to.equal('ERR_SIGNATURE_TYPE');
      expect(codeOf(() => verify(sig, 'nope', pk, ctx))).to.equal('ERR_MESSAGE_TYPE');
      expect(codeOf(() => verify(sig, msg, 'nope', ctx))).to.equal('ERR_PK_TYPE');
      expect(codeOf(() => verify(sig, msg, pk, 'nope'))).to.equal('ERR_CTX_TYPE');
    });

    it('sign: validation errors carry codes too', () => {
      const ctx = signingContext(desc);
      const sk = wallet.getSK();
      expect(codeOf(() => sign('nope', msg, ctx))).to.equal('ERR_SK_TYPE');
      expect(codeOf(() => sign(new Uint8Array(3), msg, ctx))).to.equal('ERR_SK_LENGTH');
      expect(codeOf(() => sign(sk, 'nope', ctx))).to.equal('ERR_MESSAGE_TYPE');
      expect(codeOf(() => sign(sk, msg, 'nope'))).to.equal('ERR_CTX_TYPE');
      expect(codeOf(() => sign(sk, msg, ctx, 'nope'))).to.equal('ERR_RANDOMIZED_TYPE');
      sk.fill(0);
    });
  });
});
