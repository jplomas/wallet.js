import { expect } from 'chai';
import { bytesToHex, utf8ToBytes, hexToBytes } from '@noble/hashes/utils.js';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';
import { ExtendedSeed } from '../../src/wallet/common/seed.js';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import * as Wallet from '../../src/wallet/factory.js';
import { DESCRIPTOR_SIZE } from '../../src/wallet/common/constants.js';

function createWalletFromSeed(tc) {
  const ext = ExtendedSeed.from(tc.extendedSeed);
  const seed = ext.getSeed();
  return MLDSA87.newWalletFromSeed(seed);
}

function createWalletFromExtendedSeed(tc) {
  const ext = ExtendedSeed.from(tc.extendedSeed);
  return MLDSA87.newWalletFromExtendedSeed(ext);
}

function createWalletFromMnemonic(tc) {
  return MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);
}

function createWalletFromFactory(tc) {
  return Wallet.newWalletFromExtendedSeed(tc.extendedSeed);
}

const walletCreators = {
  FromSeed: createWalletFromSeed,
  FromExtendedSeed: createWalletFromExtendedSeed,
  FromMnemonic: createWalletFromMnemonic,
  FromFactory: createWalletFromFactory,
};

describe('ML-DSA-87 Wallet', () => {
  it('newWallet() creates a wallet(random)', () => {
    const w = MLDSA87.newWallet();
    expect(w).to.be.instanceOf(MLDSA87);
    expect(w.getPK()).to.be.instanceof(Uint8Array);
    expect(w.getSK()).to.be.instanceof(Uint8Array);
  });

  it('getDescriptor() returns ML_DSA_87 type descriptor', () => {
    const w = MLDSA87.newWallet();
    const desc = w.getDescriptor();
    expect(desc.type()).to.equal(1); // ML_DSA_87
    expect(desc.toBytes().length).to.equal(DESCRIPTOR_SIZE);
  });

  it('returns defensive copies for descriptor/seed/extendedSeed', () => {
    const tc = walletTestCases[0];
    const w = createWalletFromExtendedSeed(tc);

    const seedCopy = w.getSeed();
    seedCopy.bytes[0] ^= 0xff;
    expect(bytesToHex(w.getSeed().toBytes())).to.equal(tc.extendedSeed.slice(DESCRIPTOR_SIZE * 2));

    const extCopy = w.getExtendedSeed();
    extCopy.bytes[0] ^= 0xff;
    expect(bytesToHex(w.getExtendedSeed().toBytes())).to.equal(tc.extendedSeed);

    const descCopy = w.getDescriptor();
    descCopy.bytes[0] ^= 0xff;
    expect(w.getDescriptor().type()).to.equal(1);
  });

  describe('Seed bytes equal extendedSeed sans 3-byte descriptor', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          const got = bytesToHex(w.getSeed().toBytes());
          const want = tc.extendedSeed.slice(DESCRIPTOR_SIZE * 2);
          expect(got).to.equal(want);
        });
      });
    });
  });

  describe('ExtendedSeed bytes match vectors', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          const got = bytesToHex(w.getExtendedSeed().toBytes());
          expect(got).to.equal(tc.extendedSeed);
        });
      });
    });
  });

  describe('HexExtendedSeed is "0x" + extendedSeed', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          expect(w.getHexExtendedSeed()).to.equal(`0x${tc.extendedSeed}`);
        });
      });
    });
  });

  describe('Mnemonic matches vectors', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          expect(w.getMnemonic()).to.equal(tc.wantMnemonic);
        });
      });
    });
  });

  describe('Public/Secret keys match vectors', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - PK - ${tc.name}`, () => {
          const w = creator(tc);
          const got = bytesToHex(w.getPK());
          expect(got).to.equal(tc.wantPK);
        });
        it(`${creatorName} - SK - ${tc.name}`, () => {
          const w = creator(tc);
          const got = bytesToHex(w.getSK());
          expect(got).to.equal(tc.wantSK);
        });
      });
    });
  });

  describe('Address(bytes) matches vectors', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          const got = bytesToHex(w.getAddress());
          expect(got).to.equal(tc.wantAddress.slice(1));
        });
      });
    });
  });

  describe('Address(string) matches vectors', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          expect(w.getAddressStr()).to.equal(tc.wantAddress);
        });
      });
    });
  });

  // The pinned `wantSignature` vectors are the deterministic FIPS 204
  // §3.5 outputs (matches go-qrllib / mldsa87 ACVP vectors). After
  // TOB-QRLLIB-6 the wallet's default `sign()` is hedged and therefore
  // produces fresh bytes on every call, so the byte-equality assertion
  // here must use `signDeterministic`. Hedged `sign()` is covered by the
  // verify-instead pattern in the `Sign & Verify` and `Hedged sign
  // (TOB-QRLLIB-6)` blocks below.
  describe('signDeterministic matches vectors (FIPS 204 §3.5)', () => {
    Object.entries(walletCreators).forEach(([creatorName, creator]) => {
      walletTestCases.forEach((tc) => {
        it(`${creatorName} - ${tc.name}`, () => {
          const w = creator(tc);
          const msg = utf8ToBytes(tc.message, 'utf8');
          const sig = w.signDeterministic(msg);
          expect(bytesToHex(sig)).to.equal(tc.wantSignature);
        });
      });
    });
  });

  describe('Hedged sign (TOB-QRLLIB-6) — distinct bytes, both verify', () => {
    walletTestCases.forEach((tc) => {
      it(`${tc.name}`, () => {
        const w = createWalletFromMnemonic(tc);
        const msg = utf8ToBytes(tc.message, 'utf8');
        const sigA = w.sign(msg);
        const sigB = w.sign(msg);

        // Hedged: two signs of the same (sk, ctx, message) yield
        // distinct signatures (FIPS 204 §3.4). Skip the empty-message
        // case where some impls collapse, though ML-DSA still hedges.
        if (msg.length > 0) {
          expect(bytesToHex(sigA)).to.not.equal(bytesToHex(sigB));
        }

        // Both must verify under the same pk + descriptor.
        const pk = w.getPK();
        const desc = w.getDescriptor();
        expect(MLDSA87.verify(sigA, msg, pk, desc)).to.equal(true);
        expect(MLDSA87.verify(sigB, msg, pk, desc)).to.equal(true);

        // The deterministic signature must also verify under the same
        // pk + descriptor (hedged/deterministic are interchangeable at
        // the verification boundary).
        const sigDet = w.signDeterministic(msg);
        expect(MLDSA87.verify(sigDet, msg, pk, desc)).to.equal(true);
      });
    });
  });

  describe('Verify vectors', () => {
    walletTestCases.forEach((tc) => {
      it(`${tc.name}`, () => {
        const sig = hexToBytes(tc.wantSignature);
        const pk = hexToBytes(tc.wantPK);
        const msg = utf8ToBytes(tc.message);
        // Rebuild the wallet to recover the canonical descriptor embedded in
        // the signing context; verification is bound to it.
        const desc = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic).getDescriptor();
        expect(MLDSA87.verify(sig, msg, pk, desc)).to.equal(true);
      });
    });
  });

  describe('Sign & Verify', () => {
    const cases = [
      { name: 'ASCII', msg: utf8ToBytes('test message') },
      { name: 'Empty', msg: Buffer.alloc(0) },
      { name: 'Binary', msg: Uint8Array.from([1, 2, 3, 4, 5]) },
    ];

    cases.forEach((t) => {
      it(`newWallet - ${t.name}`, () => {
        const w = MLDSA87.newWallet();
        const sig = w.sign(t.msg);
        const pk = w.getPK();
        const desc = w.getDescriptor();

        expect(MLDSA87.verify(sig, t.msg, pk, desc)).to.equal(true);

        // tamper message
        if (t.msg.length > 0) {
          const tampered = new Uint8Array(t.msg);
          tampered[0] ^= 0x01;
          expect(MLDSA87.verify(sig, tampered, pk, desc)).to.equal(false);
        }

        // tamper signature
        if (sig.length > 0) {
          const tampered = new Uint8Array(sig);
          tampered[0] ^= 0x01;
          expect(MLDSA87.verify(tampered, t.msg, pk, desc)).to.equal(false);
        }
      });
    });
  });
});
