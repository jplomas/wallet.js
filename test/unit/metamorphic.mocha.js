// Metamorphic property tests for the wallet layer.
//
// Port of the ToB-handoff metamorphic-fuzz patterns delivered during
// the `go-qrllib` Trail of Bits engagement, adapted to wallet.js's
// scope (ML-DSA-87 only, no XMSS, no SPHINCS+). Properties:
//
//  1. Verify rejects a single-bit-mauled pk.
//  2. Verify rejects a single-bit-mauled message.
//  3. Verify rejects a single-bit-mauled signature.
//  4. Deterministic signing yields distinct bytes on a mauled message.
//  5. **Descriptor-binding metamorphic (wallet-specific, TOB-QRLLIB-3
//     mode).** A signature produced under descriptor D1 must not
//     verify under any descriptor D2 ≠ D1, because the wallet's
//     8-byte signing context (`"ZOND" || version || descriptor`)
//     binds the descriptor into every signature. This is the
//     wallet-layer expression of the cross-cutting "domain-separated
//     context" property.
//
// Tests use a small deterministic-seed corpus so they run on every
// `npm test`. Uses `signDeterministic` for byte-equality assertions.

import { expect } from 'chai';
import { CryptoBytes, CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { newMLDSA87Descriptor } from '../../src/wallet/ml_dsa_87/descriptor.js';
import { verify as cryptoVerify } from '../../src/wallet/ml_dsa_87/crypto.js';
import { signingContext } from '../../src/wallet/common/context.js';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';

function flipSingleBit(src, bitIndex) {
  const out = new Uint8Array(src);
  const bit = bitIndex % (out.length * 8);
  out[bit >> 3] ^= 1 << (bit & 7);
  return out;
}

function corpusWallets() {
  // Three deterministic-seed wallets from the existing fixture corpus.
  return walletTestCases.slice(0, 3).map((tc) => MLDSA87.newWalletFromMnemonic(tc.wantMnemonic));
}

function corpusMessages() {
  return [new TextEncoder().encode('Hello'), new TextEncoder().encode('M'.repeat(64))];
}

describe('metamorphic: verify rejects mauled public key (TOB-QRLLIB-handoff)', () => {
  corpusWallets().forEach((w, wi) => {
    corpusMessages().forEach((msg) => {
      it(`wallet${wi} msg_len=${msg.length}`, () => {
        const sig = w.signDeterministic(msg);
        const pk = w.getPK();
        const desc = w.getDescriptor();
        expect(MLDSA87.verify(sig, msg, pk, desc)).to.equal(true);

        for (const bit of [0, 7, 100, CryptoPublicKeyBytes * 4, CryptoPublicKeyBytes * 8 - 1]) {
          const mauledPk = flipSingleBit(pk, bit);
          expect(MLDSA87.verify(sig, msg, mauledPk, desc), `single-bit mauled pk verified at bit ${bit}`).to.equal(
            false
          );
        }
      });
    });
  });
});

describe('metamorphic: verify rejects mauled message', () => {
  corpusWallets().forEach((w, wi) => {
    corpusMessages().forEach((msg) => {
      it(`wallet${wi} msg_len=${msg.length}`, () => {
        const sig = w.signDeterministic(msg);
        const pk = w.getPK();
        const desc = w.getDescriptor();
        expect(MLDSA87.verify(sig, msg, pk, desc)).to.equal(true);

        for (let bit = 0; bit < Math.min(64, msg.length * 8); bit += 11) {
          const mauledMsg = flipSingleBit(msg, bit);
          expect(MLDSA87.verify(sig, mauledMsg, pk, desc), `single-bit mauled message verified at bit ${bit}`).to.equal(
            false
          );
        }
      });
    });
  });
});

describe('metamorphic: verify rejects mauled signature', () => {
  corpusWallets().forEach((w, wi) => {
    corpusMessages().forEach((msg) => {
      it(`wallet${wi} msg_len=${msg.length}`, () => {
        const sig = w.signDeterministic(msg);
        const pk = w.getPK();
        const desc = w.getDescriptor();
        expect(MLDSA87.verify(sig, msg, pk, desc)).to.equal(true);

        for (const bit of [0, 1, 127, CryptoBytes * 4, CryptoBytes * 8 - 1]) {
          const mauledSig = flipSingleBit(sig, bit);
          expect(
            MLDSA87.verify(mauledSig, msg, pk, desc),
            `single-bit mauled signature verified at bit ${bit}`
          ).to.equal(false);
        }
      });
    });
  });
});

describe('metamorphic: deterministic signing differs on mauled message (TOB-QRLLIB-6 mode)', () => {
  corpusWallets().forEach((w, wi) => {
    corpusMessages().forEach((msg) => {
      it(`wallet${wi} msg_len=${msg.length}`, () => {
        const base = w.signDeterministic(msg);
        for (let bit = 0; bit < Math.min(64, msg.length * 8); bit += 11) {
          const mauledMsg = flipSingleBit(msg, bit);
          const mauledSig = w.signDeterministic(mauledMsg);
          expect(
            Buffer.from(base).equals(Buffer.from(mauledSig)),
            `deterministic signing collision on mauled message at bit ${bit}`
          ).to.equal(false);
        }
      });
    });
  });
});

describe('metamorphic: descriptor-binding (wallet-specific, TOB-QRLLIB-3 mode)', () => {
  // A signature produced under descriptor D1 must NOT verify under any
  // context carrying descriptor bytes D2 ≠ D1 — the 8-byte signing
  // context `"ZOND" || SIGNING_CONTEXT_VERSION || descriptor` binds the
  // descriptor into every signature.
  //
  // Both halves of TOB-QRLLIB-3 are locked here:
  //  (a) REJECTION — non-zero reserved metadata cannot construct a
  //      Descriptor at all, so sibling descriptors are unrepresentable
  //      through the public API (go-qrllib `IsValid` parity);
  //  (b) BINDING — even if non-canonical descriptor bytes reach the
  //      crypto layer (hand-built context below, bypassing the public
  //      constructors), the signature does not verify under them.
  corpusWallets().forEach((w, wi) => {
    corpusMessages().forEach((msg) => {
      it(`wallet${wi} msg_len=${msg.length}`, () => {
        const sig = w.signDeterministic(msg);
        const pk = w.getPK();
        const trueDesc = w.getDescriptor();
        expect(MLDSA87.verify(sig, msg, pk, trueDesc)).to.equal(true);

        // (a) Rejection: sibling descriptors cannot be constructed.
        for (const [m0, m1] of [
          [1, 0],
          [0, 1],
          [0xff, 0xff],
          [0x42, 0x42],
        ]) {
          expect(
            () => newMLDSA87Descriptor(/** @type {[number, number]} */ ([m0, m1])),
            `descriptor with reserved metadata [${m0},${m1}] was constructible`
          ).to.throw('Descriptor metadata bytes are reserved and must be zero');
        }

        // (b) Binding: a hand-built context whose descriptor bytes differ
        // from the signing descriptor must not verify, even though the
        // sig/msg/pk triple is untouched. Mutate each descriptor byte
        // position within the true 8-byte context.
        const trueCtx = signingContext(trueDesc);
        for (let pos = trueCtx.length - 3; pos < trueCtx.length; pos += 1) {
          const mauledCtx = new Uint8Array(trueCtx);
          mauledCtx[pos] ^= 0x42;
          expect(
            cryptoVerify(sig, msg, pk, mauledCtx),
            `signature verified under mauled descriptor context byte ${pos}`
          ).to.equal(false);
        }
      });
    });
  });
});
