// Input-parsing superset locks (cross-implementation parity, X-3).
//
// wallet.js's address and mnemonic parsers deliberately accept a small,
// documented superset of what go-qrllib accepts — input normalization
// only (lowercase `q` prefix, surrounding whitespace, mnemonic casing and
// flexible inter-word whitespace). The CANONICAL output forms emitted by
// this library (`Q` + lowercase hex / EIP-55 checksummed; lowercase
// single-space mnemonics) match go-qrllib byte-for-byte, so anything this
// library produces is accepted everywhere. The leniencies below apply to
// what we *accept*, never to what we *emit*. See SECURITY.md
// "Input-parsing supersets vs go-qrllib".
//
// These tests lock the superset deliberately: if a leniency is ever
// removed (alignment with go-qrllib) or widened, this file must change in
// the same PR as the documentation.

import { expect } from 'chai';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { stringToAddress, isValidAddress, addressToString } from '../../src/wallet/common/address.js';
import { mnemonicToBin, binToMnemonic } from '../../src/wallet/misc/mnemonic.js';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';

const tc = walletTestCases[0];

describe('parser superset locks (input normalization vs go-qrllib)', () => {
  describe('address parsing', () => {
    const canonical = tc.wantAddress; // "Q" + lowercase hex

    it('canonical form round-trips and validates', () => {
      const bytes = stringToAddress(canonical);
      expect(addressToString(bytes)).to.equal(canonical);
      expect(isValidAddress(canonical)).to.equal(true);
    });

    it('accepts lowercase q prefix (accepted superset)', () => {
      const lower = `q${canonical.slice(1)}`;
      expect(stringToAddress(lower)).to.deep.equal(stringToAddress(canonical));
    });

    it('accepts surrounding whitespace (accepted superset)', () => {
      expect(stringToAddress(`  ${canonical}\n`)).to.deep.equal(stringToAddress(canonical));
    });

    it('accepts all-uppercase hex unchanged (legacy case-uniform form)', () => {
      const upper = `Q${canonical.slice(1).toUpperCase()}`;
      expect(stringToAddress(upper)).to.deep.equal(stringToAddress(canonical));
    });

    it('does NOT accept interior whitespace or other separators', () => {
      const hex = canonical.slice(1);
      const spaced = `Q${hex.slice(0, 8)} ${hex.slice(8)}`;
      expect(() => stringToAddress(spaced)).to.throw();
    });

    it('emitted form is canonical: Q-prefix + lowercase hex only', () => {
      const bytes = stringToAddress(canonical);
      const emitted = addressToString(bytes);
      expect(emitted.startsWith('Q')).to.equal(true);
      expect(emitted.slice(1)).to.equal(emitted.slice(1).toLowerCase());
    });
  });

  describe('mnemonic parsing', () => {
    const canonical = tc.wantMnemonic; // lowercase, single-space separated

    it('canonical form round-trips', () => {
      const bin = mnemonicToBin(canonical);
      expect(binToMnemonic(bin)).to.equal(canonical);
    });

    it('accepts UPPERCASE and Mixed-Case words (accepted superset)', () => {
      expect(mnemonicToBin(canonical.toUpperCase())).to.deep.equal(mnemonicToBin(canonical));
      const mixed = canonical
        .split(' ')
        .map((w, i) => (i % 2 === 0 ? w[0].toUpperCase() + w.slice(1) : w))
        .join(' ');
      expect(mnemonicToBin(mixed)).to.deep.equal(mnemonicToBin(canonical));
    });

    it('accepts flexible whitespace between words and around the phrase (accepted superset)', () => {
      const sloppy = `  ${canonical.split(' ').join('   ')}\t\n`;
      expect(mnemonicToBin(sloppy)).to.deep.equal(mnemonicToBin(canonical));
    });

    it('wallet construction accepts the normalized superset and derives the same wallet', () => {
      const w1 = MLDSA87.newWalletFromMnemonic(canonical);
      const w2 = MLDSA87.newWalletFromMnemonic(`  ${canonical.toUpperCase()}  `);
      expect(w2.getAddressStr()).to.equal(w1.getAddressStr());
      w1.zeroize();
      w2.zeroize();
    });

    it('emitted form is canonical: lowercase, single-space separated', () => {
      const emitted = binToMnemonic(mnemonicToBin(canonical));
      expect(emitted).to.equal(emitted.toLowerCase());
      expect(emitted).to.not.match(/\s{2,}|^\s|\s$/);
    });
  });
});
