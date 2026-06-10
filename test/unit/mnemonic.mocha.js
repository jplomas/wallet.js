import { expect } from 'chai';
import { binToMnemonic, mnemonicToBin } from '../../src/wallet/misc/mnemonic.js';

describe('wallet/misc/mnemonic', () => {
  describe('binToMnemonic', () => {
    it('encodes known bytes to expected words', () => {
      const cases = [
        { bytes: Uint8Array.from([0x00, 0x00, 0x00]), mnemonic: 'aback aback' },
        { bytes: Uint8Array.from([0x12, 0x34, 0x56]), mnemonic: 'base elbow' },
        { bytes: Uint8Array.from([0x00, 0x00, 0x00, 0xff, 0xff, 0xff]), mnemonic: 'aback aback zurich zurich' },
      ];
      cases.forEach(({ bytes, mnemonic }) => {
        expect(binToMnemonic(bytes)).to.equal(mnemonic);
      });
    });

    it('throws when byte lenght is not a multiple of 3', () => {
      expect(() => binToMnemonic(Uint8Array.from([0x01]))).to.throw('byte count needs to be a multiple of 3');
    });

    it('throws on non-Uint8Array input instead of encoding garbage', () => {
      // A string of length divisible by 3 used to pass the length check and
      // silently encode to a mnemonic of index-0 words via NaN coercion.
      expect(() => binToMnemonic('abcdef')).to.throw('input must be a Uint8Array');
      expect(() => binToMnemonic([0, 0, 0])).to.throw('input must be a Uint8Array');
      expect(() => binToMnemonic(null)).to.throw('input must be a Uint8Array');
    });
  });

  describe('mnemonicToBin', () => {
    it('decodes mixed-case mnemonic with extra spaces', () => {
      const mnemonic = '      ABACk   AbbeY   ';
      const expected = Uint8Array.from([0x00, 0x00, 0x01]);
      expect(mnemonicToBin(mnemonic)).to.deep.equal(expected);
    });

    it('roundtrips bytes through mnmemonic', () => {
      const bytes = Uint8Array.from([0, 1, 2, 3, 4, 5]);
      const mnemonic = binToMnemonic(bytes);
      expect(mnemonicToBin(mnemonic)).to.deep.equal(bytes);
    });

    it('throws on odd word counts', () => {
      expect(() => mnemonicToBin('aback')).to.throw('word count must be even');
    });

    it('throws on invalid words', () => {
      expect(() => mnemonicToBin('aback notaword')).to.throw('invalid word in mnemonic');
    });
  });
});
