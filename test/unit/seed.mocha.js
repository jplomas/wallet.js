import { expect } from 'chai';
import { sha256 } from '@noble/hashes/sha2.js';
import { Seed, ExtendedSeed } from '../../src/wallet/common/seed.js';
import { SEED_SIZE, EXTENDED_SEED_SIZE } from '../../src/wallet/common/constants.js';
import { getDescriptorBytes, Descriptor } from '../../src/wallet/common/descriptor.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

function buildSeedBytes() {
  return Uint8Array.from(Array.from({ length: SEED_SIZE }, (_, i) => i));
}

function buildDescriptorBytes(metadata = [0, 0]) {
  return getDescriptorBytes(WalletType.ML_DSA_87, metadata);
}

describe('wallet/common/seed', () => {
  describe('Seed', () => {
    it('creates from hex with separators', () => {
      const seedBytes = buildSeedBytes();
      const seedHex = Array.from(seedBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(':');
      const seed = Seed.from(`0x${seedHex}`);
      expect(seed.toBytes()).to.deep.equal(seedBytes);
    });

    it('produces correct sha256 hash', () => {
      const seedBytes = buildSeedBytes();
      const seed = new Seed(seedBytes);
      const expected = Uint8Array.from(sha256(seedBytes));
      expect(seed.hashSHA256()).to.deep.equal(expected);
    });

    it('throws on invalid sizes', () => {
      expect(() => new Seed(Uint8Array.from([1]))).to.throw(`Seed must be ${SEED_SIZE} bytes`);
      expect(() => Seed.from('0xdead')).to.throw(`Seed: expected ${SEED_SIZE} bytes, got 2`);
    });

    it('zeroize clears internal bytes', () => {
      const seedBytes = buildSeedBytes();
      const seed = new Seed(seedBytes);
      seed.zeroize();
      const zeros = new Uint8Array(SEED_SIZE);
      expect(seed.toBytes()).to.deep.equal(zeros);
    });
  });

  describe('ExtendedSeed', () => {
    it('constructs from descriptor + seed', () => {
      const descBytes = buildDescriptorBytes();
      const desc = new Descriptor(descBytes);
      const seedBytes = buildSeedBytes();
      const seed = new Seed(seedBytes);

      const ext = ExtendedSeed.newExtendedSeed(desc, seed);
      const expectedBytes = Uint8Array.from([...descBytes, ...seedBytes]);

      expect(ext.toBytes()).to.deep.equal(expectedBytes);
      expect(ext.getDescriptorBytes()).to.deep.equal(descBytes);
      expect(ext.getSeedBytes()).to.deep.equal(seedBytes);
      expect(ext.getDescriptor().toBytes()).to.deep.equal(descBytes);
      expect(ext.getSeed().toBytes()).to.deep.equal(seedBytes);
    });

    it('accepts hex input with prefix/separators', () => {
      const seedBytes = buildSeedBytes();
      const descBytes = buildDescriptorBytes();
      const combined = Uint8Array.from([...descBytes, ...seedBytes]);
      const withSeparators = Array.from(combined)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('_');

      const ext = ExtendedSeed.from(`0X${withSeparators}`);

      expect(ext.toBytes()).to.deep.equal(combined);
      expect(ext.getDescriptorBytes()).to.deep.equal(descBytes);
      expect(ext.getSeedBytes()).to.deep.equal(seedBytes);
      expect(ext.getDescriptor().toBytes()).to.deep.equal(descBytes);
      expect(ext.getSeed().toBytes()).to.deep.equal(seedBytes);
    });

    it('throws on invalid wallet type descriptor', () => {
      expect(() => new ExtendedSeed(Array.from({ length: EXTENDED_SEED_SIZE }, (_, i) => i))).to.throw(
        'Invalid wallet type in descriptor'
      );
    });

    it('rejects non-zero reserved descriptor metadata (TOB-QRLLIB-3, go-qrllib parity)', () => {
      // An extended seed imported from a tool that wrote non-zero metadata
      // would derive an address invalid to go-qrllib/rust-qrllib nodes —
      // reject it at the boundary instead of building an unspendable wallet.
      const bytes = new Uint8Array(EXTENDED_SEED_SIZE);
      bytes[0] = WalletType.ML_DSA_87;
      bytes[1] = 0x01;
      expect(() => new ExtendedSeed(bytes)).to.throw('Descriptor metadata bytes are reserved and must be zero');
      bytes[1] = 0;
      bytes[2] = 0xff;
      expect(() => new ExtendedSeed(bytes)).to.throw('Descriptor metadata bytes are reserved and must be zero');
      bytes[2] = 0;
      expect(() => new ExtendedSeed(bytes)).to.not.throw();
    });

    it('throws on invalid sizes', () => {
      expect(() => new ExtendedSeed(Uint8Array.from([1]))).to.throw(`ExtendedSeed must be ${EXTENDED_SEED_SIZE} bytes`);
      expect(() => ExtendedSeed.from('0xdead')).to.throw(`ExtendedSeed: expected ${EXTENDED_SEED_SIZE} bytes, got 2`);
    });

    it('zeroize clears internal bytes', () => {
      const descBytes = buildDescriptorBytes();
      const desc = new Descriptor(descBytes);
      const seedBytes = buildSeedBytes();
      const seed = new Seed(seedBytes);
      const ext = ExtendedSeed.newExtendedSeed(desc, seed);
      ext.zeroize();
      const zeros = new Uint8Array(EXTENDED_SEED_SIZE);
      expect(ext.toBytes()).to.deep.equal(zeros);
    });
  });
});
