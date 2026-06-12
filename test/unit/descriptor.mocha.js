import { expect } from 'chai';
import { Descriptor, getDescriptorBytes } from '../../src/wallet/common/descriptor.js';
import { DESCRIPTOR_SIZE } from '../../src/wallet/common/constants.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

describe('wallet/common/descriptor', () => {
  it('constructs from canonical bytes', () => {
    const bytes = Uint8Array.from([WalletType.ML_DSA_87, 0, 0]);
    const desc = new Descriptor(bytes);
    expect(desc.type()).to.equal(WalletType.ML_DSA_87);
    expect(desc.toBytes()).to.deep.equal(bytes);
  });

  it('constructs from hex strings with prefix and separators', () => {
    const desc = Descriptor.from('0X01-00_00');
    expect(desc.toBytes()).to.deep.equal(Uint8Array.from([1, 0, 0]));
  });

  it('getDescriptorBytes builds the canonical descriptor', () => {
    let descBytes = getDescriptorBytes(WalletType.ML_DSA_87);
    expect(descBytes).to.deep.equal(Uint8Array.from([1, 0, 0]));
    descBytes = getDescriptorBytes(WalletType.ML_DSA_87, [0, 0]);
    expect(descBytes).to.deep.equal(Uint8Array.from([1, 0, 0]));
  });

  it('getDescriptorBytes handles null/undefined metadata', () => {
    // Explicit null metadata falls back to [0, 0]
    expect(getDescriptorBytes(WalletType.ML_DSA_87, null)).to.deep.equal(Uint8Array.from([1, 0, 0]));
    // Explicit undefined metadata falls back to [0, 0]
    expect(getDescriptorBytes(WalletType.ML_DSA_87, undefined)).to.deep.equal(Uint8Array.from([1, 0, 0]));
    // Partial all-zero metadata array fills missing with 0
    expect(getDescriptorBytes(WalletType.ML_DSA_87, [0])).to.deep.equal(Uint8Array.from([1, 0, 0]));
  });

  // TOB-QRLLIB-3 (second half) — metadata bytes are reserved-zero, parity
  // with go-qrllib Descriptor.IsValid. Non-zero metadata must be rejected
  // at every construction path, otherwise one keypair maps to many sibling
  // addresses and the wallet diverges from go-qrllib/rust-qrllib validity.
  it('getDescriptorBytes rejects non-zero reserved metadata', () => {
    for (const metadata of [
      [1, 0],
      [0, 1],
      [0x10, 0x20],
      [0xff, 0xff],
      [256, 0], // out-of-range is also non-zero — same rejection
      [0, -1],
      [1.5, 0],
    ]) {
      expect(
        () => getDescriptorBytes(WalletType.ML_DSA_87, /** @type {[number, number]} */ (metadata)),
        `metadata [${metadata}]`
      ).to.throw('Descriptor metadata bytes are reserved and must be zero');
    }
  });

  it('Descriptor constructor rejects non-zero reserved metadata bytes', () => {
    expect(() => new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0xaa, 0xbb]))).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
    expect(() => new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 1, 0]))).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
    expect(() => new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 1]))).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
    expect(() => Descriptor.from('0X01-02_03')).to.throw('Descriptor metadata bytes are reserved and must be zero');
  });

  it('getDescriptorBytes throws on invalid wallet type', () => {
    expect(() => getDescriptorBytes(Uint8Array.from([0, 0, 0]))).to.throw('Invalid wallet type in descriptor');
  });

  it('throws on invalid size', () => {
    expect(() => new Descriptor(Uint8Array.from([1, 2]))).to.throw(`Descriptor must be ${DESCRIPTOR_SIZE} bytes`);
  });

  it('throws on invalid wallet type', () => {
    expect(() => new Descriptor(Uint8Array.from([0, 0, 0]))).to.throw('Invalid wallet type in descriptor');
  });
});
