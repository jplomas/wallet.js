import { expect } from 'chai';
import * as api from '../../src/index.js';

describe('public API (src/index.js)', () => {
  const expectedExports = [
    'Seed',
    'SEED_SIZE',
    'ExtendedSeed',
    'EXTENDED_SEED_SIZE',
    'Descriptor',
    'DESCRIPTOR_SIZE',
    'ADDRESS_SIZE',
    'SIGNING_CONTEXT_PREFIX',
    'SIGNING_CONTEXT_SIZE',
    'SIGNING_CONTEXT_VERSION',
    'signingContext',
    'newMLDSA87Descriptor',
    'getAddressFromPKAndDescriptor',
    'addressToString',
    'stringToAddress',
    'isValidAddress',
    'WalletType',
    'newWalletFromExtendedSeed',
    'MLDSA87',
  ];

  expectedExports.forEach((name) => {
    it(`exports ${name}`, () => {
      expect(api).to.have.property(name);
      expect(api[name]).to.not.be.undefined;
    });
  });

  it('has no unexpected exports', () => {
    const actual = Object.keys(api).sort();
    expect(actual).to.deep.equal([...expectedExports].sort());
  });
});
