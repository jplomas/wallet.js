import { expect } from 'chai';
import {
  SIGNING_CONTEXT_PREFIX,
  SIGNING_CONTEXT_SIZE,
  SIGNING_CONTEXT_VERSION,
  signingContext,
} from '../../src/wallet/common/context.js';
import { Descriptor } from '../../src/wallet/common/descriptor.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

describe('wallet/common/context', () => {
  it('exports the expected constants', () => {
    expect(SIGNING_CONTEXT_VERSION).to.equal(0x01);
    expect(Array.from(SIGNING_CONTEXT_PREFIX)).to.deep.equal([0x5a, 0x4f, 0x4e, 0x44]);
    expect(SIGNING_CONTEXT_SIZE).to.equal(8);
  });

  it('builds "ZOND" || version || descriptor for the canonical descriptor', () => {
    const desc = new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0]));
    const ctx = signingContext(desc);
    expect(ctx).to.be.instanceOf(Uint8Array);
    expect(ctx.length).to.equal(SIGNING_CONTEXT_SIZE);
    expect(Array.from(ctx)).to.deep.equal([
      0x5a,
      0x4f,
      0x4e,
      0x44,
      SIGNING_CONTEXT_VERSION,
      WalletType.ML_DSA_87,
      0,
      0,
    ]);
  });

  it('exactly one context is constructible — sibling contexts cannot exist via the public API', () => {
    // All three descriptor bytes are embedded in the context (locked by the
    // canonical-layout test above), and since metadata bytes are
    // reserved-zero (TOB-QRLLIB-3) with ML_DSA_87 the only valid type,
    // every constructible Descriptor yields the identical 8-byte context.
    const viaBytes = signingContext(new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0])));
    const viaHex = signingContext(Descriptor.from('0x010000'));
    expect(Array.from(viaBytes)).to.deep.equal(Array.from(viaHex));

    // Descriptors that would produce a different context are rejected at
    // construction, so a divergent context is unrepresentable upstream.
    expect(() => new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0x01, 0]))).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
    expect(() => new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0x01]))).to.throw(
      'Descriptor metadata bytes are reserved and must be zero'
    );
  });

  it('rejects non-Descriptor arguments', () => {
    expect(() => signingContext(null)).to.throw('descriptor must be a Descriptor instance');
    expect(() => signingContext(undefined)).to.throw('descriptor must be a Descriptor instance');
    expect(() => signingContext({})).to.throw('descriptor must be a Descriptor instance');
    expect(() => signingContext(Uint8Array.from([1, 0, 0]))).to.throw('descriptor must be a Descriptor instance');
  });
});
