/**
 * Seed ownership / lifecycle-isolation regression tests.
 *
 * `Wallet.newWalletFromSeed` historically stored the caller's `Seed`
 * instance by reference. A caller following SECURITY.md's own hygiene
 * advice (zeroize your inputs when done) would zero the wallet's internal
 * seed through the shared reference — after which `getSeed()` silently
 * returned 48 zero bytes while the wallet still reported itself live.
 * That is the same failure shape as the "post-zeroization wallet use"
 * audit finding (guard-flag bypass via shared mutable state): a secret
 * accessor returning wrong material with no error.
 *
 * These tests lock in the fixed contract: wallet and caller lifecycles
 * are fully independent in both directions.
 */
import { expect } from 'chai';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { Seed } from '../../src/wallet/common/seed.js';
import { SEED_SIZE } from '../../src/wallet/common/constants.js';

function patternSeedBytes() {
  return Uint8Array.from(Array.from({ length: SEED_SIZE }, (_, i) => (i * 7 + 3) & 0xff));
}

describe('seed ownership: newWalletFromSeed copies the caller seed', () => {
  it('caller zeroizing their Seed does not alter the wallet', () => {
    const original = patternSeedBytes();
    const callerSeed = new Seed(original);
    const w = MLDSA87.newWalletFromSeed(callerSeed);
    const addrBefore = w.getAddressStr();
    const mnemonicBefore = w.getMnemonic();

    callerSeed.zeroize();

    // Secret accessors must still return the *original* material — never
    // silently-zeroed bytes.
    expect(w.getSeed().toBytes()).to.deep.equal(original);
    expect(w.getMnemonic()).to.equal(mnemonicBefore);
    expect(w.getAddressStr()).to.equal(addrBefore);

    // Signing still works and verifies.
    const msg = new TextEncoder().encode('ownership');
    const sig = w.signDeterministic(msg);
    expect(MLDSA87.verify(sig, msg, w.getPK(), w.getDescriptor())).to.equal(true);
    w.zeroize();
  });

  it('wallet.zeroize() does not reach the caller-held Seed', () => {
    const original = patternSeedBytes();
    const callerSeed = new Seed(original);
    const w = MLDSA87.newWalletFromSeed(callerSeed);

    w.zeroize();

    expect(callerSeed.toBytes()).to.deep.equal(original);
    // The wallet itself is properly dead.
    expect(() => w.getSeed()).to.throw('Wallet has been zeroized');
    expect(() => w.sign(new Uint8Array([1]))).to.throw('Wallet has been zeroized');
    callerSeed.zeroize();
  });

  it('same caller Seed instance deterministically yields the same wallet twice', () => {
    const callerSeed = new Seed(patternSeedBytes());
    const w1 = MLDSA87.newWalletFromSeed(callerSeed);
    const w2 = MLDSA87.newWalletFromSeed(callerSeed);
    expect(w1.getAddressStr()).to.equal(w2.getAddressStr());
    expect(w1.getPK()).to.deep.equal(w2.getPK());
    w1.zeroize();
    w2.zeroize();
  });

  it('getSeed() returns an independent copy (mutation cannot reach the wallet)', () => {
    const callerSeed = new Seed(patternSeedBytes());
    const w = MLDSA87.newWalletFromSeed(callerSeed);
    const out = w.getSeed();
    out.zeroize();
    expect(w.getSeed().toBytes()).to.deep.equal(callerSeed.toBytes());
    w.zeroize();
  });

  it('public accessors remain functional after zeroize() by design', () => {
    // zeroize() destroys *secret* material. Address, public key, and
    // descriptor are public data and intentionally stay accessible —
    // e.g. so an app can still display which wallet was just closed.
    const w = MLDSA87.newWalletFromSeed(new Seed(patternSeedBytes()));
    const addr = w.getAddressStr();
    const pk = w.getPK();
    w.zeroize();
    expect(w.getAddressStr()).to.equal(addr);
    expect(w.getPK()).to.deep.equal(pk);
    expect(w.getDescriptor().toBytes()).to.deep.equal(new Uint8Array([1, 0, 0]));
  });
});
