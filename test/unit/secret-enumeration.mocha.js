/**
 * Defense-in-depth tests against accidental secret leakage through
 * enumeration / serialization / inspection of Wallet, Seed, and
 * ExtendedSeed instances.
 *
 * Secret-bearing fields (`sk`, `seed`, `extendedSeed`, `_zeroized` on
 * Wallet; `bytes` on Seed and ExtendedSeed) are non-enumerable. Each
 * class defines `toJSON()` returning a redacted public-only shape and a
 * `util.inspect.custom` symbol that renders a safe string. These tests
 * lock that behavior in so a future refactor cannot silently expose
 * secrets through enumeration / serialization / default inspection.
 */
import { expect } from 'chai';
import { inspect } from 'node:util';
import { MLDSA87 } from '../../src/index.js';
import { Seed, ExtendedSeed } from '../../src/wallet/common/seed.js';
import { SEED_SIZE, EXTENDED_SEED_SIZE } from '../../src/wallet/common/constants.js';

const SECRET_FIELDS = ['seed', 'sk', 'extendedSeed', '_zeroized'];

function buildSeed() {
  return new Seed(Uint8Array.from(Array.from({ length: SEED_SIZE }, (_, i) => (i + 7) & 0xff)));
}

function buildExtendedSeed() {
  const bytes = new Uint8Array(EXTENDED_SEED_SIZE);
  bytes[0] = 0x01; // ML_DSA_87 wallet type
  // bytes 1-2 stay zero: descriptor metadata is reserved-zero (TOB-QRLLIB-3)
  for (let i = 3; i < EXTENDED_SEED_SIZE; i += 1) bytes[i] = (i * 13 + 5) & 0xff;
  return new ExtendedSeed(bytes);
}

describe('secret-bearing fields are not enumerable / serializable', () => {
  describe('Wallet', () => {
    it('Object.keys() does not reveal secret fields', () => {
      const w = MLDSA87.newWallet();
      const keys = Object.keys(w);
      for (const name of SECRET_FIELDS) {
        expect(keys, `key '${name}' leaked via Object.keys`).to.not.include(name);
      }
      // descriptor and pk are public, and must remain visible.
      expect(keys).to.include.members(['descriptor', 'pk']);
    });

    it('spread (...wallet) does not copy secret fields', () => {
      const w = MLDSA87.newWallet();
      const spread = { ...w };
      for (const name of SECRET_FIELDS) {
        expect(spread, `spread copied '${name}'`).to.not.have.property(name);
      }
    });

    it('JSON.stringify() produces a redacted public shape — no secrets', () => {
      const w = MLDSA87.newWallet();
      const json = JSON.stringify(w);
      const skHex = [...w.getSK()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const seedHex = [...w.getSeed().toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const extHex = [...w.getExtendedSeed().toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');

      // Raw secret material must not appear anywhere in the serialized form.
      expect(json, 'sk hex appeared in JSON').to.not.include(skHex);
      expect(json, 'seed hex appeared in JSON').to.not.include(seedHex);
      expect(json, 'extendedSeed hex appeared in JSON').to.not.include(extHex);

      // The redacted shape exposes only address + public key.
      const parsed = JSON.parse(json);
      expect(Object.keys(parsed).sort()).to.deep.equal(['address', 'pk']);
      expect(parsed.address).to.equal(w.getAddressStr());
      expect(parsed.pk).to.match(/^0x[0-9a-f]+$/);
    });

    it('util.inspect() does not reveal secret bytes', () => {
      const w = MLDSA87.newWallet();
      const rendered = inspect(w, { depth: null });
      const skHex = [...w.getSK()].map((b) => b.toString(16).padStart(2, '0')).join('');
      expect(rendered).to.include(w.getAddressStr());
      expect(rendered).to.include('redacted');
      expect(rendered, 'sk hex leaked through util.inspect').to.not.include(skHex);
    });

    it('structured logging / property access still works for legitimate callers', () => {
      // Non-enumerable ≠ inaccessible. Direct reads and the public getters
      // must continue to function; only *accidental* traversal is blocked.
      const w = MLDSA87.newWallet();
      expect(w.sk).to.be.instanceOf(Uint8Array);
      expect(w.seed).to.be.instanceOf(Seed);
      expect(w.extendedSeed).to.be.instanceOf(ExtendedSeed);
      expect(w.getSK()).to.be.instanceOf(Uint8Array);
      expect(w.getSeed()).to.be.instanceOf(Seed);
      expect(w.getExtendedSeed()).to.be.instanceOf(ExtendedSeed);
    });

    it('inspect() after zeroize() reports zeroized state without throwing', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      const rendered = inspect(w, { depth: null });
      expect(rendered).to.include('zeroized');
      expect(rendered).to.include('redacted');
    });

    it('zeroize() still nulls secret references (non-enumerable is writable)', () => {
      const w = MLDSA87.newWallet();
      w.zeroize();
      expect(w.sk).to.equal(null);
      expect(w.seed).to.equal(null);
      expect(w.extendedSeed).to.equal(null);
    });
  });

  describe('Seed', () => {
    it('Object.keys() does not reveal bytes', () => {
      const s = buildSeed();
      expect(Object.keys(s)).to.not.include('bytes');
    });

    it('JSON.stringify() returns a redacted shape — no raw bytes', () => {
      const s = buildSeed();
      const hex = [...s.toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const json = JSON.stringify(s);
      expect(json).to.not.include(hex);
      expect(JSON.parse(json)).to.deep.equal({ type: 'Seed', redacted: true });
    });

    it('util.inspect() does not reveal raw bytes', () => {
      const s = buildSeed();
      const hex = [...s.toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const rendered = inspect(s, { depth: null });
      expect(rendered).to.include('redacted');
      expect(rendered).to.not.include(hex);
    });

    it('spread (...seed) does not copy bytes', () => {
      const s = buildSeed();
      expect({ ...s }).to.not.have.property('bytes');
    });

    it('toBytes() still works (non-enumerable is still readable)', () => {
      const s = buildSeed();
      expect(s.toBytes()).to.be.instanceOf(Uint8Array);
      expect(s.toBytes().length).to.equal(SEED_SIZE);
    });
  });

  describe('ExtendedSeed', () => {
    it('Object.keys() does not reveal bytes', () => {
      const e = buildExtendedSeed();
      expect(Object.keys(e)).to.not.include('bytes');
    });

    it('JSON.stringify() returns a redacted shape — no raw bytes', () => {
      const e = buildExtendedSeed();
      const hex = [...e.toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const json = JSON.stringify(e);
      expect(json).to.not.include(hex);
      expect(JSON.parse(json)).to.deep.equal({ type: 'ExtendedSeed', redacted: true });
    });

    it('util.inspect() does not reveal raw bytes', () => {
      const e = buildExtendedSeed();
      const hex = [...e.toBytes()].map((b) => b.toString(16).padStart(2, '0')).join('');
      const rendered = inspect(e, { depth: null });
      expect(rendered).to.include('redacted');
      expect(rendered).to.not.include(hex);
    });

    it('spread (...extendedSeed) does not copy bytes', () => {
      const e = buildExtendedSeed();
      expect({ ...e }).to.not.have.property('bytes');
    });

    it('toBytes() still works (non-enumerable is still readable)', () => {
      const e = buildExtendedSeed();
      expect(e.toBytes()).to.be.instanceOf(Uint8Array);
      expect(e.toBytes().length).to.equal(EXTENDED_SEED_SIZE);
    });
  });
});
