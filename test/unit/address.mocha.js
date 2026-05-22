import { expect } from 'chai';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';
import {
  addressToString,
  stringToAddress,
  isValidAddress,
  toChecksumAddress,
  isValidChecksumAddress,
  getAddressFromPKAndDescriptor,
} from '../../src/wallet/common/address.js';
import { Descriptor } from '../../src/wallet/common/descriptor.js';
import { ADDRESS_SIZE, DESCRIPTOR_SIZE } from '../../src/wallet/common/constants.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

describe('wallet/common/address', () => {
  const tc = walletTestCases[0];
  const addrHex = tc.wantAddress.slice(1);

  it('addressToString prefixes Q and hex encodes bytes', () => {
    const addrBytes = hexToBytes(addrHex);
    expect(addressToString(addrBytes)).to.equal(tc.wantAddress);
  });

  it('addressToString throws on non-Uint8 input', () => {
    expect(() => addressToString(null)).to.throw('address must be a Uint8Array');
    expect(() => addressToString([1, 2, 3])).to.throw('address must be a Uint8Array');
  });

  it('addressToString rejects wrong-length addresses', () => {
    // ADDRESS_SIZE = 64 is the only valid length, matching go-qrllib
    // and rust-qrllib.
    expect(() => addressToString(new Uint8Array(0))).to.throw('address must be exactly 64 bytes');
    expect(() => addressToString(new Uint8Array(20).fill(0xaa))).to.throw('address must be exactly 64 bytes');
    expect(() => addressToString(new Uint8Array(48).fill(0xaa))).to.throw('address must be exactly 64 bytes');
    expect(addressToString(new Uint8Array(64).fill(0xaa))).to.match(/^Q[0-9a-f]{128}$/);
  });

  it('getAddressFromPKAndDescriptor rejects wrong pk length for ML-DSA-87', () => {
    const desc = new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0]));
    const badPk = new Uint8Array(CryptoPublicKeyBytes - 1);
    expect(() => getAddressFromPKAndDescriptor(badPk, desc)).to.throw(`pk must be ${CryptoPublicKeyBytes} bytes`);
  });

  it('getAddressFromPKAndDescriptor derives expected address for vector', () => {
    const descBytes = hexToBytes(tc.extendedSeed.slice(0, DESCRIPTOR_SIZE * 2));
    const pk = hexToBytes(tc.wantPK);
    const addr = getAddressFromPKAndDescriptor(pk, new Descriptor(descBytes));
    expect(bytesToHex(addr)).to.equal(addrHex);
  });

  it('getAddressFromPKAndDescriptor rejects non-Uint8 public keys', () => {
    const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
    expect(() => getAddressFromPKAndDescriptor([1, 2, 3], desc)).to.throw('pk must be Uint8Array');
  });

  describe('EIP-55-style checksum', () => {
    // Recompute the canonical checksummed form for a given lowercase hex body
    // using the documented algorithm. Exercised here so the test will detect
    // any silent change to the algorithm in `address.js`.
    function expectedChecksum(lowerHex) {
      const input = new Uint8Array(lowerHex.length);
      for (let i = 0; i < lowerHex.length; i += 1) input[i] = lowerHex.charCodeAt(i);
      const hash = shake256.create({ dkLen: ADDRESS_SIZE }).update(input).digest();
      let out = '';
      for (let i = 0; i < lowerHex.length; i += 1) {
        const c = lowerHex[i];
        const isLetter = c >= 'a' && c <= 'f';
        const nibble = (i & 1) === 0 ? hash[i >> 1] >> 4 : hash[i >> 1] & 0x0f;
        out += isLetter && nibble >= 8 ? c.toUpperCase() : c;
      }
      return out;
    }

    it('toChecksumAddress(bytes) matches documented algorithm', () => {
      const bytes = hexToBytes(addrHex);
      const expected = `Q${expectedChecksum(addrHex)}`;
      expect(toChecksumAddress(bytes)).to.equal(expected);
    });

    it('toChecksumAddress preserves the byte value (round-trips)', () => {
      const bytes = hexToBytes(addrHex);
      const checksummed = toChecksumAddress(bytes);
      expect(bytesToHex(stringToAddress(checksummed))).to.equal(addrHex);
    });

    it('toChecksumAddress accepts the lowercase string form', () => {
      const lower = tc.wantAddress; // already lowercase
      expect(toChecksumAddress(lower)).to.equal(toChecksumAddress(hexToBytes(addrHex)));
    });

    it('toChecksumAddress accepts the all-uppercase hex form', () => {
      const upper = `Q${addrHex.toUpperCase()}`;
      expect(toChecksumAddress(upper)).to.equal(toChecksumAddress(hexToBytes(addrHex)));
    });

    it('toChecksumAddress accepts lowercase q prefix on input', () => {
      const lowerQ = `q${addrHex}`;
      expect(toChecksumAddress(lowerQ)).to.equal(toChecksumAddress(hexToBytes(addrHex)));
    });

    it('toChecksumAddress is idempotent', () => {
      const checksummed = toChecksumAddress(hexToBytes(addrHex));
      expect(toChecksumAddress(checksummed)).to.equal(checksummed);
    });

    it('toChecksumAddress rejects unsupported input types', () => {
      expect(() => toChecksumAddress(null)).to.throw('address must be a Uint8Array or string');
      expect(() => toChecksumAddress(123)).to.throw('address must be a Uint8Array or string');
      expect(() => toChecksumAddress([1, 2, 3])).to.throw('address must be a Uint8Array or string');
    });

    it('toChecksumAddress rejects wrong-length Uint8Array', () => {
      expect(() => toChecksumAddress(new Uint8Array(20))).to.throw('address must be exactly 64 bytes');
      expect(() => toChecksumAddress(new Uint8Array(0))).to.throw('address must be exactly 64 bytes');
    });

    it('toChecksumAddress rejects a mixed-case string with a bad checksum', () => {
      // Flip case of a single hex letter in the canonical checksummed form.
      const good = toChecksumAddress(hexToBytes(addrHex));
      const hex = good.slice(1);
      // Find a hex letter and flip its case.
      let flipIdx = -1;
      for (let i = 0; i < hex.length; i += 1) {
        const c = hex[i];
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
          flipIdx = i;
          break;
        }
      }
      expect(flipIdx).to.not.equal(-1, 'fixture must contain at least one hex letter');
      const flipped =
        hex[flipIdx] === hex[flipIdx].toLowerCase() ? hex[flipIdx].toUpperCase() : hex[flipIdx].toLowerCase();
      const bad = `Q${hex.slice(0, flipIdx)}${flipped}${hex.slice(flipIdx + 1)}`;
      expect(() => toChecksumAddress(bad)).to.throw('invalid EIP-55 checksum');
    });

    it('stringToAddress accepts the checksummed form', () => {
      const checksummed = toChecksumAddress(hexToBytes(addrHex));
      expect(bytesToHex(stringToAddress(checksummed))).to.equal(addrHex);
    });

    it('stringToAddress accepts all-lowercase and all-uppercase unchanged', () => {
      const upper = `Q${addrHex.toUpperCase()}`;
      expect(bytesToHex(stringToAddress(tc.wantAddress))).to.equal(addrHex);
      expect(bytesToHex(stringToAddress(upper))).to.equal(addrHex);
    });

    it('stringToAddress rejects mixed-case with a bad checksum', () => {
      // Take the lowercase form and uppercase a single letter that the
      // checksum says should remain lowercase. We pick any letter whose
      // checksum nibble is < 8.
      const checksummed = toChecksumAddress(hexToBytes(addrHex));
      const lowerHex = addrHex;
      let badIdx = -1;
      for (let i = 0; i < lowerHex.length; i += 1) {
        const c = lowerHex[i];
        if (c >= 'a' && c <= 'f' && checksummed[i + 1] === c) {
          badIdx = i;
          break;
        }
      }
      expect(badIdx).to.not.equal(-1, 'fixture must have a lowercase-by-checksum letter');
      const corrupted = `Q${lowerHex.slice(0, badIdx)}${lowerHex[badIdx].toUpperCase()}${lowerHex.slice(badIdx + 1)}`;
      expect(() => stringToAddress(corrupted)).to.throw('invalid EIP-55 checksum');
      expect(isValidAddress(corrupted)).to.equal(false);
    });

    it('isValidChecksumAddress returns true for the canonical checksummed form', () => {
      const checksummed = toChecksumAddress(hexToBytes(addrHex));
      expect(isValidChecksumAddress(checksummed)).to.equal(true);
    });

    it('isValidChecksumAddress is strict: rejects all-lowercase with letters', () => {
      expect(isValidChecksumAddress(tc.wantAddress)).to.equal(false);
    });

    it('isValidChecksumAddress is strict: rejects all-uppercase with letters', () => {
      expect(isValidChecksumAddress(`Q${addrHex.toUpperCase()}`)).to.equal(false);
    });

    it('isValidChecksumAddress is strict: rejects lowercase q prefix', () => {
      const checksummed = toChecksumAddress(hexToBytes(addrHex));
      const lowerQ = `q${checksummed.slice(1)}`;
      expect(isValidChecksumAddress(lowerQ)).to.equal(false);
    });

    it('isValidChecksumAddress rejects non-string and malformed input', () => {
      expect(isValidChecksumAddress(null)).to.equal(false);
      expect(isValidChecksumAddress(undefined)).to.equal(false);
      expect(isValidChecksumAddress(123)).to.equal(false);
      expect(isValidChecksumAddress('')).to.equal(false);
      expect(isValidChecksumAddress('Q')).to.equal(false);
      expect(isValidChecksumAddress('Qzz')).to.equal(false);
      expect(isValidChecksumAddress(`Q${addrHex}extra`)).to.equal(false);
      // Length-correct but non-hex char.
      expect(isValidChecksumAddress(`Q${'g'.repeat(128)}`)).to.equal(false);
    });

    it('isValidChecksumAddress accepts digit-only hex (no checksum information)', () => {
      const digitsOnly = `Q${'0123456789'.repeat(12)}${'01234567'}`;
      expect(digitsOnly.length).to.equal(129);
      expect(/^Q[0-9]+$/.test(digitsOnly)).to.equal(true);
      expect(isValidChecksumAddress(digitsOnly)).to.equal(true);
    });

    it('isValidChecksumAddress treats the all-zero address as checksummed', () => {
      // No hex letters means no case to mix; uppercase Q + lowercase form
      // is its own canonical checksummed form.
      const zeros = `Q${'0'.repeat(128)}`;
      expect(isValidChecksumAddress(zeros)).to.equal(true);
      expect(toChecksumAddress(new Uint8Array(ADDRESS_SIZE))).to.equal(zeros);
    });

    it('checksum string fully round-trips: bytes → checksummed → bytes', () => {
      for (const fixture of walletTestCases) {
        const bytes = hexToBytes(fixture.wantAddress.slice(1));
        const checksummed = toChecksumAddress(bytes);
        expect(checksummed.startsWith('Q')).to.equal(true);
        expect(checksummed.length).to.equal(129);
        expect(bytesToHex(stringToAddress(checksummed))).to.equal(bytesToHex(bytes));
        expect(isValidChecksumAddress(checksummed)).to.equal(true);
      }
    });
  });
});
