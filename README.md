# wallet.js

[![npm version](https://img.shields.io/npm/v/@theqrl/wallet.js.svg)](https://www.npmjs.com/package/@theqrl/wallet.js)
![test](https://github.com/theQRL/wallet.js/actions/workflows/release.yml/badge.svg)
[![codecov](https://codecov.io/gh/theQRL/wallet.js/branch/main/graph/badge.svg?token=HHVBFBVGFR)](https://codecov.io/gh/theQRL/wallet.js)

Quantum-resistant wallet library for The QRL using **ML-DSA-87** (FIPS 204).

## Features

- ML-DSA-87 digital signatures (NIST post-quantum standard)
- Deterministic key derivation from seeds
- Mnemonic phrase backup (34 words)
- Address generation and validation
- Works in Node.js and browsers
- Dual ESM/CommonJS support

## Installation

```bash
npm install @theqrl/wallet.js
```

## Quick Start

### ESM (recommended)

```javascript
import { MLDSA87, Seed, isValidAddress } from '@theqrl/wallet.js';

// Create a new random wallet
const wallet = MLDSA87.newWallet();
console.log('Address:', wallet.getAddressStr());
console.log('Mnemonic:', wallet.getMnemonic());

// Sign a message
const message = new TextEncoder().encode('Hello QRL!');
const signature = wallet.sign(message);

// Verify signature (descriptor is required so verification uses the
// same domain-separated context as signing)
const isValid = MLDSA87.verify(signature, message, wallet.getPK(), wallet.getDescriptor());
console.log('Valid:', isValid); // true

// Clean up sensitive data
wallet.zeroize();
```

### CommonJS

```javascript
const { MLDSA87, Seed, isValidAddress } = require('@theqrl/wallet.js');

const wallet = MLDSA87.newWallet();
console.log('Address:', wallet.getAddressStr());
```

## API Reference

### Creating Wallets

#### `MLDSA87.newWallet([metadata])`

Creates a new wallet with a random seed.

```javascript
const wallet = MLDSA87.newWallet();
const walletWithMeta = MLDSA87.newWallet([0x01, 0x02]); // Custom 2-byte metadata
```

#### `MLDSA87.newWalletFromSeed(seed, [metadata])`

Creates a wallet from an existing seed (deterministic).

```javascript
const seed = Seed.from('0x' + '00'.repeat(48)); // 48-byte hex string
const wallet = MLDSA87.newWalletFromSeed(seed);
```

#### `MLDSA87.newWalletFromMnemonic(mnemonic)`

Restores a wallet from a mnemonic phrase.

```javascript
const mnemonic = 'absorb aback veto waiter rail aroma...'; // 34 words
const wallet = MLDSA87.newWalletFromMnemonic(mnemonic);
```

#### `newWalletFromExtendedSeed(extendedSeed)`

Factory function that auto-detects wallet type from extended seed.

```javascript
import { newWalletFromExtendedSeed } from '@theqrl/wallet.js';

const wallet = newWalletFromExtendedSeed('0x01000000...'); // 51-byte hex
```

### Wallet Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `getAddressStr()` | `string` | Address with Q prefix (e.g., `Qabc123...`), 129 chars total, lowercase hex. Pass through `toChecksumAddress` to get the EIP-55-style mixed-case form |
| `getAddress()` | `Uint8Array` | Raw address bytes (64 bytes, see `ADDRESS_SIZE`) |
| `getMnemonic()` | `string` | 34-word mnemonic phrase |
| `getPK()` | `Uint8Array` | Public key (2,592 bytes) |
| `getSK()` | `Uint8Array` | Secret key (4,896 bytes) |
| `getHexExtendedSeed()` | `string` | Extended seed as hex with 0x prefix |
| `sign(message)` | `Uint8Array` | Sign a message (4,627-byte signature). **Hedged by default** (FIPS 204 §3.4, recommended per TOB-QRLLIB-6) — two signs of the same message produce distinct bytes that both verify under the same pk + descriptor |
| `signDeterministic(message)` | `Uint8Array` | Sign deterministically (FIPS 204 §3.5). Use only when determinism is itself a protocol requirement (RANDAO-style beacon contributions, KAT / ACVP vector reproduction). See [SECURITY.md](./SECURITY.md#signing-modes-tob-qrllib-6) |
| `zeroize()` | `void` | Overwrite sensitive data with zeros |

### Static Methods

| Method | Description |
|--------|-------------|
| `MLDSA87.verify(signature, message, pk, descriptor)` | Verify a signature, returns `boolean`. The descriptor is required so verification uses the same domain-separated context as signing |

### Signing Context

Every wallet-level signature is bound to its descriptor via an 8-byte domain-separated context:

```
"ZOND" || SIGNING_CONTEXT_VERSION || descriptor   (4 + 1 + 3 bytes)
```

ML-DSA-87 passes this as the FIPS 204 ctx parameter. Callers do not usually need to construct it — `wallet.sign(message)` and `MLDSA87.verify(sig, msg, pk, descriptor)` do it internally — but the helper is exported for advanced callers and cross-implementation parity with [go-qrllib](https://github.com/theQRL/go-qrllib):

```javascript
import { signingContext, SIGNING_CONTEXT_VERSION } from '@theqrl/wallet.js';

const ctx = signingContext(wallet.getDescriptor()); // Uint8Array(8)
```

Bumping `SIGNING_CONTEXT_VERSION` is a hard break of the signature wire format: signatures produced under a new version will not verify under the old one. A version bump must coincide with a coordinated consensus / library activation.

### Address Utilities

**Address Format:** `Q` prefix followed by exactly 128 hex characters (64-byte address, NIST Category 5). The 64-byte size matches go-qrllib's `AddressSize` and rust-qrllib's `ADDRESS_SIZE` — there is one canonical address size across all QRL implementations.

- `addressToString` emits lowercase hex; `toChecksumAddress` emits the EIP-55-style mixed-case checksummed form
- The `Q` prefix is always uppercase on output; input parsing accepts `Q` or `q`
- `addressToString`, `stringToAddress`, `toChecksumAddress`, `isValidAddress`, and `isValidChecksumAddress` enforce the exact 64-byte (128-hex-char) length and reject anything else

#### EIP-55-style checksum

`stringToAddress` and `isValidAddress` accept three encodings of the same address:

1. all-lowercase hex (legacy / case-uniform),
2. all-uppercase hex (legacy / case-uniform), and
3. mixed-case hex that satisfies the checksum.

Mixed-case strings whose case does **not** match the checksum are rejected, mirroring how Ethereum tooling treats EIP-55 addresses. This means a single mistyped character in a checksummed address is detected on parse.

The scheme follows EIP-55 with one substitution: the hash is **SHAKE-256** of the UTF-8 bytes of the 128-character lowercase hex (no `Q` prefix), with `dkLen = ADDRESS_SIZE`, giving exactly one hash nibble per hex character. For each hex character, if it is a letter (`a`-`f`) and the corresponding nibble is ≥ 8, it is uppercased; otherwise it stays lowercase. The `Q` prefix is not part of the checksum input.

`isValidChecksumAddress` is **strict**: it returns `true` only when the input exactly matches the canonical checksummed form produced by `toChecksumAddress` (uppercase `Q`, hex body case-for-case identical). All-lowercase and all-uppercase forms that contain letters return `false`. Use it for "did the caller paste a checksummed address?" — and use `isValidAddress` for the permissive parse check.

```javascript
import {
  addressToString,
  stringToAddress,
  toChecksumAddress,
  isValidAddress,
  isValidChecksumAddress,
} from '@theqrl/wallet.js';

// Convert bytes to string (lowercase)
const addrStr = addressToString(addressBytes); // 'Qabc...'

// Convert bytes (or any case-form string) to the checksummed mixed-case form
const checksummed = toChecksumAddress(addressBytes); // 'QAbC...' (mixed case)

// Parse: accepts lowercase, uppercase, or correctly-checksummed mixed case
const a = stringToAddress('Qabc...');         // ok
const b = stringToAddress('QABC...');         // ok
const c = stringToAddress(checksummed);       // ok
// stringToAddress('QAbc...')                  // throws if checksum is wrong

// Permissive check (accepts any of the three forms above)
if (isValidAddress(userInput)) { /* ... */ }

// Strict check (only true for the canonical checksummed form)
if (isValidChecksumAddress(userInput)) { /* ... */ }
```

### Seeds and Descriptors

```javascript
import {
  Seed,
  ExtendedSeed,
  Descriptor,
  newMLDSA87Descriptor,
  SEED_SIZE,           // 48
  EXTENDED_SEED_SIZE,  // 51
  DESCRIPTOR_SIZE      // 3
} from '@theqrl/wallet.js';

// Create seed from hex
const seed = Seed.from('0x' + 'ab'.repeat(48));

// Create descriptor
const descriptor = newMLDSA87Descriptor([0x00, 0x00]);

// Create extended seed
const extSeed = ExtendedSeed.newExtendedSeed(descriptor, seed);
```

## Security

See [SECURITY.md](SECURITY.md) for the security model and best practices.

**Important:**
- Always call `wallet.zeroize()` when done
- Never log or transmit mnemonics/seeds
- Mnemonics do not include a built-in checksum — application-layer verification is recommended (see [SECURITY.md](SECURITY.md) for details)
- Validate addresses with `isValidAddress()` before use (accepts uniform-case and checksummed forms), or with `isValidChecksumAddress()` to require an EIP-55-style checksummed address

## Browser Usage

The library works in browsers via bundlers (webpack, vite, etc.):

```javascript
import { MLDSA87 } from '@theqrl/wallet.js';

const wallet = MLDSA87.newWallet();
```

Uses Web Crypto API for secure random number generation (see _Requirements_).

## Wallet Type

This library currently supports **ML-DSA-87** (FIPS 204), the NIST standardized version of Dilithium.

| Property | Value |
|----------|-------|
| Security Level | NIST Level 5 |
| Public Key | 2,592 bytes |
| Secret Key | 4,896 bytes |
| Signature | 4,627 bytes |

## Dependencies

- `@theqrl/mldsa87` - ML-DSA-87 implementation
- `@noble/hashes` - SHA-256, SHAKE-256

## Requirements

- **Node.js**: 20.19+, 22.x, or 24.x (requires `globalThis.crypto.getRandomValues`)
- **Browsers**: Any modern browser with [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) support (`crypto.getRandomValues()`) and ES2020 (BigInt). This includes Chrome 67+, Firefox 68+, Safari 14+, and Edge 79+.
- **Not supported**: Internet Explorer, Node.js < 20, or environments without Web Crypto API

## License

[MIT](LICENSE)
