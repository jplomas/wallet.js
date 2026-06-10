/**
 * Minimal mnemonic adapters.
 * @module wallet/misc/mnemonic
 */

import { WordList } from '../../qrl/wordlist.js';

const WORD_LOOKUP = WordList.reduce((acc, word, i) => {
  acc[word] = i;
  return acc;
}, Object.create(null));

/**
 * Encode bytes to a spaced hex mnemonic string.
 * @param {Uint8Array} input
 * @returns {string}
 */
function binToMnemonic(input) {
  if (!(input instanceof Uint8Array)) {
    // Without this check a string (or array) input whose length happens to
    // be a multiple of 3 would silently encode to a garbage mnemonic —
    // character indexing coerces to NaN, which maps every word to index 0.
    throw new Error('input must be a Uint8Array');
  }
  if (input.length % 3 !== 0) {
    throw new Error('byte count needs to be a multiple of 3');
  }

  const words = [];
  for (let nibble = 0; nibble < input.length * 2; nibble += 3) {
    const p = nibble >> 1;
    const b1 = input[p];
    /* c8 ignore next -- fallback unreachable for valid (multiple of 3) input */
    const b2 = p + 1 < input.length ? input[p + 1] : 0;
    const idx = nibble % 2 === 0 ? (b1 << 4) + (b2 >> 4) : ((b1 & 0x0f) << 8) + b2;

    words.push(WordList[idx]);
  }

  return words.join(' ');
}

/**
 * Decode spaced hex mnemonic to bytes.
 * @param {string} mnemonic
 * @returns {Uint8Array}
 *
 * Note: Mnemonic words are normalized to lowercase for user convenience.
 * This is by design to reduce errors from capitalization differences.
 */
function mnemonicToBin(mnemonic) {
  // Normalize to lowercase for user-friendly input (case-insensitive matching)
  const mnemonicWords = mnemonic.trim().toLowerCase().split(/\s+/);
  if (mnemonicWords.length % 2 !== 0) throw new Error('word count must be even');

  const result = new Uint8Array((mnemonicWords.length * 15) / 10);
  let current = 0;
  let buffering = 0;
  let resultIndex = 0;

  for (let i = 0; i < mnemonicWords.length; i += 1) {
    const w = mnemonicWords[i];
    const value = WORD_LOOKUP[w];
    if (value === undefined) throw new Error('invalid word in mnemonic');

    buffering += 3;
    current = (current << 12) + value;
    for (; buffering > 2; ) {
      const shift = 4 * (buffering - 2);
      const mask = (1 << shift) - 1;
      const tmp = current >> shift;
      buffering -= 2;
      current &= mask;
      result[resultIndex++] = tmp;
    }
  }

  if (buffering > 0) {
    result[resultIndex] = current & 0xff;
  }

  return result;
}

export { mnemonicToBin, binToMnemonic };
