'use strict';

// Invisible characters: zero-width, bidi controls, word joiners, ZWNBSP, Unicode tags.
const INVISIBLE_RANGES = [[0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x2069], [0xFEFF, 0xFEFF], [0xE0000, 0xE007F]];
const BIDI_CONTROL_RANGES = [[0x202A, 0x202E], [0x2066, 0x2069]];
const ZERO_WIDTH_JOINERS = new Set([0x200B, 0x200C, 0x200D]);
const DIRECTION_MARKS = new Set([0x200E, 0x200F]);
const ZWJ = 0x200D;
const BLACK_FLAG = 0x1F3F4;
const CANCEL_TAG = 0xE007F;

const inRanges = (cp, ranges) => ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
const isInvisible = (cp) => inRanges(cp, INVISIBLE_RANGES);
const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
const isPictographic = (cp) => /\p{Extended_Pictographic}/u.test(String.fromCodePoint(cp));
// Skin tones, variation selectors and the keycap mark sit between an emoji and a ZWJ.
const isEmojiModifier = (cp) => (cp >= 0x1F3FB && cp <= 0x1F3FF) || cp === 0xFE0E || cp === 0xFE0F || cp === 0x20E3;
const isNonLatinLetter = (cp) => {
  const ch = String.fromCodePoint(cp);
  return /[\p{L}\p{M}]/u.test(ch) && !/\p{Script=Latin}/u.test(ch);
};
const RTL_SCRIPT = /[\p{Script=Hebrew}\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}]/u;

/**
 * Finds invisible characters that could hide instructions from a human reviewer
 * ("rules file backdoor", Trojan Source, ASCII smuggling), while ignoring their
 * legitimate uses: ZWJ inside emoji sequences, joiners in non-Latin scripts,
 * direction marks in right-to-left text, and tag sequences in subdivision flags.
 *
 * Returns { cleaned, suspicious, strong }: cleaned has every invisible character
 * removed; suspicious counts the unexplained ones; strong counts those with no
 * benign reading here (bidi overrides/isolates, stray tag characters).
 */
function scanHidden(text) {
  let src = String(text || '');
  if (src.codePointAt(0) === 0xFEFF) src = src.slice(1);
  const cps = Array.from(src, ch => ch.codePointAt(0));
  const hasRtl = RTL_SCRIPT.test(src);

  let cleaned = '';
  let suspicious = 0;
  let strong = 0;
  let inFlagTags = false;

  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i];
    if (!isInvisible(cp)) {
      cleaned += String.fromCodePoint(cp);
      inFlagTags = cp === BLACK_FLAG;
      continue;
    }

    if (isTag(cp)) {
      if (inFlagTags) {
        if (cp === CANCEL_TAG) inFlagTags = false;
      } else {
        suspicious++;
        strong++;
      }
      continue;
    }
    inFlagTags = false;

    if (inRanges(cp, BIDI_CONTROL_RANGES)) {
      suspicious++;
      strong++;
    } else if (DIRECTION_MARKS.has(cp)) {
      if (!hasRtl) suspicious++;
    } else if (ZERO_WIDTH_JOINERS.has(cp)) {
      if (!isBenignJoiner(cps, i)) suspicious++;
    } else {
      suspicious++;
    }
  }
  return { cleaned, suspicious, strong };
}

function isBenignJoiner(cps, i) {
  let p = i - 1;
  while (p >= 0 && isEmojiModifier(cps[p])) p--;
  const prev = p >= 0 ? cps[p] : null;
  const next = i + 1 < cps.length ? cps[i + 1] : null;
  if (cps[i] === ZWJ && prev != null && next != null && isPictographic(prev) && isPictographic(next)) return true;
  return (prev != null && isNonLatinLetter(prev)) || (next != null && isNonLatinLetter(next));
}

// For attacker-controlled excerpts placed in reports: drop invisible and control characters
// (keeping tab/newline), then truncate.
function sanitizeExcerpt(text, max = 500) {
  const { cleaned } = scanHidden(text);
  let out = '';
  for (const ch of cleaned) {
    const cp = ch.codePointAt(0);
    if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0A) || (cp >= 0x7F && cp <= 0x9F)) continue;
    out += ch;
  }
  return out.slice(0, max);
}

module.exports = { scanHidden, sanitizeExcerpt };
