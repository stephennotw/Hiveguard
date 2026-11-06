'use strict';

// Zero-width, bidi-control and Unicode tag characters: invisible to a reviewer but
// read by language models ("rules file backdoor" / ASCII smuggling).
const HIDDEN_RANGES = [[0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x2069], [0xFEFF, 0xFEFF], [0xE0000, 0xE007F]];

function isHiddenCodePoint(cp) {
  return HIDDEN_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

// Returns { cleaned, hidden } where hidden counts removed characters. A leading BOM is not counted.
function stripHidden(text) {
  const src = String(text || '').replace(/^\uFEFF/, '');
  let cleaned = '';
  let hidden = 0;
  for (const ch of src) {
    if (isHiddenCodePoint(ch.codePointAt(0))) hidden++;
    else cleaned += ch;
  }
  return { cleaned, hidden };
}

// For attacker-controlled excerpts placed in reports: drop invisible and control characters
// (keeping tab/newline), then truncate.
function sanitizeExcerpt(text, max = 500) {
  const { cleaned } = stripHidden(text);
  let out = '';
  for (const ch of cleaned) {
    const cp = ch.codePointAt(0);
    if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0A) || (cp >= 0x7F && cp <= 0x9F)) continue;
    out += ch;
  }
  return out.slice(0, max);
}

module.exports = { stripHidden, sanitizeExcerpt, isHiddenCodePoint };
