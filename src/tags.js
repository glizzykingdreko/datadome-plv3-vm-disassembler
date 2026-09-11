'use strict';

// tags.js, recover the typed-value tag map from the bundle's reader function.
//
// A lot of opcodes take an immediate that is not a fixed-width integer but a
// tagged value: one tag byte followed by 0 to 8 payload bytes. Without this
// table a disassembler cannot even advance the program counter correctly, so
// this is the first thing that has to be derived.
//
// The reader always looks like this (identifiers and tag bytes rotate):
//
//   function s(A) {
//     let g = A();
//     if (128 & g) return 127 & g;           // 7-bit small int, 1 byte total
//     let C = 0, B = 24;
//     switch (g) {
//       case 55:  return !0;                 // true
//       case 72:  return !1;                 // false
//       case 34:  return null;
//       case 64:  return;                    // undefined
//       case 114: return <f64 decoder>(A);   // 8 payload bytes
//       case 103: C |= A() << 24, B -= 8;    // i32, falls through
//       case 94:  C |= A() << 16, B -= 8;    // i24, falls through
//       case 62:  C |= A() << 8,  B -= 8;    // i16, falls through
//       case 108: return C |= A(), C << B >> B;  // i8, terminal
//     }
//   }
//
// The signed-int cases are a deliberate fall-through chain, which is what makes
// the widths derivable without knowing a single tag byte: the terminal case
// reads one payload byte, the one above it reads two, and so on up the chain.

// -- helpers -------------------------------------------------------------

// Return the source slice between `open` (index of `{`) and its matching brace.
function braceBody(source, open) {
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const ch = source[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return null;
}

// -- derivation ----------------------------------------------------------

function deriveTagMap(source, constMap = {}) {
  // The reader is the only function whose body carries a switch with a
  // `return !0` arm. Anchor on that, then walk back to the enclosing brace.
  const anchor = source.search(/case\s+[A-Za-z0-9_$]+\s*:\s*\n?\s*return\s*!0\s*;/);
  if (anchor < 0) throw new Error('tags: no boolean case, cannot locate the reader');

  const switchAt = source.lastIndexOf('switch', anchor);
  if (switchAt < 0) throw new Error('tags: no switch above the boolean case');
  const bodyAt = source.indexOf('{', switchAt);
  const body = braceBody(source, bodyAt);
  if (!body) throw new Error('tags: unbalanced switch body');

  // Small-int fast path, `if (128 & g) return 127 & g`.
  const head = source.slice(Math.max(0, switchAt - 400), switchAt);
  const maskHit = head.match(/if\s*\(\s*([A-Za-z0-9_$]+)\s*&\s*([A-Za-z0-9_$]+)\s*\)\s*return/);
  // One operand is the mask, the other is the tag byte just read. Only the mask
  // can be a byte value, so anything outside 2..255 is the wrong operand (the
  // tag variable often shares a name with a const-block offset in the thousands).
  let smallIntMask = 128;
  if (maskHit) {
    for (const token of [maskHit[1], maskHit[2]]) {
      const value = /^\d+$/.test(token) ? Number(token) : constMap[token];
      if (value !== undefined && value > 1 && value < 256) smallIntMask = value;
    }
  }

  // Split the switch body into `case X:` arms, in source order.
  const arms = [];
  const caseRe = /case\s+([A-Za-z0-9_$]+)\s*:/g;
  let hit;
  const marks = [];
  while ((hit = caseRe.exec(body)) !== null) {
    marks.push({ token: hit[1], start: hit.index, end: caseRe.lastIndex });
  }
  for (let i = 0; i < marks.length; i++) {
    const next = i + 1 < marks.length ? marks[i + 1].start : body.length;
    arms.push({ token: marks[i].token, text: body.slice(marks[i].end, next) });
  }

  const widths = {};
  const kinds = {};
  const chain = [];

  for (const arm of arms) {
    const tag = /^\d+$/.test(arm.token) ? Number(arm.token) : constMap[arm.token];
    if (tag === undefined) continue;
    const text = arm.text;

    if (/return\s*!0/.test(text)) { widths[tag] = 1; kinds[tag] = 'true'; continue; }
    if (/return\s*!1/.test(text)) { widths[tag] = 1; kinds[tag] = 'false'; continue; }
    if (/return\s+null/.test(text)) { widths[tag] = 1; kinds[tag] = 'null'; continue; }
    if (/return\s*;/.test(text)) { widths[tag] = 1; kinds[tag] = 'undefined'; continue; }

    // The float arm builds an 8-element array from the byte reader.
    const floatHit = text.match(/length\s*:\s*(\d+)/);
    if (floatHit) {
      widths[tag] = 1 + Number(floatHit[1]);
      kinds[tag] = 'f64';
      continue;
    }

    // Anything still reading bytes is part of the signed-int fall-through.
    if (/\|=/.test(text)) chain.push(tag);
  }

  // Terminal chain case reads 1 payload byte, the one above reads 2, and so on.
  for (let i = 0; i < chain.length; i++) {
    const payload = chain.length - i;
    widths[chain[i]] = 1 + payload;
    kinds[chain[i]] = 'i' + payload * 8;
  }

  return {
    smallIntMask,
    widths,
    kinds,
    // Total byte width of the tagged value starting at `tag`, null when the
    // byte is not a tag we know (which is how the walker detects a desync).
    widthOf(tag) {
      if (tag & this.smallIntMask) return 1;
      return this.widths[tag] === undefined ? null : this.widths[tag];
    },
    kindOf(tag) {
      if (tag & this.smallIntMask) return 'smallint';
      return this.kinds[tag] || null;
    },
  };
}

module.exports = { deriveTagMap, braceBody };
