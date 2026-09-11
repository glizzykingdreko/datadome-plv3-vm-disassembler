'use strict';

// loader.js, turn a vm-obf.js bundle into the flat buffer the VM actually runs on.
//
// Nothing here is hardcoded. DataDome rotates identifier names, register
// offsets, the LCG seed, the tag bytes and the bytecode length on every push,
// so anchoring on names would break the next morning. What never changes is
// the *shape* of the file:
//
//   1. a top-level declaration block of numeric offsets
//   2. an LCG closure using the xorshift trio (<<13, >>17, <<5)
//   3. a typed-value reader with a tag switch
//   4. a string-cipher decoder
//   5. an initializer that fills the primitive table and installs MAKE_FUNC
//   6. an entry IIFE that atob's a base64 blob into an Array.from buffer
//
// We anchor on (6) because it is unmistakable: it is the only place in the
// file where `charCodeAt` shows up, and the arrow body spells out the code
// window as `i >= CODE && i < CODE + LEN`. From that single expression we get
// the buffer size, the code base and the code length in one shot.

const fs = require('fs');

// -- tiny arithmetic evaluator -------------------------------------------

// Substitute known identifiers, then evaluate what is left. Returns null when
// anything is unresolved or the residue is not pure arithmetic, so we never
// end up eval'ing arbitrary bundle source.
function evalArith(expr, map) {
  let resolved = true;
  const substituted = expr.replace(/[A-Za-z_$][\w$]*/g, (id) => {
    if (Object.prototype.hasOwnProperty.call(map, id)) return '(' + map[id] + ')';
    resolved = false;
    return id;
  });
  if (!resolved) return null;
  if (!/^[\d+\-*/()%<>&|^ .]*$/.test(substituted)) return null;
  try {
    const value = Function('"use strict";return (' + substituted + ');')();
    return typeof value === 'number' && isFinite(value) ? value : null;
  } catch {
    return null;
  }
}

// -- const block ---------------------------------------------------------

// Every numeric constant the VM needs lives in top-level `var a = 1, b = a + 2;`
// statements. The interstitial ships a single block; the captcha ships three
// (offsets, tag bytes, primitive slot IDs) so we merge all of them, which is
// what the JS engine does anyway since they share one scope.
//
// Declarations can reference earlier ones (`Q = B + 348`), so we run several
// passes until the map stops growing.
function buildConstMap(source) {
  const spans = [];
  const spanRe = /^(?:var|const|let)\s+[\s\S]*?;/gm;
  let span;
  while ((span = spanRe.exec(source)) !== null) {
    spans.push(span[0]);
    if (spans.length > 12) break;
  }

  const map = {};
  // Lookbehind rather than \b: `$` is not a word character, so `\b$foo` never
  // matches and every `$`-named constant silently vanishes. The captcha uses
  // `$` and `AA` as identifiers, and losing `$ = 18` costs you a primitive slot.
  const assignRe = /(?<![\w$])([A-Za-z_$][\w$]*)\s*=\s*([^,;\n]+)/g;
  for (let pass = 0; pass < 6; pass++) {
    for (const text of spans) {
      let hit;
      assignRe.lastIndex = 0;
      while ((hit = assignRe.exec(text)) !== null) {
        if (map[hit[1]] !== undefined) continue;
        const value = evalArith(hit[2].trim(), map);
        if (value !== null) map[hit[1]] = value;
      }
    }
  }
  return map;
}

// Resolve a token to a number: literal first, then the const block, then the
// nearest preceding local declaration (the captcha computes its buffer size
// into a function-local `var g = w + J`).
function resolveToken(token, map, source, before) {
  if (/^\d+$/.test(token)) return Number(token);
  if (map[token] !== undefined) return map[token];

  const escaped = token.replace(/\$/g, '\\$');
  const declRe = new RegExp('(?:var|let|const)\\s+' + escaped + '\\s*=\\s*([^,;\\n]+)', 'g');
  let hit;
  let nearest = null;
  while ((hit = declRe.exec(source)) !== null) {
    if (before !== undefined && hit.index > before) break;
    nearest = hit[1];
  }
  return nearest === null ? null : evalArith(nearest.trim(), map);
}

// -- header --------------------------------------------------------------

function parseHeader(source) {
  const constMap = buildConstMap(source);

  const anchor = source.indexOf('charCodeAt');
  if (anchor < 0) {
    throw new Error('loader: no charCodeAt anchor, this is not a plv3 VM bundle');
  }

  // The window guard sits right next to the anchor:
  //   (Q, D) => D >= C && D < C + B ? A.charCodeAt(D - C) : g()
  const windowStart = Math.max(0, anchor - 800);
  const region = source.slice(windowStart, anchor + 200);
  const guard = region.match(
    /([A-Za-z_$][\w$]*)\s*>=\s*([A-Za-z_$][\w$]*)\s*&&\s*\1\s*<\s*\2\s*\+\s*([A-Za-z_$][\w$]*)/
  );
  if (!guard) throw new Error('loader: could not locate the code-window guard');

  const codeBase = resolveToken(guard[2], constMap, source, anchor);
  const codeLen = resolveToken(guard[3], constMap, source, anchor);

  // `Array.from({ length: N }, ...)` in the same region gives the flat-buffer
  // size. Take the last match so the 8-byte float scratch never wins.
  const lengths = [...region.matchAll(/length\s*:\s*([A-Za-z0-9_$]+)/g)];
  if (!lengths.length) throw new Error('loader: no Array.from length near the anchor');
  const lastLength = lengths[lengths.length - 1];
  const bufSize = resolveToken(
    lastLength[1], constMap, source, windowStart + lastLength.index
  );

  // The LCG seed is the last big number assigned just above the xorshift trio.
  // Literal in the interstitial, a const-block name in the captcha.
  const xorshift = source.search(/<<\s*13[\s\S]{0,60}?>>\s*17[\s\S]{0,60}?<<\s*5/);
  if (xorshift < 0) throw new Error('loader: no xorshift closure');
  const preamble = source.slice(Math.max(0, xorshift - 500), xorshift);
  const seedCandidates = [
    ...preamble.matchAll(/(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z0-9_$]+)/g),
  ];
  let seed = null;
  for (let i = seedCandidates.length - 1; i >= 0; i--) {
    const value = resolveToken(seedCandidates[i][2], constMap, source, xorshift);
    if (value !== null && Math.abs(value) > 1000) {
      seed = value;
      break;
    }
  }

  const payload = (source.match(/"([A-Za-z0-9+/=]{500,})"/) || [])[1];

  if (!bufSize || codeBase === null || codeLen === null || seed === null || !payload) {
    throw new Error(
      'loader: incomplete header ' +
        JSON.stringify({ bufSize, codeBase, codeLen, seed, payload: !!payload })
    );
  }

  return { bufSize, codeBase, codeLen, seed, payload, constMap };
}

// -- LCG -----------------------------------------------------------------

// Faithful port of the bundle's byte generator. State is re-mixed every fourth
// call and the return value rotates through the four bytes of the 32-bit state,
// which is why the counter is bumped before the shift.
function makeLcg(seed) {
  let state = seed | 0;
  let counter = 0;
  return function next() {
    if (!(3 & counter++)) {
      state ^= state << 13;
      state ^= state >> 17;
      state ^= state << 5;
    }
    return (state >> ((3 & counter) << 3)) & 0xff;
  };
}

// -- flat buffer ---------------------------------------------------------

// The VM does not run on the base64 blob, it runs on a ~200 KB buffer where
// the decoded bytecode occupies [codeBase, codeBase + codeLen) and every other
// byte is LCG filler. That filler is not padding: the registers live in the
// bytes below codeBase and guest handlers happily read entropy from the bytes
// above it, so we have to reproduce it exactly.
function assembleBuffer(header) {
  const decoded = Buffer.from(header.payload, 'base64');
  const buffer = Buffer.alloc(header.bufSize);
  const nextByte = makeLcg(header.seed);

  for (let i = 0; i < header.bufSize; i++) {
    if (i >= header.codeBase && i < header.codeBase + header.codeLen) {
      const offset = i - header.codeBase;
      buffer[i] = offset < decoded.length ? decoded[offset] : 0;
    } else {
      buffer[i] = nextByte();
    }
  }

  return { buffer, decodedLen: decoded.length };
}

function load(source) {
  const header = parseHeader(source);
  const { buffer, decodedLen } = assembleBuffer(header);
  return { header, buffer, decodedLen };
}

function loadFile(path) {
  return load(fs.readFileSync(path, 'utf8'));
}

module.exports = {
  evalArith,
  buildConstMap,
  resolveToken,
  parseHeader,
  makeLcg,
  assembleBuffer,
  load,
  loadFile,
};
