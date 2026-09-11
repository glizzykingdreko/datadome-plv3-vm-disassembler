'use strict';

// strings.js, port of the bundle's string decoder.
//
// There is no S-box and no lookup table of literals. Strings live as raw bytes
// inside the bytecode and get XOR'd out on demand:
//
//   header  : bytes 0..3 of the bytecode, little-endian u32, the base key
//   table   : starts at byte 4, six bytes per entry
//             [ u24 LE source offset ][ u16 LE length ][ u8 flags ]
//             flags bit 0 clear = one byte per char, set = UTF-8
//   keystrm : k[i] = (baseKey ^ ctx ^ (i + 1)) & 0xff
//   plain   : text[i] = bytecode[offset + i] ^ k[i]
//
// `ctx` is the catch. It is not stored anywhere, it is a byte the calling
// handler reads from the instruction stream, so a given table entry decodes to
// different text depending on which call site asked for it. Statically we can
// only sweep candidate ctx values and keep what comes out readable, which is
// why `sweep()` reports a printable ratio instead of pretending to be exact.

function headerKey(buffer, codeBase) {
  return (
    (buffer[codeBase] |
      (buffer[codeBase + 1] << 8) |
      (buffer[codeBase + 2] << 16) |
      ((buffer[codeBase + 3] << 24) >>> 0)) >>> 0
  );
}

function tableEntry(buffer, codeBase, id) {
  const at = codeBase + 4 + 6 * id;
  return {
    id,
    offset: buffer[at] | (buffer[at + 1] << 8) | (buffer[at + 2] << 16),
    length: buffer[at + 3] | (buffer[at + 4] << 8),
    flags: buffer[at + 5],
  };
}

function decodeString(buffer, codeBase, entry, ctx) {
  const key = headerKey(buffer, codeBase);
  const bytes = new Array(entry.length);
  for (let i = 0; i < entry.length; i++) {
    bytes[i] = buffer[codeBase + entry.offset + i] ^ ((key ^ ctx ^ (i + 1)) & 0xff);
  }
  return (entry.flags & 1) === 0
    ? bytes.map((b) => String.fromCharCode(b)).join('')
    : decodeUtf8(bytes);
}

function decodeUtf8(bytes) {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i++];
    if (b < 128) {
      out += String.fromCharCode(b);
    } else if (b > 191 && b < 224) {
      out += String.fromCharCode(((31 & b) << 6) | (63 & (bytes[i++] || 0)));
    } else if (b > 239 && b < 365) {
      const point =
        (((7 & b) << 18) |
          ((63 & (bytes[i++] || 0)) << 12) |
          ((63 & (bytes[i++] || 0)) << 6) |
          (63 & (bytes[i++] || 0))) - 65536;
      out += String.fromCharCode(0xd800 + (point >> 10), 0xdc00 + (0x3ff & point));
    } else {
      out += String.fromCharCode(
        ((15 & b) << 12) | ((63 & (bytes[i++] || 0)) << 6) | (63 & (bytes[i++] || 0))
      );
    }
  }
  return out;
}

function printableRatio(text) {
  if (!text.length) return 0;
  let good = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127) || code > 160) good++;
  }
  return good / text.length;
}

// XOR against the wrong ctx still lands in printable ASCII most of the time, so
// "is it printable" is far too weak a filter. Score for text that actually looks
// like something a fingerprinting script would carry: identifiers, CSS, URLs,
// property names. Vowel and separator distribution does most of the work.
function score(text) {
  if (text.length < 3) return 0;
  let letters = 0;
  let vowels = 0;
  let structural = 0;
  let junk = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const code = text.charCodeAt(i);
    if (/[A-Za-z]/.test(ch)) {
      letters++;
      if ('aeiouAEIOU'.indexOf(ch) >= 0) vowels++;
    } else if (/[0-9._:/\-#[\]{}()"'=; ]/.test(ch)) {
      structural++;
    } else if (code < 32 || code > 126) {
      junk++;
    }
  }

  if (junk > 0) return 0;
  const known = letters + structural;
  if (known / text.length < 0.95) return 0;
  if (letters === 0) return structural / text.length * 0.4;

  const vowelRatio = vowels / letters;
  // Real words sit around 0.2 to 0.55. Pure consonant runs are XOR noise.
  const shape = vowelRatio > 0.12 && vowelRatio < 0.75 ? 1 : 0.15;
  return (known / text.length) * shape * Math.min(1, text.length / 6);
}

// Try every ctx for every plausible table entry and keep the best hit per entry.
// `base` is the offset of the cipher image, which is NOT always the bytecode:
// see `findStringBlobs`.
function sweep(buffer, base, length, options = {}) {
  const maxEntries = options.maxEntries || 512;
  const maxLength = options.maxLength || 400;
  const minLength = options.minLength || 3;
  const minScore = options.minScore === undefined ? 0.45 : options.minScore;

  const found = [];
  for (let id = 0; id < maxEntries; id++) {
    if (4 + 6 * id + 6 > length) break;
    const entry = tableEntry(buffer, base, id);
    if (entry.length < minLength || entry.length > maxLength) continue;
    if (entry.offset + entry.length > length) continue;

    let best = null;
    for (let ctx = 0; ctx < 256; ctx++) {
      const text = decodeString(buffer, base, entry, ctx);
      const value = score(text);
      if (value >= minScore && (!best || value > best.score)) {
        best = { id, ctx, offset: entry.offset, length: entry.length, score: value, text };
      }
    }
    if (best) found.push(best);
  }
  return found;
}

// The string image is not the bytecode. Handlers hand the cipher a buffer they
// read out of a register, and that buffer arrives as an inline byte blob pushed
// by the program prologue. So: find the big PUSH_BYTES payloads and treat each
// one as a candidate cipher image (key in its first four bytes, table at +4).
function findStringBlobs(instructions, codeBase, minBytes = 512) {
  const blobs = [];
  for (const insn of instructions) {
    if (insn.mnemonic !== 'PUSH_BYTES') continue;
    const size = insn.operands.find((o) => o.kind === 'uint');
    const payload = insn.operands.find((o) => o.kind === 'bytes');
    if (!size || !payload || size.value < minBytes) continue;
    blobs.push({
      pc: insn.pc,
      dataPc: insn.next - payload.bytes,
      base: codeBase + (insn.next - payload.bytes),
      length: size.value,
    });
  }
  return blobs;
}

// The ctx byte is not a mystery after all: it is an operand. The handler that
// decodes strings reads a register index, a table id and a ctx byte from the
// instruction stream, then calls the cipher with them:
//
//   var n = a[45](), r = a[45](), s = a[14]();
//   var t = a[32][a[11] + n];
//   a[32][a[32][a[36]]++] = a[23](t, r, s);
//
// So every PUSH_STR instruction in the listing carries the exact table id and
// the exact ctx for that call site. Map the cipher call's argument names back to
// the order the operands were read in and string recovery becomes exact instead
// of a sweep. Returns {tableId, ctx} as operand indexes, or null.
function stringCallSignature(entry, cipherSlot) {
  const info = entry.info;
  if (!info || !info.bind) return null;

  const call = info.calls.find((c) => c.slot === cipherSlot);
  if (!call) return null;

  const args = call.args.split(',').map((a) => a.trim());
  if (args.length < 3) return null;

  // Names bound to reader calls, in the order the bytes are consumed.
  const bind = info.bind.replace(/\$/g, '\\$');
  const declRe = new RegExp(
    `([A-Za-z_$][\\w$]*)\\s*=\\s*${bind}\\s*\\[\\s*(\\d+)\\s*\\]\\s*\\(\\s*\\)`, 'g'
  );
  const order = [];
  let hit;
  while ((hit = declRe.exec(entry.source)) !== null) order.push(hit[1]);

  const tableId = order.indexOf(args[1]);
  const ctx = order.indexOf(args[2]);
  if (tableId < 0 || ctx < 0) return null;
  return { tableId, ctx };
}

// Walk every PUSH_STR site and decode its string exactly.
function resolveStrings(instructions, table, buffer, blobs, cipherSlot) {
  const sites = [];
  const signatures = new Map();

  for (const insn of instructions) {
    const entry = table.get(insn.opcode);
    if (!entry || entry.mnemonic !== 'PUSH_STR') continue;

    if (!signatures.has(insn.opcode)) {
      signatures.set(insn.opcode, stringCallSignature(entry, cipherSlot));
    }
    const signature = signatures.get(insn.opcode);
    if (!signature) continue;

    const uints = insn.operands.filter((o) => o.kind === 'uint');
    const id = uints[signature.tableId];
    const ctx = uints[signature.ctx];
    if (!id || !ctx) continue;

    for (const blob of blobs) {
      const entryRecord = tableEntry(buffer, blob.base, id.value);
      if (entryRecord.length === 0 || entryRecord.length > 4096) continue;
      if (entryRecord.offset + entryRecord.length > blob.length) continue;
      sites.push({
        pc: insn.pc,
        id: id.value,
        ctx: ctx.value,
        blobPc: blob.pc,
        text: decodeString(buffer, blob.base, entryRecord, ctx.value),
      });
      break;
    }
  }
  return sites;
}

module.exports = {
  headerKey,
  tableEntry,
  decodeString,
  sweep,
  findStringBlobs,
  resolveStrings,
  stringCallSignature,
  printableRatio,
  score,
};
