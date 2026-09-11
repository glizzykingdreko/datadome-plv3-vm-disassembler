'use strict';

// handlers.js, walk the MAKE_FUNC chain and read every opcode body.
//
// This is the part that makes the whole VM tractable. The program does not
// begin with instructions, it begins with roughly 103 back-to-back MAKE_FUNC
// records, each one carrying the *plaintext JavaScript source* of one opcode
// handler:
//
//     [ 1B MAKE_FUNC opcode ][ 1B target slot ][ 3B big-endian length ][ source ]
//
// The installer compiles that source with `new Function`, binds the primitive
// table into it as `arguments[0]` and drops the closure into slot table entry
// `slot`. From then on, a single byte in the bytecode stream picks a handler.
//
// So the opcode table is not a constant you can look up once. It ships inside
// the payload and it is different in every bundle. The upside for us: once the
// chain is walked, we are reading JavaScript, not guessing at semantics.

const PRINTABLE = /^[\x09\x0a\x0d\x20-\x7e]*$/;

// -- chain ---------------------------------------------------------------

function walkChain(buffer, codeBase, makeFuncOpcode) {
  const handlers = [];
  let pc = 0;

  for (;;) {
    const at = codeBase + pc;
    if (at + 5 > buffer.length) break;
    if (buffer[at] !== makeFuncOpcode) break;

    const slotId = buffer[at + 1];
    const length = (buffer[at + 2] << 16) | (buffer[at + 3] << 8) | buffer[at + 4];
    if (length <= 0 || at + 5 + length > buffer.length) break;

    const source = buffer.slice(at + 5, at + 5 + length).toString('binary');
    // The chain ends the moment a record stops looking like source code. That
    // byte is the first real instruction.
    if (!PRINTABLE.test(source)) break;

    handlers.push({ index: handlers.length, slotId, pc, length, source });
    pc += 5 + length;
  }

  return { handlers, entryPc: pc };
}

// -- per-handler analysis ------------------------------------------------

// Return the source between `open` (a `(`) and its match, honouring strings.
function parenBody(source, open) {
  let depth = 0;
  let quote = null;
  for (let i = open; i < source.length; i++) {
    const ch = source[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return null;
}

// Every handler opens with `const n = arguments[0]` (identifier rotates) and
// closes with `n[NEXT]()`. In between, every `n[N](...)` is a primitive call,
// and the ones that read from the bytecode stream in program order are exactly
// the instruction's operands.
function analyze(source) {
  const bind = source.match(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*arguments\s*\[\s*0\s*\]/
  );

  const info = {
    bind: bind ? bind[1] : null,
    calls: [],
    loops: [],
    memWrites: [],
    endsWithNext: false,
  };
  if (!info.bind) return info;

  // For-loop header spans. A primitive call after a header belongs to the loop
  // body, which means it runs an unknown number of times, which in turn means
  // the instruction carries a variable-length inline payload.
  const forRe = /\bfor\s*\(/g;
  let hit;
  while ((hit = forRe.exec(source)) !== null) {
    const open = source.indexOf('(', hit.index);
    const header = parenBody(source, open);
    if (header === null) continue;
    const headerEnd = open + header.length + 1;
    // The body is the statement (or block) right after the header.
    let bodyEnd = source.length;
    if (source[headerEnd + 1] === '{') {
      let depth = 0;
      for (let i = headerEnd + 1; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') { depth--; if (depth === 0) { bodyEnd = i; break; } }
      }
    } else {
      const semi = source.indexOf(';', headerEnd);
      bodyEnd = semi < 0 ? source.length : semi;
    }
    info.loops.push({ start: hit.index, headerEnd, bodyEnd, header });
  }

  const escaped = info.bind.replace(/\$/g, '\\$');
  const callRe = new RegExp('\\b' + escaped + '\\s*\\[\\s*(\\d+)\\s*\\]\\s*\\(', 'g');
  while ((hit = callRe.exec(source)) !== null) {
    const open = callRe.lastIndex - 1;
    const args = parenBody(source, open);
    const at = hit.index;
    const loop = info.loops.find((l) => at > l.headerEnd && at <= l.bodyEnd);
    info.calls.push({
      slot: Number(hit[1]),
      args: args === null ? '' : args.trim(),
      at,
      inLoop: !!loop,
      loopHeader: loop ? loop.header : null,
    });
  }

  const memWriteRe = new RegExp(
    '\\b' + escaped + '\\s*\\[\\s*(\\d+)\\s*\\]\\s*\\[([^\\]]+)\\]\\s*([+\\-*/%<>|&^]?=)', 'g'
  );
  while ((hit = memWriteRe.exec(source)) !== null) {
    info.memWrites.push({ slot: Number(hit[1]), index: hit[2].trim(), op: hit[3] });
  }

  info.endsWithNext = new RegExp(
    '\\b' + escaped + '\\s*\\[\\s*\\d+\\s*\\]\\s*\\(\\s*\\)\\s*[;)]?\\s*$'
  ).test(source.slice(-48));

  return info;
}

module.exports = { walkChain, analyze, parenBody };
