'use strict';

// disasm.js, walk the bytecode and emit a listing.
//
// The VM is a thread-of-code interpreter: there is no `switch`, the dispatch
// loop just keeps calling whatever closure the last handler installed. Handlers
// jump by adding to the PC slot at runtime, so a plain linear sweep eventually
// lands mid-operand and decodes garbage.
//
// The walk is therefore a worklist: start at the program entry, decode until
// the basic block ends, and queue branch targets as they are discovered. Every
// address is decoded at most once. Anything the worklist never reaches is
// reported as a gap rather than silently sweeped over, because a wrong
// instruction is worse than a missing one.

const { ROLE } = require('./primitives');

// -- single instruction --------------------------------------------------

function decodeAt(pc, ctx) {
  const { buffer, codeBase, codeLen, table, tags } = ctx;
  if (pc < 0 || pc >= codeLen) return null;

  const opcode = buffer[codeBase + pc];
  const entry = table.get(opcode);
  if (!entry) return { pc, opcode, bad: 'no handler installed for this opcode' };

  let cursor = pc + 1;
  const operands = [];
  let lastNumeric = null;

  for (const operand of entry.operands) {
    if (operand.repeats) {
      // Inline payload: the count came from the operand just read.
      const count = lastNumeric === null ? 0 : lastNumeric;
      if (operand.role === ROLE.READ_TV) {
        const start = cursor;
        for (let i = 0; i < count; i++) {
          const width = tags.widthOf(buffer[codeBase + cursor]);
          if (width === null) {
            return { pc, opcode, bad: `unknown value tag 0x${buffer[codeBase + cursor].toString(16)}` };
          }
          cursor += width;
        }
        operands.push({ kind: 'consts', count, bytes: cursor - start });
      } else {
        const bytes = count * (operand.width || 1);
        operands.push({ kind: 'bytes', count, bytes });
        cursor += bytes;
      }
      continue;
    }

    if (operand.role === ROLE.READ_TV) {
      const tag = buffer[codeBase + cursor];
      const width = tags.widthOf(tag);
      if (width === null) {
        return { pc, opcode, bad: `unknown value tag 0x${tag.toString(16)}` };
      }
      operands.push({
        kind: 'value',
        tag,
        type: tags.kindOf(tag),
        value: readTagged(buffer, codeBase + cursor, tag, tags),
        bytes: width,
      });
      cursor += width;
      continue;
    }

    let value = 0;
    for (let i = 0; i < operand.width; i++) value = (value << 8) | buffer[codeBase + cursor + i];
    operands.push({ kind: 'uint', width: operand.width, value });
    lastNumeric = value;
    cursor += operand.width;
  }

  if (cursor > codeLen) return { pc, opcode, bad: 'operands run past the end of the bytecode' };

  return { pc, opcode, mnemonic: entry.mnemonic, operands, next: cursor, size: cursor - pc };
}

// Decode a tagged immediate well enough to print it. Small ints and the signed
// widths are worth resolving; the float path is reported by type only.
function readTagged(buffer, at, tag, tags) {
  if (tag & tags.smallIntMask) return tag & (tags.smallIntMask - 1);
  const kind = tags.kindOf(tag);
  if (kind === 'true') return true;
  if (kind === 'false') return false;
  if (kind === 'null') return null;
  if (kind === 'undefined') return undefined;
  if (kind && kind.startsWith('i')) {
    const bits = Number(kind.slice(1));
    const bytes = bits / 8;
    let value = 0;
    for (let i = 0; i < bytes; i++) value = (value << 8) | buffer[at + 1 + i];
    const shift = 32 - bits;
    return (value << shift) >> shift;
  }
  return null;
}

// -- program walk --------------------------------------------------------

function isBranch(mnemonic) {
  return mnemonic === 'JMP' || mnemonic === 'JMP_IF_FALSE' || mnemonic === 'JMP_IF_TRUE';
}

function disassemble(ctx, options = {}) {
  const limit = options.limit || 2_000_000;
  const entryPc = ctx.entryPc;

  const seen = new Map();
  const queue = [entryPc];
  const problems = [];
  let steps = 0;

  while (queue.length && steps < limit) {
    let pc = queue.shift();

    while (pc !== undefined && pc < ctx.codeLen && !seen.has(pc) && steps++ < limit) {
      const insn = decodeAt(pc, ctx);
      if (!insn) break;
      seen.set(pc, insn);

      if (insn.bad) {
        problems.push({ pc, opcode: insn.opcode, reason: insn.bad });
        break;
      }

      // Relative jump: the operand is added to the PC *after* the operand was
      // consumed, so the target is measured from the end of the instruction.
      if (isBranch(insn.mnemonic)) {
        const displacement = insn.operands.find((o) => o.kind === 'uint');
        if (displacement) {
          const target = insn.next + displacement.value;
          insn.target = target;
          if (target >= 0 && target < ctx.codeLen && !seen.has(target)) queue.push(target);
        }
        if (insn.mnemonic === 'JMP') break;   // unconditional, block ends here
      }

      pc = insn.next;
    }
  }

  const instructions = [...seen.values()]
    .filter((i) => !i.bad)
    .sort((a, b) => a.pc - b.pc);

  return {
    entryPc,
    instructions,
    problems,
    coverage: coverageOf(instructions, entryPc, ctx.codeLen),
  };
}

function coverageOf(instructions, entryPc, codeLen) {
  let decoded = 0;
  for (const insn of instructions) decoded += insn.size;
  const span = codeLen - entryPc;
  return {
    decodedBytes: decoded,
    programBytes: span,
    ratio: span > 0 ? decoded / span : 0,
  };
}

// -- rendering -----------------------------------------------------------

function formatOperand(operand) {
  switch (operand.kind) {
    case 'uint':
      return `${operand.value}`;
    case 'value':
      if (operand.type === 'f64') return 'f64';
      if (operand.value === undefined) return 'undefined';
      return JSON.stringify(operand.value);
    case 'bytes':
      return `<${operand.count} bytes>`;
    case 'consts':
      return `<${operand.count} consts>`;
    default:
      return '?';
  }
}

function render(result, table, options = {}) {
  const lines = [];
  const showSource = !!options.source;
  // pc -> decoded string, so `PUSH_STR 0, 196, 251` reads as `; "document"`.
  const annotations = options.strings || new Map();

  lines.push(`; entry  pc=${result.entryPc}`);
  lines.push(`; decoded ${result.instructions.length} instructions, ` +
             `${result.coverage.decodedBytes}/${result.coverage.programBytes} bytes ` +
             `(${(result.coverage.ratio * 100).toFixed(1)}%)`);
  lines.push(';');

  let previousEnd = result.entryPc;
  for (const insn of result.instructions) {
    if (insn.pc > previousEnd) {
      lines.push(`; ---- ${insn.pc - previousEnd} bytes not reached ----`);
    }
    const operands = insn.operands.map(formatOperand).join(', ');
    let comment = '';
    if (insn.target !== undefined) comment = `   ; -> ${insn.target}`;
    else if (annotations.has(insn.pc)) comment = `   ; ${JSON.stringify(annotations.get(insn.pc))}`;
    lines.push(
      `${String(insn.pc).padStart(8)}  ${String(insn.opcode).padStart(3)}  ` +
      `${insn.mnemonic.padEnd(14)} ${operands}${comment}`
    );
    if (showSource) {
      const entry = table.get(insn.opcode);
      if (entry) lines.push(`          | ${entry.source}`);
    }
    previousEnd = insn.next;
  }

  if (result.problems.length) {
    lines.push(';');
    lines.push(`; ${result.problems.length} decode problem(s):`);
    for (const problem of result.problems.slice(0, 40)) {
      lines.push(`;   pc=${problem.pc} opcode=${problem.opcode}: ${problem.reason}`);
    }
  }

  return lines.join('\n');
}

module.exports = { disassemble, decodeAt, render };
