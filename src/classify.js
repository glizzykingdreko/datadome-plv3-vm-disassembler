'use strict';

// classify.js, turn 103 handler bodies into an opcode table.
//
// Two things are needed per opcode before a listing can exist:
//
//   1. the operand signature, so the walker knows how many bytes to skip
//   2. a mnemonic, so the listing says `JMP 4262` instead of `slot159 u24=4262`
//
// Both come out of the handler source. Operand widths are exact: a handler
// consumes bytecode only by calling a reader primitive, so the ordered list of
// reader calls *is* the operand list. Mnemonics are best-effort pattern
// matching on the body shape, and anything that does not match keeps a
// slot-derived name plus its source, which is still perfectly usable.

const { ROLE } = require('./primitives');
const { analyze } = require('./handlers');

// -- operand signature ---------------------------------------------------

// A reader called inside a for-loop body does not read once, it reads until
// the loop bound is hit. The bound is invariably an operand read moments
// earlier, which is how opcodes carry inline blobs (a 4 KB byte array, a list
// of 129 constants). Getting this wrong desyncs the walker on the very first
// data-carrying instruction, so it is worth the extra bookkeeping.
function signatureOf(handlerInfo, primitives) {
  const operands = [];
  for (const call of handlerInfo.calls) {
    const slot = primitives.slots[call.slot];
    if (!slot) continue;

    const kind = slot.role;
    if (kind !== ROLE.READ_U8 && kind !== ROLE.READ_U16 &&
        kind !== ROLE.READ_U24 && kind !== ROLE.READ_TV) continue;

    operands.push({
      role: kind,
      width: kind === ROLE.READ_TV ? null : { readU8: 1, readU16: 2, readU24: 3 }[kind],
      repeats: call.inLoop,
    });
  }
  return operands;
}

// -- mnemonics -----------------------------------------------------------

const BINARY_OPS = {
  '^=': 'XOR', '|=': 'OR', '&=': 'AND', '+=': 'ADD', '-=': 'SUB',
  '*=': 'MUL', '/=': 'DIV', '%=': 'MOD', '<<=': 'SHL', '>>=': 'SHR', '>>>=': 'USHR',
};

const COMPARE_OPS = [
  ['===', 'SEQ'], ['!==', 'SNE'], ['==', 'EQ'], ['!=', 'NE'],
  ['>=', 'GE'], ['<=', 'LE'], ['>', 'GT'], ['<', 'LT'],
  ['instanceof', 'INSTANCEOF'], ['in', 'IN'],
];

function mnemonicOf(handler, info, primitives) {
  const src = handler.source.replace(/\s+/g, ' ');
  const bind = info.bind;
  if (!bind) return 'OP_' + handler.slotId;

  const mem = primitives.slotOf(ROLE.MEM);
  const pcAddr = addressSlotFor(primitives, 'pc');
  const roleOfCall = (slotId) => {
    const slot = primitives.slots[slotId];
    return slot ? slot.role : null;
  };
  const uses = new Set(info.calls.map((c) => roleOfCall(c.slot)).filter(Boolean));
  const b = bind.replace(/\$/g, '\\$');

  // The exit instruction. Exactly one handler per bundle touches the output
  // object primitive, and what it does there is the whole point of the VM:
  // copy the accumulator into `out.r` and raise the halt flag. It is also the
  // only handler that never dispatches to NEXT, because there is no next.
  const outSlot = primitives.slotOf(ROLE.OUT);
  if (outSlot !== null && new RegExp(`\\b${b}\\s*\\[\\s*${outSlot}\\s*\\]\\s*\\.`).test(src)) {
    return 'HALT';
  }

  // Control flow first: anything that adds to the PC slot is a branch.
  if (pcAddr !== null && new RegExp(`\\[\\s*${b}\\s*\\[\\s*${pcAddr}\\s*\\]\\s*\\]\\s*\\+=`).test(src)) {
    if (/\|\|\s*\(/.test(src)) return 'JMP_IF_FALSE';
    if (/&&\s*\(/.test(src)) return 'JMP_IF_TRUE';
    return 'JMP';
  }

  // A handler that builds an inner function and pushes it is the VM's closure
  // constructor: it reads an arity, a capture count, then that many capture
  // slots. It looks like a byte-blob pusher from the operand side, so it has to
  // be checked first.
  if (/=\s*function\s*\(/.test(src) && /new\s+Function/.test(src) === false &&
      info.calls.some((c) => c.inLoop)) {
    return 'MAKE_CLOSURE';
  }

  // Inline payload pushers.
  if (info.calls.some((c) => c.inLoop && roleOfCall(c.slot) === ROLE.READ_U8)) {
    return /new\s+Uint8Array/.test(src) ? 'PUSH_BYTES' : 'PUSH_SLOTS';
  }
  if (info.calls.some((c) => c.inLoop && roleOfCall(c.slot) === ROLE.READ_TV)) return 'PUSH_CONSTS';

  // Primitive-driven names.
  if (uses.has(ROLE.STRING)) return 'PUSH_STR';

  // Most handlers do their real work inline rather than through a primitive:
  // they read the flat buffer directly and operate on plain locals. Blanking
  // out every `bind[N]` reference leaves just that guest-level expression, which
  // is far easier to pattern match than the raw body.
  //   n[32][n[32][n[36]]++] = s   ->  @[@[@]++] = s
  //   t[s] = c                    ->  t[s] = c
  const guest = src.replace(new RegExp(`${b}\\s*\\[\\s*\\d+\\s*\\]`, 'g'), '@');
  const pushesToStack = /@\[\s*@\[\s*@\s*\]\s*\+\+\s*\]\s*=/.test(guest);

  // A local being invoked is a guest-level call: `t(s)` after popping `t`.
  if (/(?:^|[,;=(])\s*[a-z_$][\w$]*\s*\(\s*[a-z_$]?[\w$]*\s*\)\s*[,;]/.test(guest)) return 'CALL';
  if (/\.apply\s*\(/.test(src)) return 'CALL_APPLY';
  if (/\bnew\s+[A-Za-z_$]/.test(src) && !/new\s+Uint8Array/.test(src)) return 'NEW';

  // Property access on a guest object, either through the primitive or inline.
  if (uses.has(ROLE.PROP_SET) || /[a-z_$][\w$]*\s*\[[^\]]+\]\s*=\s*[a-z_$][\w$]*\s*[,;]/.test(guest)) {
    return 'SET_PROP';
  }
  if (uses.has(ROLE.PROP_GET) || /=\s*[a-z_$][\w$]*\s*\[[a-z_$@][^\]]*\]/.test(guest)) {
    return signatureOf(info, primitives).length ? 'GET_PROP_IMM' : 'GET_PROP';
  }

  if (uses.has(ROLE.STORE_REG) && uses.has(ROLE.PUSH_REG)) return 'STORE_PUSH';
  if (uses.has(ROLE.STORE_REG)) return 'STORE_REG';
  if (uses.has(ROLE.PUSH_REG)) return 'PUSH_REG';

  // Object and array shapes.
  if (/for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s/.test(handler.source)) return 'KEYS';
  if (/\.reverse\s*\(/.test(src)) return 'REVERSE';
  if (/new\s+Uint8Array/.test(src)) return 'ALLOC_BYTES';
  if (/typeof\s/.test(src)) return 'TYPEOF';
  if (/=\s*\[\s*\]/.test(src) && /push/.test(src)) return 'NEW_ARRAY';
  if (/=\s*\{\s*\}/.test(src)) return 'NEW_OBJECT';

  // Stack arithmetic: `MEM[top - 1] <op>= value`.
  for (const [token, name] of Object.entries(BINARY_OPS)) {
    const escaped = token.replace(/[|^*+\-/%<>&]/g, '\\$&');
    if (new RegExp(`\\]\\s*${escaped}`).test(src)) {
      const immediate = signatureOf(info, primitives).length > 0;
      return name + (immediate ? '_IMM' : '');
    }
  }
  for (const [token, name] of COMPARE_OPS) {
    // Word operators need real boundaries, otherwise `in` matches the middle of
    // any identifier that happens to contain those two letters.
    const pattern = /^[a-z]+$/.test(token)
      ? `\\b${token}\\b`
      : `=\\s*[^=]*[^<>=!]${token.replace(/[=!<>]/g, '\\$&')}[^=]`;
    if (new RegExp(pattern).test(src)) return 'CMP_' + name;
  }

  // A bare push of an immediate or a computed value.
  if (pushesToStack) {
    const operands = signatureOf(info, primitives);
    if (operands.length === 1 && operands[0].role === ROLE.READ_TV) return 'PUSH_CONST';
    if (operands.length) return 'PUSH_IMM';
    return 'PUSH';
  }

  // Pure stack pointer arithmetic, `MEM[SP] -= n`.
  const spAddr = addressSlotFor(primitives, 'sp');
  if (spAddr !== null && new RegExp(`\\[\\s*${b}\\s*\\[\\s*${spAddr}\\s*\\]\\s*\\]\\s*-=`).test(src)) {
    return 'POP_N';
  }
  if (uses.has(ROLE.POP_ACC)) return 'POP';

  return 'OP_' + handler.slotId;
}

// The primitive table holds several raw addresses (PC, SP, ACC, halt). They all
// look like plain integers, so we tell them apart by how the initializer used
// them: the PC address is the one the NEXT primitive reads, the SP address is
// the one the push/pop primitives index. Rather than re-parse the initializer
// we take them from the recorded const values, matching against the reader and
// stack primitive bodies.
function addressSlotFor(primitives, which) {
  const candidates = Object.values(primitives.slots).filter((s) => s.role === ROLE.CONST);
  if (!candidates.length) return null;

  const probe = which === 'pc'
    ? primitives.slots[primitives.slotOf(ROLE.READ_U8)]
    : primitives.slots[primitives.slotOf(ROLE.PUSH_REG)];
  if (!probe) return null;

  // Both bodies index the flat buffer by the address we are after, e.g.
  // `A[C + A[D]++]` for the PC and `A[A[P]++]` for the SP. Pull the identifier
  // and match it back to whichever const slot carries the same name. Some
  // entries are references to a named inner function, so prefer the resolved
  // body over the raw text.
  const body = probe.body || probe.raw;
  const names = which === 'pc'
    ? body.match(/\[\s*[A-Za-z_$][\w$]*\s*\+\s*[A-Za-z_$][\w$]*\s*\[\s*([A-Za-z_$][\w$]*)\s*\]/)
    : body.match(/\[\s*[A-Za-z_$][\w$]*\s*\[\s*([A-Za-z_$][\w$]*)\s*\]/);
  if (!names) return null;

  const wanted = names[1];
  for (const slot of candidates) {
    if (slot.raw === wanted) return slot.slotId;
  }
  return null;
}

// -- table ---------------------------------------------------------------

function buildOpcodeTable(handlers, primitives) {
  const table = new Map();

  for (const handler of handlers) {
    const info = analyze(handler.source);
    const operands = signatureOf(info, primitives);
    const mnemonic = mnemonicOf(handler, info, primitives);

    table.set(handler.slotId, {
      slotId: handler.slotId,
      index: handler.index,
      mnemonic,
      operands,
      source: handler.source,
      length: handler.length,
      info,
    });
  }

  return table;
}

module.exports = { buildOpcodeTable, signatureOf, mnemonicOf, addressSlotFor };
