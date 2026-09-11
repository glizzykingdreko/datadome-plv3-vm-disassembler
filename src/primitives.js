'use strict';

// primitives.js, recover the primitive table and the MAKE_FUNC slot.
//
// The bundle declares roughly 22 primitives in its initializer and hands the
// whole table to every compiled handler as `arguments[0]`. That table is the
// only vocabulary a handler has: it cannot touch the DOM, it cannot call a
// global, it can only index into this array. Recovering it is what turns an
// opaque handler body into something readable.
//
//   var w = [];
//   w[31] = A;                       // the flat buffer
//   w[22] = function () { return A[Q + A[M]++]; };        // read u8 at PC
//   w[49] = function () { ... return A[M] = g + 2, C << 8 | c; };  // read u16
//   w[35] = C;                       // read u24 (named inner function)
//   w[38] = function () { return u(...); };               // read typed value
//   w[12] = D;                       // NEXT, dispatch the following opcode
//   ...
//   A[B + 182] = function () { ... new Function(J) ... };  // MAKE_FUNC
//
// Slot IDs rotate per bundle and the captcha spells them as named constants
// (`w[l]` with `l = 31` up top) while the interstitial inlines the numbers, so
// every index goes through the const map before it is trusted.

const { braceBody } = require('./tags');

// -- role classification -------------------------------------------------

const ROLE = {
  MEM: 'mem',                 // the flat buffer itself
  OUT: 'out',                 // caller-supplied output object
  CONST: 'const',             // a register address or plain integer
  READ_U8: 'readU8',
  READ_U16: 'readU16',
  READ_U24: 'readU24',
  READ_TV: 'readTypedValue',
  NEXT: 'next',               // install the next handler, hand back to the loop
  POP_ACC: 'popToAcc',
  PUSH_REG: 'pushReg',
  STORE_REG: 'storeReg',
  PROP_GET: 'propGet',
  PROP_SET: 'propSet',
  STRING: 'stringCipher',
  NOP: 'noop',
  UNKNOWN: 'unknown',
};

// How many bytecode bytes a primitive eats when a handler calls it. This is
// the number the disassembler actually cares about.
const OPERAND_WIDTH = {
  [ROLE.READ_U8]: 1,
  [ROLE.READ_U16]: 2,
  [ROLE.READ_U24]: 3,
  [ROLE.READ_TV]: null,       // variable, driven by the tag byte
};

// `V` stands in for "any identifier" to keep these patterns readable.
const V = '[A-Za-z_$][\\w$]*';
const re = (pattern) => new RegExp(pattern);

function classifyBody(body) {
  const flat = body.replace(/\s+/g, ' ').trim();

  if (flat === '') return ROLE.NOP;

  // The string cipher also shifts bytes around (it reads a 4-byte header key),
  // so it has to be recognised before the integer readers or it looks like a
  // u24 read.
  if (/String\.fromCharCode/.test(flat) || (/\^/.test(flat) && /for\s*\(/.test(flat))) {
    return ROLE.STRING;
  }

  // NEXT: read one byte, use it as an index into the function-slot table,
  // store the resulting closure. It is the only primitive that advances the PC
  // with a plain `PC = x + 1;` statement instead of a post-increment.
  if (re(`=\\s*${V}\\s*\\+\\s*1\\s*;`).test(flat) && !/<</.test(flat)) return ROLE.NEXT;

  // Integer readers, widest first.
  if (/<<\s*16/.test(flat)) return ROLE.READ_U24;
  if (/<<\s*8/.test(flat)) return ROLE.READ_U16;

  // Typed value: hands a byte-reader closure to the tag decoder.
  if (re(`return\\s+${V}\\s*\\(\\s*(?:function|\\()`).test(flat) && /\+\+\s*\]/.test(flat)) {
    return ROLE.READ_TV;
  }

  // Plain u8: a single indexed load with a post-incremented PC.
  if (/\+\+\s*\]/.test(flat) && !/=/.test(flat.replace(/=>/g, ''))) return ROLE.READ_U8;

  // Stack and register plumbing.
  if (re(`\\[\\s*--\\s*${V}\\s*\\[[^\\]]+\\]\\s*\\]\\s*\\[`).test(flat)) return ROLE.PROP_SET;
  if (re(`\\[\\s*${V}\\s*\\[[^\\]]+\\]\\s*\\+\\+\\s*\\]\\s*=`).test(flat)) return ROLE.PUSH_REG;
  // `MEM[regBase + param] = ...` is only ever a register store. Note the RHS
  // has nested brackets (`A[A[SP] - 1]`), so do not try to match it with a
  // negated character class.
  if (re(`^${V}\\s*\\[\\s*${V}\\s*\\+\\s*${V}\\s*\\]\\s*=`).test(flat)) return ROLE.STORE_REG;
  if (re(`^${V}\\s*\\[\\s*${V}\\s*\\]\\s*=\\s*${V}\\s*\\[\\s*--`).test(flat)) return ROLE.POP_ACC;
  if (/--/.test(flat) && re(`=\\s*${V}\\s*\\[\\s*${V}\\s*\\]\\s*;?$`).test(flat)) return ROLE.PROP_GET;

  if (/\+\+\s*\]/.test(flat)) return ROLE.READ_U8;

  return ROLE.UNKNOWN;
}

// Slice exactly one expression out of `text` starting at 0: a function literal
// through its matching brace, otherwise everything up to the first top-level
// comma or semicolon. Without this the final table entry swallows the whole
// MAKE_FUNC installer that follows it.
function takeExpression(text) {
  const trimmed = text.replace(/^\s+/, '');
  if (/^function\b/.test(trimmed) || /^\(/.test(trimmed)) {
    const open = trimmed.indexOf('{');
    if (open >= 0) {
      let depth = 0;
      for (let i = open; i < trimmed.length; i++) {
        if (trimmed[i] === '{') depth++;
        else if (trimmed[i] === '}') {
          depth--;
          if (depth === 0) return trimmed.slice(0, i + 1);
        }
      }
    }
  }
  let depth = 0;
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if ((ch === ',' || ch === ';') && depth === 0) return trimmed.slice(0, i);
  }
  return trimmed;
}

// -- initializer ---------------------------------------------------------

// The initializer is the function that installs MAKE_FUNC, so it is the only
// one containing `new Function`.
function findInitializer(source) {
  const marker = source.indexOf('new Function');
  if (marker < 0) {
    throw new Error(
      'primitives: no `new Function` in this bundle. ' +
      'Older DataDome VMs used a static opcode switch and are not supported.'
    );
  }

  // The initializer is the *enclosing* declaration, not simply the closest one
  // above the marker: it declares inner helpers (the u24 reader, NEXT, ...) that
  // sit between its own header and the `new Function` call. So take every named
  // declaration whose body actually spans the marker and keep the tightest one.
  const declRe = /function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/g;
  let best = null;
  let hit;
  while ((hit = declRe.exec(source)) !== null) {
    if (hit.index > marker) break;
    const bodyStart = source.indexOf('{', hit.index + hit[0].length - 1);
    const body = braceBody(source, bodyStart);
    if (body === null) continue;
    const bodyEnd = bodyStart + body.length;
    if (bodyStart > marker || bodyEnd < marker) continue;
    if (!best || body.length < best.body.length) {
      best = {
        name: hit[1],
        params: hit[2].split(',').map((s) => s.trim()).filter(Boolean),
        body,
        index: hit.index,
      };
    }
  }
  if (!best) throw new Error('primitives: could not find the initializer function');
  return best;
}

// Collect `function NAME() { ... }` declared anywhere, so a table entry that is
// just a name (`w[35] = C`) can be resolved to a real body.
function collectFunctions(source) {
  const out = {};
  const re = /function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g;
  let hit;
  while ((hit = re.exec(source)) !== null) {
    const body = braceBody(source, source.indexOf('{', hit.index + hit[0].length - 1));
    if (body !== null) out[hit[1]] = body;
  }
  return out;
}

// -- table ---------------------------------------------------------------

function derivePrimitives(source, constMap) {
  const init = findInitializer(source);
  const functions = collectFunctions(source);

  // `E.bind(null, d)` / `Y.bind(null, w)` names the primitive table.
  const bindHit = init.body.match(/\.bind\s*\(\s*null\s*,\s*([A-Za-z_$][\w$]*)\s*\)/);
  if (!bindHit) throw new Error('primitives: no `.bind(null, table)` in the initializer');
  const tableName = bindHit[1];

  // Every `table[idx] = value` in the initializer, value text running up to the
  // next assignment to the same table.
  const escaped = tableName.replace(/\$/g, '\\$');
  const assignRe = new RegExp('(?<![\\w$])' + escaped + '\\s*\\[\\s*([A-Za-z0-9_$]+)\\s*\\]\\s*=\\s*', 'g');
  const marks = [];
  let hit;
  while ((hit = assignRe.exec(init.body)) !== null) {
    marks.push({ token: hit[1], valueAt: assignRe.lastIndex });
  }

  const slots = {};
  for (const mark of marks) {
    const raw = takeExpression(init.body.slice(mark.valueAt));
    const slotId = /^\d+$/.test(mark.token) ? Number(mark.token) : constMap[mark.token];
    if (slotId === undefined) continue;
    slots[slotId] = { slotId, raw, role: ROLE.UNKNOWN, value: null };
  }

  // Classify each entry.
  for (const slot of Object.values(slots)) {
    const raw = slot.raw;

    if (/^\d+$/.test(raw)) {
      slot.role = ROLE.CONST;
      slot.value = Number(raw);
      continue;
    }
    if (/^[A-Za-z_$][\w$]*$/.test(raw)) {
      if (raw === init.params[0]) { slot.role = ROLE.MEM; continue; }
      if (raw === init.params[1]) { slot.role = ROLE.OUT; continue; }
      if (functions[raw] !== undefined) {
        // Keep the resolved body around: several entries are plain references
        // to a named inner function, and later passes need the real code.
        slot.body = functions[raw];
        slot.role = classifyBody(functions[raw]);
        continue;
      }
      if (constMap[raw] !== undefined) {
        slot.role = ROLE.CONST;
        slot.value = constMap[raw];
        continue;
      }
      slot.role = ROLE.UNKNOWN;
      continue;
    }
    const open = raw.indexOf('{');
    slot.body = open < 0 ? null : braceBody(raw, open);
    slot.role = slot.body === null ? ROLE.UNKNOWN : classifyBody(slot.body);
  }

  // MAKE_FUNC is installed as `MEM[funcBase + SLOT] = function () { ... }`.
  // The captcha writes that as two names we can resolve; the interstitial folds
  // it into one literal flat address (`A[4379] = ...`), which on its own tells
  // us nothing without the function-slot base. We report what the source gives
  // us and let the caller fall back to the first bytecode byte, which is always
  // the MAKE_FUNC opcode because the program opens with the install chain.
  let makeFuncSlot = null;
  const installHit = init.body.match(
    /\[\s*([A-Za-z0-9_$]+)\s*\+\s*([A-Za-z0-9_$]+)\s*\]\s*=\s*function\s*\([^)]*\)\s*\{[\s\S]{0,600}?new Function/
  );
  if (installHit) {
    for (const token of [installHit[1], installHit[2]]) {
      const value = /^\d+$/.test(token) ? Number(token) : constMap[token];
      if (value !== undefined && value >= 0 && value < 256) makeFuncSlot = value;
    }
  }

  const byRole = {};
  for (const slot of Object.values(slots)) {
    if (!byRole[slot.role]) byRole[slot.role] = [];
    byRole[slot.role].push(slot.slotId);
  }

  return {
    tableName,
    initializer: init.name,
    slots,
    byRole,
    makeFuncSlot,
    // Convenience lookups the disassembler leans on.
    slotOf(role) {
      const list = byRole[role];
      return list && list.length ? list[0] : null;
    },
    widthOfSlot(slotId) {
      const slot = slots[slotId];
      if (!slot) return undefined;
      return OPERAND_WIDTH[slot.role];
    },
    isReader(slotId) {
      const slot = slots[slotId];
      return !!slot && Object.prototype.hasOwnProperty.call(OPERAND_WIDTH, slot.role);
    },
  };
}

module.exports = { ROLE, OPERAND_WIDTH, derivePrimitives, findInitializer, classifyBody };
