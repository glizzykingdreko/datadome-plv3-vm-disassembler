'use strict';

// index.js, the public API.
//
//   const { analyzeBundle } = require('datadome-plv3-vm-disassembler');
//   const vm = analyzeBundle(fs.readFileSync('vm-obf.js', 'utf8'));
//   console.log(vm.listing());
//
// Everything is derived from the bundle that was passed in. Nothing is cached
// between calls and no constant is hardcoded, so the same code handles the next
// rotation without edits.

const fs = require('fs');
const loader = require('./loader');
const { deriveTagMap } = require('./tags');
const { derivePrimitives, ROLE } = require('./primitives');
const { walkChain } = require('./handlers');
const { buildOpcodeTable } = require('./classify');
const { disassemble, render } = require('./disasm');
const strings = require('./strings');
const chains = require('./chains');

function analyzeBundle(source) {
  const { header, buffer, decodedLen } = loader.load(source);
  const tags = deriveTagMap(source, header.constMap);
  const primitives = derivePrimitives(source, header.constMap);

  // The program always opens with the MAKE_FUNC install chain, so the first
  // bytecode byte is the MAKE_FUNC opcode. That is more reliable than reading
  // it out of the initializer, where the interstitial folds the slot id into a
  // single literal flat address. When the source did give us a slot id, the two
  // should agree, and a mismatch is worth surfacing.
  const makeFuncOpcode = buffer[header.codeBase];
  const declaredSlot = primitives.makeFuncSlot;
  const warnings = [];
  if (declaredSlot !== null && declaredSlot !== makeFuncOpcode) {
    warnings.push(
      `MAKE_FUNC slot mismatch: initializer says ${declaredSlot}, bytecode opens with ${makeFuncOpcode}`
    );
  }

  const { handlers, entryPc } = walkChain(buffer, header.codeBase, makeFuncOpcode);
  if (!handlers.length) {
    throw new Error('no MAKE_FUNC chain found, the bundle layout is not recognised');
  }

  const table = buildOpcodeTable(handlers, primitives);

  const ctx = {
    buffer,
    codeBase: header.codeBase,
    codeLen: header.codeLen,
    entryPc,
    table,
    tags,
    primitives,
  };

  return {
    header,
    buffer,
    decodedLen,
    tags,
    primitives,
    handlers,
    entryPc,
    table,
    warnings,

    disassemble(options) {
      return disassemble(ctx, options);
    },

    // Annotated by default: every PUSH_STR gets its decoded string in a trailing
    // comment, which is the difference between a wall of opcodes and something
    // you can actually read. Pass `{ strings: false }` to skip the resolve pass.
    listing(options = {}) {
      const result = this.disassemble(options);
      let annotations = new Map();

      if (options.strings !== false) {
        const blobs = strings.findStringBlobs(result.instructions, header.codeBase);
        const cipherSlot = primitives.slotOf(ROLE.STRING);
        if (blobs.length && cipherSlot !== null) {
          for (const site of strings.resolveStrings(result.instructions, table, buffer, blobs, cipherSlot)) {
            annotations.set(site.pc, site.text);
          }
        }
      }

      return render(result, table, { ...options, strings: annotations });
    },

    // Strings do not live at a fixed offset and they are not decodable from the
    // table alone: the cipher takes a per-call-site ctx byte. Both problems are
    // solved by disassembling first. The blobs come from the prologue's
    // PUSH_BYTES payloads and the ctx comes straight off every PUSH_STR
    // instruction, so the result is exact rather than a guess.
    strings(options = {}) {
      const result = this.disassemble(options);
      const blobs = strings.findStringBlobs(result.instructions, header.codeBase);
      if (!blobs.length) return [];

      const cipherSlot = primitives.slotOf(ROLE.STRING);
      const exact = cipherSlot === null
        ? []
        : strings.resolveStrings(result.instructions, table, buffer, blobs, cipherSlot);

      if (exact.length || options.exactOnly) return exact;

      // No PUSH_STR sites resolved (a rotation moved the cipher call shape).
      // Fall back to the ctx sweep so there is still something to look at.
      const out = [];
      for (const blob of blobs) {
        for (const hit of strings.sweep(buffer, blob.base, blob.length, options)) {
          out.push({ ...hit, blobPc: blob.pc, approximate: true });
        }
      }
      return out;
    },

    // Deduplicated view of the above, which is what you usually want to read.
    stringTable(options) {
      const byText = new Map();
      for (const site of this.strings(options)) {
        const existing = byText.get(site.text);
        if (existing) existing.hits++;
        else byText.set(site.text, { text: site.text, id: site.id, ctx: site.ctx, hits: 1 });
      }
      return [...byText.values()].sort((a, b) => b.hits - a.hits);
    },

    // What the program actually asks the browser.
    //
    // Property access is always `PUSH_STR key; GET_PROP`, so a run of those
    // pairs reconstructs back into `document.timeline.currentTime`. Returns the
    // deduplicated chains with hit counts, call counts and the byte offsets they
    // were found at, which is what makes the collection surface provable rather
    // than inferred from a string dump.
    apiChains(options = {}) {
      const result = this.disassemble(options);
      const blobs = strings.findStringBlobs(result.instructions, header.codeBase);
      const cipherSlot = primitives.slotOf(ROLE.STRING);
      const byPc = new Map();
      if (blobs.length && cipherSlot !== null) {
        for (const site of strings.resolveStrings(result.instructions, table, buffer, blobs, cipherSlot)) {
          byPc.set(site.pc, site.text);
        }
      }
      return chains.summarise(chains.reconstruct(result.instructions, table, byPc));
    },

    // The recovered strings bucketed by what they probe, with call-site counts.
    surface(options) {
      const buckets = {};
      for (const entry of this.stringTable(options)) {
        const area = chains.classify(entry.text);
        if (!buckets[area]) buckets[area] = { area, strings: 0, sites: 0, items: [] };
        buckets[area].strings++;
        buckets[area].sites += entry.hits;
        buckets[area].items.push({ text: entry.text, hits: entry.hits });
      }
      for (const bucket of Object.values(buckets)) {
        bucket.items.sort((a, b) => b.hits - a.hits);
      }
      return Object.values(buckets).sort((a, b) => b.sites - a.sites);
    },

    // How the token leaves the machine.
    //
    // The loader builds an output object, hands it to the initializer, and the
    // initializer parks it in the primitive table. So the guest program can
    // write properties on it directly, and exactly one handler does:
    //
    //     n[41].r = n[32][n[10]], n[32][n[22]] = 1;
    //     // out.r = MEM[ACC];    halt = 1
    //
    // That is the plv3 token, taken from the accumulator. Everything else on
    // the output object (`i`, `t`, `u`, `e`) is written by the loader in JS
    // after the dispatch loop ends. Worth surfacing because the wire payload
    // and several signals are fed straight from these fields.
    exitContract() {
      const outSlot = primitives.slotOf(ROLE.OUT);
      const halt = [...table.values()].filter((entry) => entry.mnemonic === 'HALT');

      const properties = [];
      if (outSlot !== null) {
        for (const entry of halt) {
          const re = new RegExp(
            `${entry.info.bind.replace(/\$/g, '\\$')}\\s*\\[\\s*${outSlot}\\s*\\]\\s*\\.\\s*([A-Za-z_$][\\w$]*)`, 'g'
          );
          let hit;
          while ((hit = re.exec(entry.source)) !== null) properties.push(hit[1]);
        }
      }

      // Fields the loader itself attaches, `E.i = P, E.t = ... , E.u = Q[-1]`.
      const loaderFields = [];
      const tail = source.slice(source.lastIndexOf('finally'));
      for (const hit of tail.matchAll(/\.\s*([A-Za-z_$][\w$]*)\s*=/g)) loaderFields.push(hit[1]);

      return {
        outPrimitiveSlot: outSlot,
        haltHandlers: halt.map((entry) => ({
          slotId: entry.slotId,
          source: entry.source,
          writes: properties,
        })),
        guestWrittenFields: [...new Set(properties)],
        loaderWrittenFields: [...new Set(loaderFields)],
      };
    },

    // Compact machine-readable shape, useful for diffing two rotations.
    summary() {
      const roles = {};
      for (const slot of Object.values(primitives.slots)) {
        roles[slot.role] = (roles[slot.role] || 0) + 1;
      }
      const mnemonics = {};
      for (const entry of table.values()) {
        mnemonics[entry.mnemonic] = (mnemonics[entry.mnemonic] || 0) + 1;
      }
      return {
        buffer: { size: header.bufSize, codeBase: header.codeBase, codeLen: header.codeLen },
        lcgSeed: header.seed,
        payloadBytes: decodedLen,
        makeFuncOpcode,
        entryPc,
        handlers: handlers.length,
        primitives: { count: Object.keys(primitives.slots).length, roles },
        tags: { mask: tags.smallIntMask, widths: tags.widths },
        readers: {
          u8: primitives.slotOf(ROLE.READ_U8),
          u16: primitives.slotOf(ROLE.READ_U16),
          u24: primitives.slotOf(ROLE.READ_U24),
          typedValue: primitives.slotOf(ROLE.READ_TV),
          next: primitives.slotOf(ROLE.NEXT),
        },
        mnemonics,
        warnings,
      };
    },
  };
}

function analyzeFile(path) {
  return analyzeBundle(fs.readFileSync(path, 'utf8'));
}

module.exports = { analyzeBundle, analyzeFile, ROLE, loader, strings };
