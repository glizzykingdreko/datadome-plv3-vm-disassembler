#!/usr/bin/env node
'use strict';

// ddvm, CLI for the DataDome plv3 VM disassembler.
//
//   ddvm <vm-obf.js> [outDir] [flags]
//
// Writes the listing, the recovered opcode table and a machine-readable summary.
// With no outDir it prints the listing to stdout, which is usually what you want
// while poking at a fresh rotation.

const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../src/index');

const USAGE = `
ddvm, DataDome plv3 VM disassembler

  ddvm <vm-obf.js> [outDir] [flags]

Flags
  --source           inline each handler's JavaScript under its instruction
  --strings          resolve the string table and write strings.json
  --chains           reconstruct the API chains the program evaluates
  --limit <n>        stop after n decoded instructions
  --summary-only     print the summary, skip the listing
  --json             print the summary as JSON on stdout
  -h, --help         this

Outputs (when outDir is given)
  disasm.txt         the listing
  opcodes.json       recovered opcode table: slot id, mnemonic, operands, source
  handlers/          one .js file per handler body
  summary.json       buffer geometry, primitives, tag map, mnemonic histogram
  strings.json       only with --strings
  chains.json        only with --chains: property chains + collection surface
`.trim();

function parseArgs(argv) {
  const args = { positional: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '-h' || token === '--help') args.flags.help = true;
    else if (token === '--source') args.flags.source = true;
    else if (token === '--strings') args.flags.strings = true;
    else if (token === '--chains') args.flags.chains = true;
    else if (token === '--summary-only') args.flags.summaryOnly = true;
    else if (token === '--json') args.flags.json = true;
    else if (token === '--limit') args.flags.limit = Number(argv[++i]);
    else args.positional.push(token);
  }
  return args;
}

function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));

  if (flags.help || !positional.length) {
    console.log(USAGE);
    process.exit(positional.length ? 0 : 1);
  }

  const [input, outDir] = positional;
  if (!fs.existsSync(input)) {
    console.error(`ddvm: no such file: ${input}`);
    process.exit(1);
  }

  let vm;
  try {
    vm = analyzeFile(input);
  } catch (err) {
    console.error(`ddvm: ${err.message}`);
    process.exit(2);
  }

  const summary = vm.summary();
  for (const warning of vm.warnings) console.error(`ddvm: warning: ${warning}`);

  const result = vm.disassemble({ limit: flags.limit });
  summary.instructions = result.instructions.length;
  summary.coverage = result.coverage;
  summary.decodeProblems = result.problems.length;

  if (flags.json) {
    console.log(JSON.stringify(summary, null, 2));
    if (!outDir) return;
  }

  if (!flags.json && !outDir) {
    if (flags.summaryOnly) {
      printSummary(summary);
      printExitContract(vm.exitContract());
      return;
    }
    console.log(vm.listing({ source: flags.source, limit: flags.limit }));
    return;
  }

  if (!flags.json) {
    printSummary(summary);
    printExitContract(vm.exitContract());
  }
  if (!outDir) return;

  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(path.join(outDir, 'handlers'), { recursive: true });

  fs.writeFileSync(
    path.join(outDir, 'disasm.txt'),
    vm.listing({ source: flags.source, limit: flags.limit })
  );

  const opcodes = [...vm.table.values()]
    .sort((a, b) => a.index - b.index)
    .map((entry) => ({
      slotId: entry.slotId,
      installOrder: entry.index,
      mnemonic: entry.mnemonic,
      operands: entry.operands.map((o) => ({ role: o.role, width: o.width, repeats: o.repeats })),
      sourceBytes: entry.length,
      source: entry.source,
    }));
  fs.writeFileSync(path.join(outDir, 'opcodes.json'), JSON.stringify(opcodes, null, 2));

  for (const entry of vm.table.values()) {
    fs.writeFileSync(
      path.join(outDir, 'handlers', `${String(entry.index).padStart(3, '0')}_slot${entry.slotId}_${entry.mnemonic}.js`),
      entry.source
    );
  }

  summary.exitContract = vm.exitContract();
  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));

  if (flags.strings) {
    const sites = vm.strings();
    const unique = vm.stringTable();
    fs.writeFileSync(
      path.join(outDir, 'strings.json'),
      JSON.stringify({ unique, sites }, null, 2)
    );
    const approximate = sites.some((s) => s.approximate);
    console.log(
      `strings: ${unique.length} unique from ${sites.length} call site(s)` +
      (approximate ? ' (approximate, ctx swept)' : '')
    );
  }

  if (flags.chains) {
    const apiChains = vm.apiChains();
    const surface = vm.surface();
    fs.writeFileSync(
      path.join(outDir, 'chains.json'),
      JSON.stringify({ chains: apiChains, surface }, null, 2)
    );
    console.log(`chains: ${apiChains.length} distinct property chains`);
    for (const chain of apiChains.slice(0, 12)) {
      console.log(`   ${String(chain.hits).padStart(3)}x ${chain.calls ? '()' : '  '} ${chain.path}`);
    }
  }

  console.log(`written to ${outDir}/`);
}

function printExitContract(contract) {
  const halt = contract.haltHandlers.map((h) => h.slotId).join(', ') || 'none found';
  console.log(
    `exit        HALT at slot ${halt}, plv3 token -> out.${contract.guestWrittenFields.join('/') || '?'}, ` +
    `loader adds {${contract.loaderWrittenFields.join(', ')}}`
  );
}

function printSummary(summary) {
  const { buffer, readers } = summary;
  console.log(`buffer      ${buffer.size} bytes, code at ${buffer.codeBase}..${buffer.codeBase + buffer.codeLen}`);
  console.log(`lcg seed    ${summary.lcgSeed}`);
  console.log(`make_func   opcode ${summary.makeFuncOpcode}, ${summary.handlers} handlers, program starts at ${summary.entryPc}`);
  console.log(`primitives  ${summary.primitives.count} slots`);
  console.log(`readers     u8=${readers.u8} u16=${readers.u16} u24=${readers.u24} typed=${readers.typedValue} next=${readers.next}`);
  console.log(`value tags  ${Object.keys(summary.tags.widths).length} (small-int mask ${summary.tags.mask})`);
  if (summary.instructions !== undefined) {
    console.log(
      `disassembly ${summary.instructions} instructions, ` +
      `${(summary.coverage.ratio * 100).toFixed(1)}% of the program, ` +
      `${summary.decodeProblems} problem(s)`
    );
  }
}

main();
