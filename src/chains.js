'use strict';

// chains.js, reconstruct the JavaScript the VM evaluates.
//
// A disassembly of 43k instructions tells you the program ran. It does not tell
// you what it asked the browser. That answer is sitting in the listing though,
// because property access in this VM is always the same two-instruction shape:
//
//   PUSH_STR "document"     ; push a decoded string
//   GET_PROP                ; pop key, pop object, push object[key]
//   PUSH_STR "timeline"
//   GET_PROP
//   PUSH_STR "currentTime"
//   GET_PROP
//
// A run of those pairs is a property chain, and joining the strings back
// together turns the listing into `document.timeline.currentTime`. Follow it
// with a CALL and you know it was invoked rather than merely read.
//
// This is what makes the collection surface provable instead of inferred: every
// chain below is a byte offset in the bytecode, not a guess from a string dump.

// Two-instruction step that walks one level deeper into an object.
const ACCESS = new Set(['GET_PROP', 'GET_PROP_IMM']);
const CALLS = new Set(['CALL', 'CALL_APPLY']);

// Anything that clearly ends an expression. Arithmetic and stack shuffling do
// not, because the VM interleaves them with access chains constantly.
const BREAKS = new Set(['JMP', 'JMP_IF_FALSE', 'JMP_IF_TRUE', 'HALT', 'MAKE_CLOSURE']);

function reconstruct(instructions, table, stringsByPc) {
  const chains = [];
  let current = null;

  const flush = () => {
    if (current && current.parts.length >= 2) chains.push(current);
    current = null;
  };

  for (let i = 0; i < instructions.length; i++) {
    const insn = instructions[i];
    const entry = table.get(insn.opcode);
    const mnemonic = entry ? entry.mnemonic : '';

    if (mnemonic === 'PUSH_STR') {
      const text = stringsByPc.get(insn.pc);
      const next = instructions[i + 1];
      const nextEntry = next ? table.get(next.opcode) : null;
      const isAccess = nextEntry && ACCESS.has(nextEntry.mnemonic);

      if (text === undefined) { flush(); continue; }

      if (isAccess) {
        // A SCREAMING_CASE key is a constant being read off an object
        // (`gl.ARRAY_BUFFER`), never a container you then walk into. Close the
        // chain on it so sibling reads do not glue together.
        const isEnum = /^[A-Z][A-Z0-9_]{2,}$/.test(text);
        if (current && isEnum) flush();
        if (!current) current = { pc: insn.pc, parts: [], called: false };
        current.parts.push(text);
        i++;                       // consume the GET_PROP
        if (isEnum) flush();
        continue;
      }
      // A string that is not used as a key ends whatever we were building.
      flush();
      continue;
    }

    if (current && CALLS.has(mnemonic)) {
      current.called = true;
      flush();
      continue;
    }

    if (BREAKS.has(mnemonic)) { flush(); continue; }

    // Any other push buries the object we were walking, so the next
    // `PUSH_STR key; GET_PROP` starts a fresh chain rather than going deeper.
    // Without this, the `fn.apply(thisArg, ...)` idiom (which pushes the
    // receiver, then re-resolves it to reach the method) reconstructs as
    // `Math.Math.random` instead of two reads of `Math` and `Math.random`.
    if (mnemonic.startsWith('PUSH')) { flush(); continue; }
    // Arithmetic, comparisons and stores are allowed to interleave.
  }
  flush();

  return chains;
}

// Group identical chains and count how often the program walks them.
function summarise(chains) {
  const byPath = new Map();
  for (const chain of chains) {
    const path = chain.parts.join('.');
    const existing = byPath.get(path);
    if (existing) {
      existing.hits++;
      if (chain.called) existing.calls++;
      existing.pcs.push(chain.pc);
    } else {
      byPath.set(path, {
        path,
        depth: chain.parts.length,
        hits: 1,
        calls: chain.called ? 1 : 0,
        pcs: [chain.pc],
      });
    }
  }
  return [...byPath.values()].sort((a, b) => b.hits - a.hits);
}

// Bucket the recovered surface by what it is probing. Purely descriptive, but it
// turns 200 strings into something you can reason about.
const AREAS = [
  ['webgl', /^(webgl|createShader|shaderSource|compileShader|attachShader|linkProgram|useProgram|createProgram|getUniformLocation|uniform1f|ARRAY_BUFFER|STATIC_DRAW|bufferData|bindBuffer|getAttribLocation|enableVertexAttribArray|vertexAttribPointer|drawArrays|readPixels|TRIANGLES|FLOAT|RGBA|UNSIGNED_BYTE|VERTEX_SHADER|attribute vec2)/],
  ['canvas', /^(canvas|getContext|2d|fillRect|fillStyle|strokeStyle|save|restore|translate|rect|getImageData|globalCompositeOperation|difference|willReadFrequently|data)$/],
  ['svg', /^(svg|createElementNS|http:\/\/www\.w3\.org\/2000\/svg)$/],
  ['layout', /(^calc\(|^max\(|^--|^var\(--|px|cssText|offsetWidth|paddingLeft|boxSizing|position|left|visibility|<style>|<\/style>|<div|display:|max-width|inline-block|9999px)/],
  ['timing', /^(performance|timing|loadEventEnd|timeline|currentTime|Date|now|memory|usedJSHeapSize|totalJSHeapSize|jsHeapSizeLimit)$/],
  ['entropy', /^(crypto|getRandomValues|random|Math)$/],
  ['navigator', /^(navigator|_userAgent|maxTouchPoints|hardwareConcurrency|webdriver|devicePixelRatio|isSecureContext|_virtualConsole)$/],
  ['dom', /^(document|window|body|createElement|appendChild|removeChild|lastChild|querySelector|innerHTML|setAttribute|remove|id|style|location|pathname|hidden)$/],
  ['encoding', /^(btoa|atob|charCodeAt|fromCharCode|Uint8Array|Float32Array|Buffer|String|Array|RegExp|replace|indexOf|join|push|toString|length|round)$/],
];

function classify(text) {
  for (const [area, pattern] of AREAS) if (pattern.test(text)) return area;
  return 'other';
}

module.exports = { reconstruct, summarise, classify, AREAS };
